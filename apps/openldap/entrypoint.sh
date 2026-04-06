#!/usr/bin/env bash
set -euo pipefail

export LDAP_SUFFIX="${LDAP_SUFFIX:-dc=example,dc=com}"
export LDAP_ROOT_DN="${LDAP_ROOT_DN:-cn=admin,${LDAP_SUFFIX}}"
export LDAP_SCHEMAS="${LDAP_SCHEMAS:-core,cosine,inetorgperson,nis}"
export LDAP_OVERLAYS="${LDAP_OVERLAYS:-}"
export LDAP_LOG_LEVEL="${LDAP_LOG_LEVEL:-256}"

LDAPI_URL="ldapi://%2Frun%2Fopenldap%2Fldapi"
TLS_FILES=(/config/tls/tls.crt /config/tls/tls.key /config/tls/ca.crt)

require_env() {
    if [[ -z "${LDAP_ROOT_PASSWORD:-}" ]]; then
        printf "\e[31mError: LDAP_ROOT_PASSWORD is required\e[0m\n"
        exit 1
    fi
}

validate_tls_config() {
    local present=0
    local missing=0
    local file

    for file in "${TLS_FILES[@]}"; do
        if [[ -f "${file}" ]]; then
            present=$((present + 1))
        else
            missing=$((missing + 1))
        fi
    done

    if [[ ${present} -gt 0 && ${missing} -gt 0 ]]; then
        printf "\e[31mError: TLS requires tls.crt, tls.key, and ca.crt to all be present in /config/tls\e[0m\n"
        exit 1
    fi
}

has_tls() {
    local file

    for file in "${TLS_FILES[@]}"; do
        [[ -f "${file}" ]] || return 1
    done

    return 0
}

tls_required() {
    if [[ -n "${LDAP_TLS_REQUIRED:-}" ]]; then
        case "${LDAP_TLS_REQUIRED}" in
        true|TRUE|1|yes|YES|on|ON)
            return 0
            ;;
        false|FALSE|0|no|NO|off|OFF)
            return 1
            ;;
        *)
            printf "\e[31mError: LDAP_TLS_REQUIRED must be a boolean value\e[0m\n"
            exit 1
            ;;
        esac
    fi

    has_tls
}

require_tls_if_configured() {
    if tls_required && ! has_tls; then
        printf "\e[31mError: LDAP_TLS_REQUIRED is enabled but TLS files are missing from /config/tls\e[0m\n"
        exit 1
    fi
}

set_root_password() {
    if [[ "${LDAP_ROOT_PASSWORD}" == \{* ]]; then
        printf "\e[31mError: Pre-hashed passwords are not supported\e[0m\n"
        exit 1
    fi

    export LDAP_ROOT_PASSWORD_PLAIN="${LDAP_ROOT_PASSWORD}"
    export LDAP_ROOT_PASSWORD
    LDAP_ROOT_PASSWORD=$(slappasswd -o module-path=/usr/lib/openldap -o module-load=argon2 -h {ARGON2} -s "${LDAP_ROOT_PASSWORD}")
}

set_urls() {
    if [[ -n "${LDAP_URLS:-}" ]]; then
        return
    fi

    LDAP_URLS="ldap://0.0.0.0:389/"
    if has_tls; then
        LDAP_URLS="${LDAP_URLS} ldaps://0.0.0.0:636/"
    fi
    export LDAP_URLS
}

build_schema_config() {
    export LDAP_SCHEMA_INCLUDES=""

    local schema_includes=""

    IFS=',' read -ra schemas <<<"${LDAP_SCHEMAS}"
    for schema in "${schemas[@]}"; do
        schema=$(echo "${schema}" | xargs)
        if [[ -n "${schema}" ]]; then
            schema_includes+="include     /etc/openldap/schema/${schema}.schema"$'\n'
        fi
    done

    export LDAP_SCHEMA_INCLUDES="${schema_includes}"
}

build_overlay_config() {
    export LDAP_MODULE_LOADS=""
    export LDAP_OVERLAY_CONFIG=""

    if [[ -z "${LDAP_OVERLAYS}" ]]; then
        return
    fi

    local module_loads=""
    local overlay_config=""

    IFS=',' read -ra overlays <<<"${LDAP_OVERLAYS}"
    for overlay in "${overlays[@]}"; do
        overlay=$(echo "${overlay}" | xargs)
        if [[ -n "${overlay}" ]]; then
            module_loads+="moduleload  ${overlay}"$'\n'
            overlay_config+="overlay     ${overlay}"$'\n'
        fi
    done

    export LDAP_MODULE_LOADS="${module_loads}"
    export LDAP_OVERLAY_CONFIG="${overlay_config}"
}

build_security_config() {
    export LDAP_SECURITY_CONFIG=""

    if tls_required; then
        export LDAP_SECURITY_CONFIG="security ssf=1"
    fi
}

render_config() {
    envsubst </defaults/slapd.conf >/config/slapd.conf
    sed -i '/^$/d' /config/slapd.conf

    if ! has_tls; then
        sed -i '/^TLS/d' /config/slapd.conf
    fi

    if compgen -G "/config/slapd.conf.d/*.conf" >/dev/null; then
        for conf in /config/slapd.conf.d/*.conf; do
            echo "include     ${conf}" >>/config/slapd.conf
        done
    fi
}

wait_for_ldap() {
    local attempt=0
    while ! ldapsearch -x -H "${LDAPI_URL}" -b "" -s base "(objectclass=*)" >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [[ ${attempt} -ge 30 ]]; then
            printf "\e[31mError: slapd failed to start\e[0m\n"
            exit 1
        fi
        sleep 0.1
    done
}

init_base_entry() {
    local dc
    dc="${LDAP_SUFFIX#dc=}"
    dc="${dc%%,*}"

    local org_name="${LDAP_ORGANIZATION_NAME:-${dc}}"

    cat >/tmp/base.ldif <<EOF
dn: ${LDAP_SUFFIX}
objectClass: top
objectClass: dcObject
objectClass: organization
dc: ${dc}
o: ${org_name}
EOF

    ldapadd -x -H "${LDAPI_URL}" -D "${LDAP_ROOT_DN}" -w "${LDAP_ROOT_PASSWORD_PLAIN}" -f /tmp/base.ldif 2>/dev/null || {
        local rc=$?
        if [[ ${rc} -ne 68 ]]; then # 68 = already exists
            rm -f /tmp/base.ldif
            return ${rc}
        fi
    }
    rm -f /tmp/base.ldif
}

apply_ldifs() {
    if ! compgen -G "/config/ldif.d/*.ldif" >/dev/null; then
        return
    fi

    for ldif in /config/ldif.d/*.ldif; do
        printf "Applying %s\n" "${ldif}"
        ldapmodify -c -x -H "${LDAPI_URL}" -D "${LDAP_ROOT_DN}" -w "${LDAP_ROOT_PASSWORD_PLAIN}" -f "${ldif}" 2>/dev/null || true
    done
}

stop_bootstrap_slapd() {
    local pid=""
    local attempt=0

    if [[ -f /run/openldap/slapd.pid ]]; then
        pid=$(cat /run/openldap/slapd.pid)
        kill "${pid}" 2>/dev/null || true
    else
        pkill -x slapd 2>/dev/null || true
        return
    fi

    while kill -0 "${pid}" 2>/dev/null; do
        attempt=$((attempt + 1))
        if [[ ${attempt} -ge 50 ]]; then
            pkill -x slapd 2>/dev/null || true
            break
        fi
        sleep 0.1
    done
}

require_env
validate_tls_config
require_tls_if_configured
mkdir -p /config/data /config/slapd.conf.d /config/ldif.d /run/openldap

set_root_password
set_urls
build_schema_config
build_overlay_config
build_security_config
render_config

slapd -h "${LDAPI_URL}" -f /config/slapd.conf
wait_for_ldap
init_base_entry
apply_ldifs

stop_bootstrap_slapd

exec slapd -d "${LDAP_LOG_LEVEL}" -f /config/slapd.conf -h "${LDAP_URLS}" "$@"
