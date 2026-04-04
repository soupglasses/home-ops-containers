#!/usr/bin/env bash
set -euo pipefail

export LDAP_SUFFIX="${LDAP_SUFFIX:-dc=example,dc=com}"
export LDAP_ROOT_DN="${LDAP_ROOT_DN:-cn=admin,${LDAP_SUFFIX}}"
export LDAP_ORGANISATION="${LDAP_ORGANISATION:-Example}"
export LDAP_LOG_LEVEL="${LDAP_LOG_LEVEL:-256}"
export LDAP_PPOLICY_DEFAULT_DN="${LDAP_PPOLICY_DEFAULT_DN:-}"

require_env() {
    if [[ -n "${LDAP_ROOT_PASSWORD:-}" ]]; then
        return
    fi

    printf "\e[1;32m%-6s\e[m\n" "Invalid configuration - missing a required environment variable"
    printf "\e[1;32m%-6s\e[m\n" "LDAP_ROOT_PASSWORD: unset"
    exit 1
}

has_tls() {
    [[ -f /config/tls/tls.crt && -f /config/tls/tls.key ]]
}

set_root_password() {
    if [[ "${LDAP_ROOT_PASSWORD}" == \{* ]]; then
        return
    fi

    export LDAP_ROOT_PASSWORD
    LDAP_ROOT_PASSWORD=$(slappasswd -s "${LDAP_ROOT_PASSWORD}")
}

set_urls() {
    if [[ -n "${LDAP_URLS:-}" ]]; then
        export LDAP_URLS
        return
    fi

    LDAP_URLS="ldap://0.0.0.0:389/"
    if has_tls; then
        LDAP_URLS="${LDAP_URLS} ldaps://0.0.0.0:636/"
    fi
    export LDAP_URLS
}

render_config() {
    envsubst </defaults/slapd.conf >/config/slapd.conf

    if ! has_tls; then
        sed -i '/^TLS/d' /config/slapd.conf
    fi

    if [[ -z "${LDAP_PPOLICY_DEFAULT_DN}" ]]; then
        sed -i '/^ppolicy_default /d' /config/slapd.conf
    fi
}

seed_database() {
    local dc

    if [[ -f /config/data/data.mdb ]]; then
        return
    fi

    dc="${LDAP_SUFFIX#dc=}"
    dc="${dc%%,*}"

    cat >/tmp/init.ldif <<EOF
dn: ${LDAP_SUFFIX}
objectClass: top
objectClass: dcObject
objectClass: organization
dc: ${dc}
o: ${LDAP_ORGANISATION}
EOF

    slapadd -f /config/slapd.conf -l /tmp/init.ldif
    rm -f /tmp/init.ldif
}

require_env
mkdir -p /config/data /run/openldap
set_root_password
set_urls
render_config
seed_database

exec slapd -d "${LDAP_LOG_LEVEL}" -f /config/slapd.conf -h "${LDAP_URLS}" "$@"
