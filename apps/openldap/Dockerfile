# syntax=docker/dockerfile:1

FROM docker.io/library/alpine:3.23
ARG VERSION

ENV LDAP_SUFFIX="dc=example,dc=com" \
    LDAP_ROOT_DN="" \
    LDAP_ORGANIZATION_NAME="" \
    LDAP_SCHEMAS="core,cosine,inetorgperson,nis" \
    LDAP_OVERLAYS="" \
    LDAP_LOG_LEVEL="256"

USER root

RUN \
    apk add --no-cache \
    bash \
    catatonit \
    envsubst \
    openldap=="${VERSION}" \
    openldap-clients=="${VERSION}" \
    openldap-back-mdb=="${VERSION}" \
    openldap-overlay-all=="${VERSION}" \
    openldap-passwd-argon2=="${VERSION}" \
    && \
    mkdir -p /config/data /config/tls /config/slapd.conf.d /config/ldif.d /run/openldap \
    && \
    chown -R nobody:nogroup /config /run/openldap /etc/openldap \
    && \
    rm -rf /tmp/*

COPY . /

USER nobody:nogroup
WORKDIR /config
VOLUME ["/config"]

EXPOSE 389 636

ENTRYPOINT ["/usr/bin/catatonit", "--", "/entrypoint.sh"]
