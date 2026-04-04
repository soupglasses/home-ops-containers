# syntax=docker/dockerfile:1

FROM docker.io/library/alpine:3.23
ARG VERSION

ENV LDAP_SUFFIX="dc=example,dc=com" \
    LDAP_ROOT_DN="" \
    LDAP_ORGANISATION="Example" \
    LDAP_LOG_LEVEL="256"

USER root

RUN \
    apk add --no-cache \
        bash \
        catatonit \
        envsubst \
        openldap=="${VERSION}" \
        openldap-back-mdb \
        openldap-clients \
        openldap-overlay-ppolicy \
        openldap-passwd-argon2 \
    && \
    mkdir -p /config/data /config/tls /run/openldap \
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
