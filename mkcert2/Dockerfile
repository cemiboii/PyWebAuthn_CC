FROM alpine

WORKDIR /opt/mkcert/data
VOLUME ["/opt/mkcert/data"]
VOLUME ["/.local/share/mkcert"]

RUN apk --no-cache add  \
        wget            \
        ca-certificates \
        libstdc++
# Get and install glibc for alpine
ARG APK_GLIBC_VERSION=2.29-r0
ARG APK_GLIBC_FILE="glibc-${APK_GLIBC_VERSION}.apk"
ARG APK_GLIBC_BIN_FILE="glibc-bin-${APK_GLIBC_VERSION}.apk"
ARG APK_GLIBC_BASE_URL="https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${APK_GLIBC_VERSION}"
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub \
    && wget "${APK_GLIBC_BASE_URL}/${APK_GLIBC_FILE}"       \
    && apk --no-cache add "${APK_GLIBC_FILE}"               \
    && wget "${APK_GLIBC_BASE_URL}/${APK_GLIBC_BIN_FILE}"   \
    && apk --no-cache add "${APK_GLIBC_BIN_FILE}"           \
    && rm glibc-* \
    && export TRUST_STORES=""


CMD ["sh", "-c", "set -ex && mkdir -p /opt/mkcert/data && cd /opt/mkcert/data && wget -q -O mkcert https://github.com/FiloSottile/mkcert/releases/download/v1.4.3/mkcert-v1.4.3-linux-amd64 && chmod +x mkcert && export CAROOT=/cem/.local/share/mkcert && ./mkcert -CAROOT && ./mkcert -install && echo $TRUST_STORES && ./mkcert localhost *.localhost 127.0.0.0 0.0.0.0"]
