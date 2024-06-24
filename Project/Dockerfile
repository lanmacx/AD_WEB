FROM python:3.12-alpine
LABEL maintainer="Allan Santos <allan.santos@amchambrasil.com.br>" \
      version="1.0" \
      date_created="2024-06-01" \
      last_change="2024-06-24"

ARG USER_APP=allan
ARG DEVMODE=''      

ENV PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=America/Sao_Paulo \
    HOST=0.0.0.0 \
    PORT=3000 \
    LOG=info \
    PIP=22.3.1 \
    SETUPTOOLS=67.1.0 \
    WHEEL=0.38.4 \
    BUILD_DEPS="python3-dev \
                libffi-dev \
                pcre2-dev \
                build-base \
                gcc \
                g++ \
                musl-dev \
                linux-headers \
                libstdc++ \
                rust \
                openssl-dev \
                cargo" \
    APP_DEPS="pcre2 \
              py3-pip \
              py3-cffi \
              py3-setuptools \
              wget \
              curl \
              postgresql-dev \
              procps \
              psmisc \
              vim \
              htop \
              tzdata \
              net-tools \
              tar \
              bash \
              make \
              openssl \
              ca-certificates \
              gnupg"
ENV PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=America/Sao_Paulo \
    HOST=0.0.0.0 \
    PORT=3000 \
    LOG=info \
    PIP=24.0 \
    SETUPTOOLS=67.1.0 \
    WHEEL=0.38.4 \
    BUILD_DEPS="python3-dev \
                libffi-dev \
                pcre2-dev \
                build-base \
                gcc \
                g++ \
                musl-dev \
                linux-headers \
                libstdc++ \
                rust \
                openssl-dev \
                cargo" \
    APP_DEPS="pcre2 \
              py3-pip \
              py3-cffi \
              py3-setuptools \
              wget \
              curl \
              postgresql-dev \
              procps \
              psmisc \
              vim \
              htop \
              tzdata \
              net-tools \
              tar \
              bash \
              make \
              openssl \
              ca-certificates \
              gnupg"

COPY . /$USER_APP

RUN set -avex \
    # create user/group first, to be consistent throughost docker variants
    && addgroup -g 500 -S $USER_APP \
    && adduser -S -D -H -u 500 -h /$USER_APP -s /bin/nologin -G $USER_APP -g $USER_APP $USER_APP \
    && mkdir -p /$USER_APP/ \
    && apk update \
    && apk --update add --no-cache --virtual .build-deps $BUILD_DEPS \
    && apk add --no-cache --update --virtual .run-deps $APP_DEPS \
    && ln -sf /usr/share/zoneinfo/$TZ /etc/localtime \
    && ln -s /usr/include/locale.h /usr/include/xlocale.h \
    && echo "$TZ" > /etc/timezone \
    && pip3 install --no-cache-dir pip==$PIP setuptools==$SETUPTOOLS wheel==$WHEEL \
    && cd /$USER_APP \
    && if [ -n "${DEVMODE:-}" ] ; then make devinstall ; else make prodinstall ; fi \
    && make copy_po \
    && mv /$USER_APP/docker-entrypoint.sh /docker-entrypoint.sh \
    && chmod +x /docker-entrypoint.sh \
    && chown -R $USER_APP:$USER_APP /$USER_APP \
    && apk add --upgrade expat \
    && apk del .build-deps \
    && rm -rf /var/cache/apk/* /tmp/* /var/tmp/* /usr/share/man \
    && find /$USER_APP \( -type f -a -name '*.pyc' -o -name '*.pyo' \) -exec rm -rf '{}' +

USER $USER_APP
WORKDIR /$USER_APP
EXPOSE $PORT

HEALTHCHECK --interval=1m --timeout=5s --start-period=1m \
    CMD nc -z -w5 $HOST $PORT || exit 1

VOLUME /$USER_APP
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD []                