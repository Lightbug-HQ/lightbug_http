FROM ghcr.io/prefix-dev/pixi:latest

RUN apt-get update && apt-get install -y git

RUN git clone https://github.com/Lightbug-HQ/lightbug_http

WORKDIR /lightbug_http

ARG DEFAULT_SERVER_PORT=8080
ARG DEFAULT_SERVER_HOST=localhost

EXPOSE ${DEFAULT_SERVER_PORT}

ENV DEFAULT_SERVER_PORT=${DEFAULT_SERVER_PORT}
ENV DEFAULT_SERVER_HOST=${DEFAULT_SERVER_HOST}
ENV APP_ENTRYPOINT=lightbug.🔥

CMD pixi run mojo ${APP_ENTRYPOINT}
