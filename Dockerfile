FROM alpine
RUN apk update
RUN apk add curl
WORKDIR /
RUN curl -L -o opa https://openpolicyagent.org/downloads/v0.53.1/opa_linux_amd64_static
RUN chmod +x ./opa
RUN mv /opa /bin/opa
COPY ./chart/policy/ /policy/
COPY ./data.json /data.json
COPY ./input.json /input.json
RUN opa test /policy
RUN opa eval --bundle /policy --data /data.json --input /input.json --format pretty 'data'
LABEL org.opencontainers.image.source=https://github.com/mars-office/huna-opa-policy