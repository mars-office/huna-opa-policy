FROM alpine
RUN apk update
RUN apk add curl
WORKDIR /
RUN curl -L -o opa https://openpolicyagent.org/downloads/v0.53.1/opa_linux_amd64_static
RUN chmod +x ./opa
RUN mv /opa /bin/opa
COPY ./com/ /policy/com/
RUN opa check /policy
RUN opa test /policy
RUN opa build /policy --ignore=".*"
LABEL org.opencontainers.image.source=https://github.com/mars-office/huna-opa-policy