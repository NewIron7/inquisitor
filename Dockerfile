FROM alpine:latest

RUN apk update && apk add --no-cache \
    bash 

CMD [ "tail", "-f", "/dev/null" ]