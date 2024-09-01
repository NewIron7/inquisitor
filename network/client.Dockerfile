FROM alpine:latest

RUN apk update && apk add --no-cache lftp bash python3 tcpdump

WORKDIR /ftp

COPY ftp-files/ .

RUN echo "alias ftptest='lftp -u ftpuser,pass 192.168.1.2'" >> ~/.bashrc

CMD ["tail", "-f", "/dev/null" ]
