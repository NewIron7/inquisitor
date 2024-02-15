# Use Alpine Linux as the base image
FROM alpine:latest

# Install lftp
RUN apk update && apk add --no-cache lftp bash python3

# Set the work directory
WORKDIR /ftp

# copy the content of ftp-files folder
COPY ftp-files/ .

# Default command: open an interactive shell
CMD ["tail", "-f", "/dev/null" ]
