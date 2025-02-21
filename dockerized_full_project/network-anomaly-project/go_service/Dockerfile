FROM golang:1.20

WORKDIR /app

COPY network_logger.go .

RUN go mod init network_logger
RUN go build -o network_logger network_logger.go

CMD ["./network_logger"]
