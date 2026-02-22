FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /veil-go ./cmd/server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates curl
COPY --from=builder /veil-go /usr/local/bin/veil-go
WORKDIR /app
EXPOSE 443 80 8080
CMD ["veil-go"]
