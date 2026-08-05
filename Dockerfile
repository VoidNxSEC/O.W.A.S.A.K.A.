FROM golang:1.25-alpine AS builder
RUN apk add --no-cache gcc musl-dev libpcap-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /owasaka ./cmd/oswaka && go mod vendor

FROM alpine:3.20
RUN apk add --no-cache libpcap ca-certificates
COPY --from=builder /owasaka /usr/local/bin/owasaka
RUN mkdir -p /etc/owasaka
COPY --from=builder /app/configs/examples/default.yaml /etc/owasaka/default.yaml
ENTRYPOINT ["owasaka", "--config", "/etc/owasaka/default.yaml"]
