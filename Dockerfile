FROM golang:1.12 as builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o grafana-auth-proxy .

RUN echo "nobody:x:65534:65534:Nobody:/:" > /etc_passwd

FROM scratch
LABEL maintainer="code@efugulin.com"

WORKDIR /app

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/grafana-auth-proxy .

USER nobody

EXPOSE 5000
CMD ["./grafana-auth-proxy"]