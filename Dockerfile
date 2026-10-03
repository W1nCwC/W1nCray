FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/W1nCwC/W1nCray/cmd.version=${VERSION}" -o /out/W1nCray .

FROM alpine:3
RUN apk add --no-cache ca-certificates tzdata && mkdir -p /etc/W1nCray
COPY --from=build /out/W1nCray /usr/local/bin/W1nCray
COPY release/config/ /etc/W1nCray/
ENV XRAY_LOCATION_ASSET=/etc/W1nCray
WORKDIR /etc/W1nCray
ENTRYPOINT ["/usr/local/bin/W1nCray", "-c", "/etc/W1nCray/config.yml"]
