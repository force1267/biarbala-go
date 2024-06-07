FROM golang:alpine AS builder
WORKDIR $GOPATH/src/biarbala/biarbala/

COPY . .

RUN go mod download
RUN go mod verify
RUN GOOS=linux \
    GOARCH=amd64 \
    go build \
    -ldflags="-w -s" \
    -o /go/bin/biarbala \
    ./cmd/biarbala

RUN mkdir -p /data/projects /data/zips

FROM scratch
WORKDIR /app

COPY --from=builder /data /data
COPY --from=builder /go/bin/biarbala /app/biarbala

EXPOSE 8080
ENTRYPOINT ["/app/biarbala"]
