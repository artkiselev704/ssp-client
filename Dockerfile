FROM    golang:1.26 AS build

WORKDIR /build

COPY    ./src/app.go ./src/socks.go ./src/stcp.go ./

RUN     CGO_ENABLED=0 GOOS=linux go build -o app app.go socks.go stcp.go

FROM    gcr.io/distroless/static:nonroot

WORKDIR /app

COPY    ./src/cert.crt ./src/config.json ./
COPY    --from=build /build/app ./

CMD     ["/app/app"]

EXPOSE  2080/tcp
