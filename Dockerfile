FROM golang:alpine as build

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o yasp .

FROM scratch

COPY --from=build /build/yasp .

ENTRYPOINT ["./yasp"]
