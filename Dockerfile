FROM golang:1.19-alpine3.16 AS build
WORKDIR /app
COPY . .
RUN go build -o ocsp_controller

FROM alpine:3.16
WORKDIR /app
COPY --from=build /app/ocsp_controller ocsp-controller
ENTRYPOINT [ "/app/ocsp-controller" ]