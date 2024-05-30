FROM --platform=linux/amd64 golang:1.22-alpine3.19 AS build
WORKDIR /app
COPY . .
RUN go build -o ocsp_controller

FROM --platform=linux/amd64 alpine:3.19
WORKDIR /app
COPY --from=build /app/ocsp_controller ocsp-controller
ENTRYPOINT [ "/app/ocsp-controller" ]
EXPOSE 8443