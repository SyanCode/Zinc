FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /zinc .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /data
COPY --from=build /zinc /usr/local/bin/zinc
VOLUME /data
EXPOSE 6697
ENTRYPOINT ["zinc"]
CMD ["serve", "-config", "/data/zinc.json"]
