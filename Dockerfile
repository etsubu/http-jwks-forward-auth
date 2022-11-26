FROM golang:1.19 as build

WORKDIR /go/src/app
COPY http-forward-auth .

RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/app

# Now copy it into our base image.
FROM gcr.io/distroless/static-debian11:nonroot
COPY --from=build /go/bin/app /
EXPOSE 8080
CMD ["/app"]