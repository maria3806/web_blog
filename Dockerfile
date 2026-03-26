FROM golang:1.23-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /blog-app main.go
FROM alpine:3.20

WORKDIR /app

RUN apk add --no-cache ca-certificates wget && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder /blog-app /app/blog-app

COPY --from=builder /build/HTML /app/HTML
COPY --from=builder /build/images /app/images

RUN mkdir -p /app/articles /app/users && \
    chown -R appuser:appgroup /app

ENV PORT=8080
ENV ARTICLES_DIR=/app/articles



ENV USERS_DIR=/app/users


EXPOSE 8080
USER appuser

LABEL org.opencontainers.image.source=https://github.com
LABEL org.opencontainers.image.description="Web-Blog service built with Go and Docker."

CMD ["/app/blog-app"]


