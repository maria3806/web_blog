# Stage 1: Builder
FROM golang:1.25.1 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o blog-app .

# Stage 2: Runtime
FROM alpine:3.20

WORKDIR /app

RUN apk add --no-cache ca-certificates wget && \
    addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder /app/blog-app /app/blog-app
COPY --from=builder /app/HTML /app/HTML
COPY --from=builder /app/images /app/images

RUN mkdir -p /app/articles /app/users && \
    chown -R appuser:appgroup /app

ENV PORT=8080
ENV ARTICLES_DIR=/app/articles
ENV USERS_DIR=/app/users
ENV AUTH_USER=admin
ENV AUTH_PASS=password

EXPOSE 8080

USER appuser

CMD ["/app/blog-app"]