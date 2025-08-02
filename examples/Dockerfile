# ---- Build Stage ----
# Use an official Go image as the builder.
FROM golang:1.20-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copy the source code into the container
COPY *.go ./

# Build the Go app. CGO_ENABLED=0 is important for a static binary.
# -o /go-hello-scanner creates the output file at the root.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /go-hello-scanner

# ---- Final Stage ----
# Use a minimal, non-root alpine image for the final container.
FROM gcr.io/distroless/static-debian11

# Copy the compiled binary from the builder stage.
COPY --from=builder /go-hello-scanner /

# Expose port 8080 to the outside world.
EXPOSE 8080

# Command to run when the container starts.
CMD ["/go-hello-scanner"]