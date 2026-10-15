# Root-level documentation image reference; production services use their own Dockerfiles.
FROM alpine:3.20
CMD ["sh", "-c", "echo CyberShield uses backend/ and frontend/ service images."]
