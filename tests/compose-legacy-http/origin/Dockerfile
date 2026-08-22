FROM docker.io/library/python:3.13-alpine

RUN adduser -D -H app

WORKDIR /app
COPY server.py healthcheck.py /app/

USER app
ENV PORT=8081
ENV HEADER_LIMIT=32768
ENV MAX_CONNECTIONS=64

EXPOSE 8081
HEALTHCHECK --interval=1s --timeout=2s --retries=30 --start-period=1s CMD ["python3", "/app/healthcheck.py"]

ENTRYPOINT ["python3", "/app/server.py"]
