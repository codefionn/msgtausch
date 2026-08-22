FROM docker.io/library/python:3.13-alpine
RUN adduser -D -H app
WORKDIR /app
COPY server.py /app/server.py
USER app
ENV PORT=5678
ENV TLS=false
EXPOSE 5678 8443
ENTRYPOINT ["python3", "/app/server.py"]
