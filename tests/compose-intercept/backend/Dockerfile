FROM docker.io/library/python:3.14.7-alpine3.24
RUN adduser -D -H app
WORKDIR /app
COPY server.py /app/server.py
USER app
ENV PORT=5678
ENV TLS=false
EXPOSE 5678 8443
ENTRYPOINT ["python3", "/app/server.py"]
