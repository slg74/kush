FROM python:3.12-slim
WORKDIR /app
COPY dns_shell.py .
EXPOSE 5353/udp
CMD ["python3", "-u", "dns_shell.py", "server", "--port", "5353"]
