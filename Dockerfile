FROM python:3.9-slim

WORKDIR /src

COPY src/ ./src/

RUN pip install pyotp cryptography

CMD ["python", "manager.py"]
