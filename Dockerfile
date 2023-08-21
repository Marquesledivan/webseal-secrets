FROM python:3-slim-buster

WORKDIR /usr/src/app

COPY src/app/ /usr/src/app/

COPY requirements.txt .

RUN pip install --upgrade pip  && \
    pip install -r requirements.txt && \
    useradd app-seal && \
    chown -R  app-seal:app-seal /usr/src/app/

USER app-seal

EXPOSE 8080

CMD ["gunicorn", "main:app", "--workers", "1", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8080"]