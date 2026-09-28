FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
ENV FLASK_ENV=production
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
