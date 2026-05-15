FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./

# First run will train the model and save it to /app/data
ENV PYTHONUNBUFFERED=1

EXPOSE 8000
CMD ["python", "app.py"]
