FROM python:3.11-slim
WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .
ENV FLASK_APP=app.py
CMD ["flask", "run", "--host=0.0.0.0"]
