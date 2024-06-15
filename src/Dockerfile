FROM python:3.12-slim

RUN pip3 install Flask-Login
RUN pip3 install Flask-SQLAlchemy

COPY . /opt/app

WORKDIR /opt/app

CMD ["python", "./app.py"]