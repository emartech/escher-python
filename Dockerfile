FROM python:3.8.18-alpine3.19

RUN mkdir /escher
WORKDIR /escher

COPY setup.py /escher
COPY requirements-dev.txt /escher

RUN python -m pip install --upgrade pip && \
    pip install build && \
    pip install -r requirements-dev.txt
