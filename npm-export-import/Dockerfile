ARG BUILD_FROM
FROM python:3.11-alpine

ENV LANG=C.UTF-8
WORKDIR /app

RUN apk add --no-cache bash

SHELL ["/bin/bash", "-c"]

RUN pip install --no-cache-dir requests flask

COPY run.sh /run.sh
COPY npm_export_import.py /app/npm_export_import.py
COPY icon.png /app/icon.png
COPY config.json /app/config.json
RUN chmod a+x /run.sh

CMD ["/run.sh"]
