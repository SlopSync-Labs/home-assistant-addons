ARG BUILD_FROM
FROM python:3.11-alpine

ENV LANG=C.UTF-8
WORKDIR /app

RUN pip install --no-cache-dir requests flask

COPY run.sh /run.sh
COPY npm_export_import.py /app/npm_export_import.py
RUN chmod a+x /run.sh

CMD ["/run.sh"]
