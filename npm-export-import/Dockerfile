ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:latest
FROM ${BUILD_FROM}

# Use bash as the default shell for the app
ENV LANG C.UTF-8

# Copy files
COPY run.sh /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
