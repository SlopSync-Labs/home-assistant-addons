# Use the official Nginx Proxy Manager image directly.
# BUILD_FROM is declared to satisfy HA's build tooling but not used —
# we want the full NPM image, not the minimal HA base.
ARG BUILD_FROM
FROM jc21/nginx-proxy-manager:2.14.0

# Redirect Let's Encrypt certificate storage to /ssl/nginxproxymanager so certs
# are accessible to other HA add-ons via HA's shared SSL directory.
# NPM's prepare service uses `mountpoint -q /etc/letsencrypt` which requires a
# real Docker volume mount — a symlink doesn't satisfy it. Patch the check to
# a simple existence test so our symlink is accepted.
RUN rm -rf /etc/letsencrypt \
    && ln -s /ssl/nginxproxymanager /etc/letsencrypt \
    && file=$(grep -rl "letsencrypt is not mounted" /etc/s6-overlay/ /app/ 2>/dev/null | head -1) \
    && if [ -n "$file" ]; then \
         sed -i 's|mountpoint -q /etc/letsencrypt|test -e /etc/letsencrypt|g' "$file"; \
       fi

# Run our HA setup script early in s6's cont-init sequence.
# Uses /bin/sh — with-contenv is not available in the jc21 base image.
COPY cont-init.d/01-ha-setup.sh /etc/cont-init.d/01-ha-setup.sh
RUN chmod +x /etc/cont-init.d/01-ha-setup.sh

EXPOSE 80 81 443

# Do NOT override ENTRYPOINT — s6-overlay (/init) must run as PID 1.
