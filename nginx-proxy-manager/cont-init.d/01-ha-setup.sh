#!/bin/sh
# Runs early in s6's cont-init sequence.
# Creates the /data sub-directories NPM expects on the HA persistent volume.
mkdir -p /ssl/nginxproxymanager /data/nginx /data/logs /data/access
