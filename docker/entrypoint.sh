#!/bin/sh
set -e
# SteamCMD lives in the data volume so its updates and the cached Steam login survive restarts.
if [ ! -x /data/steam/steamcmd/steamcmd.sh ]; then
    mkdir -p /data/steam
    cp -a /opt/steamcmd /data/steam/steamcmd
fi
exec python -m workshopguard "$@"
