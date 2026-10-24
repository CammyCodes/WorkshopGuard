FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/data/steam \
    STEAMCMD=/data/steam/steamcmd/steamcmd.sh \
    DATA_DIR=/data

# SteamCMD is a 32-bit Linux program; lib32gcc-s1 brings the 32-bit runtime it needs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends lib32gcc-s1 ca-certificates curl tini unzip \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --root-user-action=ignore -r /app/requirements.txt

# capa's rules and library signatures, matching the installed capa version, and YARA Forge's "core" community
# rules. CI rebuilds the image weekly so these stay current.
RUN V=$(pip show flare-capa | sed -n 's/^Version: //p') && mkdir -p /opt/capa /opt/yara-forge && cd /tmp \
 && curl -fsSL -o r.zip "https://github.com/mandiant/capa-rules/archive/refs/tags/v$V.zip" \
 && unzip -q r.zip && mv "capa-rules-$V" /opt/capa/rules \
 && curl -fsSL -o s.zip "https://github.com/mandiant/capa/archive/refs/tags/v$V.zip" \
 && unzip -q s.zip "capa-$V/sigs/*" && mv "capa-$V/sigs" /opt/capa/sigs \
 && curl -fsSL -o f.zip https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip \
 && unzip -q -j f.zip "*yara-rules-core.yar" -d /opt/yara-forge \
 && rm -rf /tmp/*

RUN useradd -m -u 1000 guard \
 && mkdir -p /opt/steamcmd /data/steam /rules \
 && chown -R guard:guard /opt/steamcmd /data /rules

# Download SteamCMD and let it self-update once at build time, so the first start is quick.
USER guard
RUN curl -fsSL https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz | tar xz -C /opt/steamcmd \
 && HOME=/tmp/steamhome /opt/steamcmd/steamcmd.sh +quit >/dev/null 2>&1 || true \
 && rm -rf /tmp/steamhome

COPY --chown=guard:guard workshopguard /app/workshopguard
COPY --chown=guard:guard rules /app/rules
COPY --chown=guard:guard --chmod=755 docker/entrypoint.sh /app/entrypoint.sh

WORKDIR /app
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=30m CMD curl -fs http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["tini", "--", "/app/entrypoint.sh"]
CMD ["watch"]
