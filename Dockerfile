FROM python:3.12-slim

# Chromium system deps + Node.js
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdbus-1-3 libdrm2 libxkbcommon0 libatspi2.0-0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libx11-xcb1 libfontconfig1 libx11-6 \
    libxcb1 libxext6 libxshmfence1 \
    libglib2.0-0 libgtk-3-0 libpangocairo-1.0-0 libcairo-gobject2 \
    libgdk-pixbuf-2.0-0 libxss1 libxtst6 fonts-liberation \
    fonts-noto-color-emoji fonts-unifont fonts-freefont-ttf \
    fonts-ipafont-gothic fonts-wqy-zenhei fonts-tlwg-loma-otf \
    fonts-urw-base35 \
    xvfb xdotool openbox \
    curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python wrapper
COPY pyproject.toml README.md LICENSE BINARY-LICENSE.md CHANGELOG.md ./
COPY cloakbrowser/ cloakbrowser/
RUN pip install --no-cache-dir ".[serve,geoip]"

# JS wrapper
COPY js/ js/
RUN cd js && npm install && npm run build

# Examples
COPY examples/ examples/

# CLI shortcuts
COPY bin/cloaktest /usr/local/bin/cloaktest
COPY bin/cloakserve /usr/local/bin/cloakserve
COPY bin/fetch-widevine.py /usr/local/bin/fetch-widevine.py
RUN chmod +x /usr/local/bin/cloaktest /usr/local/bin/cloakserve /usr/local/bin/fetch-widevine.py

# Xvfb entrypoint for headed mode support
COPY bin/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Run unprivileged so the Chromium namespace/seccomp sandbox stays on. Upstream
# runs as uid 0, where Chromium refuses to start without --no-sandbox; this fork
# no longer passes that flag, so a non-root uid is load-bearing, not hygiene.
# /tmp is shared with the entrypoint's Xvfb lock cleanup, so keep it writable.
RUN useradd --create-home --shell /bin/bash cloak \
    && chown -R cloak:cloak /app
USER cloak

# Pre-download the Chromium binary during build (not at runtime), as the
# unprivileged user so it lands in that user's ~/.cloakbrowser cache.
# Remove welcome marker so users see it on first container run
RUN python -c "from cloakbrowser import ensure_binary; ensure_binary()" \
    && rm -f ~/.cloakbrowser/.welcome_shown

# No EXPOSE for the CDP port: cloakserve is unauthenticated and now binds
# loopback only. Forward it deliberately (ssh -L) rather than by default.

ENV DISPLAY=:99

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python"]
