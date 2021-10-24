FROM debian:stable-slim
WORKDIR /tmp/e2guardian
#COPY --chown=1161 src/e2guardian /usr/sbin/e2guardian 
#COPY --chown=1161 configs /etc/e2guardian 
#COPY --chown=1161 data/languages /usr/share/e2guardian/languages 
#COPY --chown=1161 data/*swf /usr/share/e2guardian/
RUN apt-get update && apt-get install --no-upgrade --no-install-recommends --no-install-suggests -y sed libevent-pthreads-* libssl1.1 ca-certificates curl \
    && adduser --no-create-home --uid 1161 --group --system e2guardian \
    && mkdir -p /run/e2guardian \
    && mkdir -p /var/log/e2guardian && chown -R e2guardian /var/log/e2guardian && chown -R e2guardian /run/e2guardian \
    && rm -Rf /tmp/* \
    && find /etc -type f -name "Makefil*" -delete \
    && find /etc -type f -name "*.in" -delete \
    && find /etc -type f -name "*.am" -delete \
    && find /usr/share -type f -name "Makefil*" -delete \
    && find /usr/share -type f -name "*.in" -delete \
    && find /usr/share -type f -name "*.am" -delete \
    && sed -i "s/^#dockermode.*$/dockermode\ =\ on/" /etc/e2guardian/e2guardian.conf \
    && sed -i "s/^#pidfilename.*$/pidfilename\ =\ \/run\/e2guardian\/e2.pid/" /etc/e2guardian/e2guardian.conf \
    && sed -i "s/^#icapport.*$/icapport\ =\ 1344/" /etc/e2guardian/e2guardian.conf \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -Rf /var/lib/apt/lists/* 

HEALTHCHECK CMD curl http://localhost:8080/internal.test.e2guardian.org | grep "e2guardian" || exit 1
USER e2guardian
EXPOSE 8080
CMD ["e2guardian", "-N"]
