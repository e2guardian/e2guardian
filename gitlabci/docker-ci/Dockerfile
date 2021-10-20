FROM alpine:3.13 AS build
# exclude /tmp/e2guardian from first layer (reduce size)

FROM debian:stable-slim
COPY --from=build /tmp/e2guardian /tmp/e2guardian
WORKDIR /tmp/e2guardian
RUN apt-get update && apt-get install --no-upgrade --no-install-recommends --no-install-suggests -y sed libevent-pthreads-* libssl1.1 ca-certificates curl \
    && adduser --no-create-home --uid 1161 --group --system e2guardian \
    && cp src/e2guardian /usr/sbin/e2guardian \
    && chmod +x /usr/sbin/e2guardian \     
    && cp -Rf configs /etc/e2guardian \
    && mkdir -p /usr/share/e2guardian/languages \
    && mkdir -p /run/e2guardian \
    && mkdir -p /var/log/e2guardian && chown -R e2guardian /var/log/e2guardian && chown -R e2guardian /etc/e2guardian && chown -R e2guardian /run/e2guardian \
    && cp -Rf data/languages /usr/share/e2guardian/ \
    && cp data/*.gif /usr/share/e2guardian/ \
    && cp data/*swf /usr/share/e2guardian/ \
    && sed -i "s/^#dockermode.*$/dockermode\ =\ on/" /etc/e2guardian/e2guardian.conf \
    && sed -i "s/^#pidfilename.*$/pidfilename\ =\ \/run\/e2guardian\/e2.pid/" /etc/e2guardian/e2guardian.conf \
    && sed -i "s/^#icapport.*$/icapport\ =\ 1344/" /etc/e2guardian/e2guardian.conf \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/* \
    && rm -rf /tmp/*

HEALTHCHECK CMD curl http://localhost:8080/internal.test.e2guardian.org | grep "e2guardian" || exit 1
USER e2guardian
EXPOSE 8080
CMD ["e2guardian", "-N"]
