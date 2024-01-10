FROM debian:bookworm-slim as builddocker
ARG PROJECT_DIR
COPY . /tmp/e2guardian

FROM debian:bookworm-slim
ARG PROJECT_DIR
ENV DOCKER_BUILD=/tmp/e2guardian/scripts/debian_package/e2debian_package/data
COPY --from=builddocker --chown=1161 /tmp/e2guardian/src/e2guardian /usr/sbin/e2guardian
COPY --from=builddocker --chown=1161 $DOCKER_BUILD/etc/e2guardian /etc/e2guardian
COPY --from=builddocker --chown=1161 $DOCKER_BUILD/usr/share/e2guardian/languages /usr/share/e2guardian/languages
COPY --from=builddocker --chown=1161 $DOCKER_BUILD/usr/share/e2guardian/*swf /usr/share/e2guardian/
COPY --from=builddocker --chown=1161 $DOCKER_BUILD/usr/share/e2guardian/*gif /usr/share/e2guardian/
RUN apt-get update && apt-get install --no-upgrade --no-install-recommends --no-install-suggests -y rsync sed libevent-pthreads-* ca-certificates curl inotify-tools libpcre3 libssl3 \
    && adduser --no-create-home --uid 1161 --group --system e2guardian \
    && mkdir -p /run/e2guardian \
    && mkdir -p /var/log/e2guardian && chown -R e2guardian /var/log/e2guardian && chown -R e2guardian /run/e2guardian \
    && rm -Rf /tmp/* \
    && sed -i "s/^#dockermode.*$/dockermode\ =\ on/" /etc/e2guardian/e2guardian.conf \
    && sed -i "s/^#pidfilename.*$/pidfilename\ =\ \/run\/e2guardian\/e2.pid/" /etc/e2guardian/e2guardian.conf \
    && sed -i "s/^#icapport.*$/icapport\ =\ 1344/" /etc/e2guardian/e2guardian.conf \
    && echo "# Docker log #" >> /etc/e2guardian/e2guardian.conf \
    && echo "set_error = 'stdout:LOG_ERR'" >> /etc/e2guardian/e2guardian.conf \
    && echo "set_warning = 'stdout:LOG_WARNING'" >> /etc/e2guardian/e2guardian.conf \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -Rf /var/lib/apt/lists/* 

HEALTHCHECK CMD curl --proxy "http://127.0.0.1:8080" http://internal.test.e2guardian.org | grep "e2guardian internal test OK" || exit 1
USER e2guardian
EXPOSE 8080
COPY --from=builddocker --chown=1161 /tmp/e2guardian/gitlabci/docker-ci/run.sh /
COPY --from=builddocker --chown=1161 /tmp/e2guardian/gitlabci/docker-ci/inotify.sh /
RUN chmod +x /inotify.sh /run.sh
USER e2guardian
EXPOSE 8080
ENTRYPOINT ["/run.sh"]

