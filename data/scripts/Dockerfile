FROM ubuntu:18.04

ARG BUILD_DATE
ENV VERSION 5.1
ENV OS ubuntu

LABEL commit.e2guardian=$COMMIT build_date.e2guardian=$BUILD_DATE
RUN apt update \
&& apt install --no-install-recommends --no-install-suggests -y curl unzip base-files automake base-passwd \
bash coreutils dash debianutils diffutils dpkg e2fsprogs findutils grep gzip hostname ncurses-base \
libevent-pthreads-* libevent-dev ncurses-bin perl-base sed login sysvinit-utils tar bsdutils \
mount util-linux libc6-dev libc-dev gcc g++ make dpkg-dev autotools-dev debhelper dh-autoreconf dpatch \
libclamav-dev libpcre3-dev zlib1g-dev pkg-config libssl1.1 libssl-dev \
&& cd /tmp && curl -k https://codeload.github.com/e2guardian/e2guardian/zip/v$VERSION > e2.zip && unzip e2.zip && cd e2guardian-$VERSION/ \
&& ./autogen.sh && ./configure  '--prefix=/usr' '--enable-clamd=yes' '--with-proxyuser=e2guardian' '--with-proxygroup=e2guardian' \
'--sysconfdir=/etc' '--localstatedir=/var' '--enable-icap=yes' '--enable-commandline=yes' '--enable-email=yes' \
'--enable-ntlm=yes' '--mandir=${prefix}/share/man' '--infodir=${prefix}/share/info' \
'--enable-pcre=yes' '--enable-sslmitm=yes' 'CPPFLAGS=-mno-sse2 -g -O2' \
&& make \
&& mkdir /etc/e2guardian && cp src/e2guardian /usr/sbin/ && mkdir /var/log/e2guardian \
&& mkdir -p /usr/share/e2guardian/languages && cp -Rf data/languages /usr/share/e2guardian/ && cp data/*.gif /usr/share/e2guardian/ && cp data/*swf /usr/share/e2guardian/ \
&& cp -Rf configs/* /etc/e2guardian/ \
&& adduser --no-create-home --system e2guardian \
&& addgroup --system e2guardian \
&& chmod 750 -Rf /etc/e2guardian && chmod 750 -Rf /usr/share/e2guardian && chown -Rf e2guardian /etc/e2guardian /usr/share/e2guardian /var/log/e2guardian \
&& find /etc/e2guardian -type f -name .in -delete \
&& find /usr/share/e2guardian -type f -name .in -delete \
# ROOT mode if needed ...
# && sed -i "s/#daemonuser = 'e2guardian'/daemonuser = 'root'/g" /etc/e2guardian/e2guardian.conf \
# && sed -i "s/#daemongroup = 'e2guardian'/daemongroup = 'root'/g" /etc/e2guardian/e2guardian.conf \
&& sed -i "s/#dockermode = off/dockermode = on/g" /etc/e2guardian/e2guardian.conf \
&& apt remove -y --allow-remove-essential --purge curl unzip sed libevent-dev libc6-dev libc-dev g++ make dpkg-dev autotools-dev debhelper dh-autoreconf dpatch libclamav-dev libpcre3-dev zlib1g-dev libssl-dev \
&& rm -rf /var/lib/apt/lists/* && rm -Rf /tmp/*
EXPOSE 8080
CMD /usr/sbin/e2guardian
