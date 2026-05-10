#!/usr/bin/env bash
set -euo pipefail

PACKPATH="$CI_PROJECT_DIR"
PACKDST="$CI_PROJECT_DIR/scripts/debian_package/e2debian_package"

apt update && apt install --no-install-recommends --no-install-suggests -y curl git ca-certificates util-linux binutils libpcre2-8-0 || true
git clone https://github.com/fredbcode/scripts || true
cp ${PACKPATH}/src/e2guardian ${PACKDST}/data/usr/sbin/e2guardian || true
chmod +x ${PACKDST}/data/usr/sbin/e2guardian || true
cp -Rf ${PACKPATH}/configs ${PACKDST}/data/etc/e2guardian || true
mkdir -p ${PACKPATH}/share/e2guardian/languages || true
cp -Rf ${PACKPATH}/data/languages ${PACKDST}/data/usr/share/e2guardian/ || true
cp ${PACKPATH}/data/*.gif ${PACKDST}/data/usr/share/e2guardian/ || true
cp ${PACKPATH}/data/*swf ${PACKDST}/data/usr/share/e2guardian/ || true
cp ${PACKPATH}/data/scripts/e2guardian.service ${PACKDST}/data/lib/systemd/system || true
find ${PACKDST}/ -type f -name "Makefil*" -delete || true
find ${PACKDST}/ -type f -name "*.in" -delete || true
SIZE=$(stat -c %s ${PACKDST}/data || echo 0) && echo $SIZE && sed -i "s/Installed-Size:.*$/Installed-Size: $SIZE/g" ${PACKDST}/control/control || true

# replace legacy pcre deps with pcre2
sed -i "s/libssl3/libssl3/g" ${PACKDST}/control/control || true
sed -i "s/libevent-pthreads-2.1-6/libevent-pthreads-2.1-7/g" ${PACKDST}/control/control || true
sed -i "s/libpcre3/libpcre2-8-0/g" ${PACKDST}/control/control || true
sed -i "s/libpcre2-8-0/libpcre2-8-0, libpcre2-posix3/g" ${PACKDST}/control/control || true

# determine version
VFULL=""
if [ -x "${PACKDST}/data/usr/sbin/e2guardian" ]; then
  VFULL=$(${PACKDST}/data/usr/sbin/e2guardian -v 2>/dev/null | sed -n 1p | cut -d ' ' -f 2 || true)
fi
if [ -z "$VFULL" ]; then
  VFULL=$(git -C $CI_PROJECT_DIR rev-parse --short HEAD || echo "unknown")
fi
sed -i "s/Version:.*$/Version: $VFULL/g" ${PACKDST}/control/control || true
cat ${PACKDST}/control/control || true
echo "export VFULL=$VFULL" >> $CI_PROJECT_DIR/scripts/debian_package/variables || true

cd ${PACKDST} && cd .. && ./rebuild.sh e2"$OS"_package || true
find $CI_PROJECT_DIR -name ".git" -exec rm -r "{}" + || true

