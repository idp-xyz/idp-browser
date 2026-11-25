# The renderer image: idp-browser and a pinned Chromium, with no shell, no package manager and nothing else (ADR-0001 D10).
#
# The Chromium is chromedp's headless-shell build of Chromium 159.0.8154.13 (BSD-3-Clause), taken by the digest of its
# multi-platform index and nothing else: the tag moves, the digest does not. The default below is the platform's copy of it
# (releases/mirror-images.yaml, ghcr.io/idp-xyz/mirror, the same digest: a mirrored image IS the source image), since Docker Hub is
# rate limited and often unreachable; CHROMIUM_IMAGE is overridden by deploy/build.sh to the copy the
# builder has (the offline build has no registry).
#
# Stage 1 copies out of that image exactly what Chromium needs to run: its directory, the shared libraries the dynamic
# linker finds for it and for the libraries NSS loads by name later (dlopen), the fonts and their configuration. Stage 2
# is scratch: the final image has none of the Debian userland (no sh, no apt, no coreutils), so a Chromium escape finds
# no tools in the container.
ARG CHROMIUM_IMAGE=ghcr.io/idp-xyz/mirror:docker.io__chromedp__headless-shell__159.0.8154.13@sha256:381353d3530ab9d579d2fe8b9c0f4519c995617f5a71daf6bb649e2d12005bd9
FROM ${CHROMIUM_IMAGE} AS chromium
RUN set -eu; mkdir -p /out/usr/lib64 /out/etc /out/profile /out/tmp; \
    cp -a /headless-shell /out/headless-shell; rm -f /out/headless-shell/run.sh; \
    # the libraries of Chromium and of what NSS, glibc and fontconfig load by name at run time
    LIBDIR=/usr/lib/x86_64-linux-gnu; \
    for b in /headless-shell/headless-shell $LIBDIR/libnss3.so $LIBDIR/libsoftokn3.so $LIBDIR/libfreebl3.so $LIBDIR/libfreeblpriv3.so $LIBDIR/libnssckbi.so $LIBDIR/libnssdbm3.so \
             $LIBDIR/libfontconfig.so.1 $LIBDIR/libnss_files.so.2 $LIBDIR/libnss_dns.so.2 $LIBDIR/libresolv.so.2; do \
      [ -e "$b" ] || continue; echo "$b"; ldd "$b" | awk '/=> \//{print $3} /^[[:space:]]*\/lib/{print $1}'; \
    done | sort -u > /libs; \
    while read -r p; do \
      [ -e "$p" ] || continue; \
      phys="$(readlink -f "$(dirname "$p")")/$(basename "$p")"; \
      cp -a --parents "$phys" /out; cp -a --parents "$(readlink -f "$p")" /out; \
    done < /libs; \
    cp -a --parents $LIBDIR/*.chk /out 2>/dev/null || true; \
    ln -s usr/lib /out/lib; ln -s usr/lib64 /out/lib64; \
    cp -a /etc/fonts /out/etc/fonts; cp -a --parents /usr/share/fonts /out; \
    printf 'idp-browser:x:10600:10600:idp-browser:/profile:/sbin/nologin\n' > /out/etc/passwd; \
    printf 'idp-browser:x:10600:\n' > /out/etc/group; \
    chown -R 10600:10600 /out/profile /out/tmp; chmod 1777 /out/tmp

FROM scratch
COPY --from=chromium /out/ /
COPY idp-browser /idp-browser
# no files to write outside the profile directory (a tmpfs in the pod) and /tmp
USER 10600:10600
ENV IDP_BROWSER_CHROME=/headless-shell/headless-shell IDP_BROWSER_PROFILE_DIR=/profile
ENTRYPOINT ["/idp-browser"]
