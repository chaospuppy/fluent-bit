FROM fluent/fluent-bit:1.5.1 as flb

LABEL org.opencontainers.image.title="fluent-bit" \
      org.opencontainers.image.description="Fluent Bit is a fast Log Processor and Forwarder for Linux, Embedded Linux, MacOS and BSD family operating systems." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.url="https://fluentbit.io" \
      org.opencontainers.image.version="1.5.1" \
      maintainer="cht@dsop.io"

