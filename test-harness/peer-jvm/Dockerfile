# Portable, self-building JVM peer image (the default). The builder stage assembles the arch-INDEPENDENT
# fat jar (JVM bytecode), so one build runs on ANY host/arch — linux/amd64, linux/arm64, Apple Silicon.
# Unlike the native peer (Kotlin/Native must cross-build per arch), the JVM jar is identical everywhere;
# only the base JRE differs per arch, which the multi-arch eclipse-temurin image handles. For a fast
# CI/local path that skips the gradle build, see Dockerfile.prebuilt (used by run-interop.sh when the jar
# is already built on the host / downloaded as a CI artifact).
#
# Build context is the REPO ROOT (compose sets context: ..), so the builder sees every module.

FROM eclipse-temurin:21-jdk AS builder
WORKDIR /src
COPY . .
RUN ./gradlew --no-daemon --no-configuration-cache :webrtc-harness-endpoint:peerJar && \
    cp webrtc-harness-endpoint/build/libs/webrtc-harness-peer-all.jar /peer.jar

FROM eclipse-temurin:21-jre
# iproute2 for the entrypoint's default-route rewrite. No io_uring (socket-udp uses NIO on the JVM), so —
# unlike the native peer — this image needs no seccomp=unconfined at runtime, only NET_ADMIN.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /peer.jar /usr/local/lib/peer.jar
COPY test-harness/peer-jvm/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
