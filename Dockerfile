FROM debian:12 AS builder

ARG GITHUB_SHA="$(git rev-parse HEAD)"

LABEL com.trailfinder.git-commit="${GITHUB_SHA}"

# fixing the issue with getting OOMKilled in BuildKit
RUN mkdir /trailfinder
COPY . /trailfinder/

WORKDIR /trailfinder
# install the dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    curl \
    libssl-dev \
    clang \
    git \
    build-essential \
    pkg-config \
    mold
# install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN mv /root/.cargo/bin/* /usr/local/bin/
# do the build bits
ENV CC="/usr/bin/clang"
RUN cargo build --quiet --release --bin trailfinder
RUN chmod +x /trailfinder/target/release/trailfinder

FROM gcr.io/distroless/cc-debian12 AS trailfinder
# # ======================
# https://github.com/GoogleContainerTools/distroless/blob/main/examples/rust/Dockerfile
COPY --from=builder /trailfinder/target/release/trailfinder /
COPY --from=builder /trailfinder/web /web
COPY --from=builder /trailfinder/templates /templates

WORKDIR /
USER nonroot
ENTRYPOINT ["./trailfinder"]

CMD ["web", "--address", "0.0.0.0"]
