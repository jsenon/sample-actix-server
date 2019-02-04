# select build image
FROM rust:1.32 as build

COPY . /sample-actix-server
WORKDIR /sample-actix-server
# this build step will cache your dependencies
RUN cargo build --release

# our final base
FROM gcr.io/distroless/cc
# copy the build artifact from the build stage
COPY --from=build /sample-actix-server/target/release/sample-actix-server .
ENV MY_JAEGER_AGENT=""
ENV MY_APP_NAME="sample-actix-server"
ENV MY_APP_VER="0.0.1"
# set the startup command to run your binary
CMD ["./sample-actix-server"]