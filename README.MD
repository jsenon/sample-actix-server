[![Build Status](https://travis-ci.com/jsenon/sample-actix-server.svg?branch=master)](https://travis-ci.com/jsenon/sample-actix-server)
# Simple actix Server

Note: **Currently in DRAFT**

Simple Actix Server with Opentracing implementation:

- Use Istio for service Mesh
- Use Opentracing inside application
- Forward opentracing header in order to see service to service trace in jaegger

## Prerequisite

## Build

Build App:

```sh
cargo build  --release
```

## Run

### Locally

```sh
cargo run
```

### On kubernetes with skaffold

Note: **Adapt skaffold.yaml and kubernetes manifest for your configuration**

- Two services will be deployed with each 2 replicas of this application.
- One sidecar will be added for jaeger agent as library rustacing_jaeger don't implement thrift trace over http
- If Istio is implemented virtualservice will route traffic to your application.

You can build and deploy your app every time your code changes:

```sh
skaffold dev --namespace test --port-forward 
```

or build and deploy your app once, on demand:

```sh
skaffold run
```

## Usage

### Backend

Get version info

```sh
 curl -X GET http://localhost:8080/
```

Create User

```sh
curl -X POST http://localhost8080/user -d '{"name": "titi", "age": 10}'
```

Generate Span and Subspan

```sh
 curl -X GET http://localhost:8080/span
```

Made Tic-tac over two services:

```sh
 curl -X GET http://localhost:8080/tic
```

### Jaeger

If tracing is implemented with Istio you can check your trace, by accessing dashboard.

Setup access to the Jaeger dashboard by using port-forwarding:

```sh
kubectl port-forward -n istio-system $(kubectl get pod -n istio-system -l app=jaeger -o jsonpath='{.items[0].metadata.name}') 16686:16686 &
```

Access the Jaeger dashboard by opening your browser to http://localhost:16686.

## TIPS

These headers must be forwarded when calling other services:

- x-request-id
- x-b3-traceid
- x-b3-spanid
- x-b3-parentspanid
- x-b3-sampled
- x-b3-flags
- x-ot-span-context

## TODO

- [x] Implement opentracing over fn
- [ ] Implement prometheus endpoint