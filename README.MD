# Simple actix Server

Note: **Currently in DRAFT**

Simple Actix Server with Opentracing implementation

## Prerequisite

## Build

## Run

### Locally

```sh
cargo run
```

### On kubernetes with skaffold

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

### TODO

- [ ] Implement opentracing over fn