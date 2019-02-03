# Simple actix Server

Note: **Currently in DRAFT**

Simple Actix Server with Opentracing implementation

## Prerequisite

## Build

## Run

```sh
cargo run
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
s```

### TODO

- [ ] Link frontend to backend
- [ ] DockerFile
- [ ] Add opentracing func