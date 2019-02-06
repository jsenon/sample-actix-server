extern crate actix;
extern crate actix_web;
extern crate bytes;
extern crate futures;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

extern crate reqwest;

#[macro_use]
extern crate log;

use rustracing::sampler::AllSampler;
use rustracing::tag::Tag;
use rustracing_jaeger::reporter::JaegerBinaryReporter;
use rustracing_jaeger::span::Span;
use rustracing_jaeger::Tracer;

use actix_web::middleware::{Middleware, Response, Started};
use actix_web::{
    error, http, middleware, server, App, AsyncResponder, Error, HttpMessage, HttpRequest,
    HttpResponse, Result,
};

use http::{header, HttpTryFrom};

use bytes::BytesMut;
use futures::{Future, Stream};

use std::io::Read;
use std::thread;
use std::time::Duration;

use chrono::prelude::*;

use log::{Level, Metadata, Record};

struct JSONLogger;

impl log::Log for JSONLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            //This is imperfect: special characters in the JSON string are not
            //properly escaped.
            let json = format!(
                r#"{{"time":"{}","level":"{}","version":{},"msg":"{}"}}"#,
                format!("{}", Utc::now().to_rfc3339()),
                record.level(),
                env!("CARGO_PKG_VERSION"),
                record.args()
            );

            thread::spawn(move || {
                //Do something with the JSON.
                println!("{}", json);
            });
        }
    }

    fn flush(&self) {}
}

static LOGGER: JSONLogger = JSONLogger;

#[derive(Debug, Serialize, Deserialize)]
struct MyObj {
    name: String,
    age: i32,
}
#[derive(Debug, Clone)]
struct MyHeader {
    name: String,
    value: String,
}

struct Headers; // <- Our middleware

/// Middleware implementation, middlewares are generic over application state,
/// so you can access state with `HttpRequest::state()` method.
impl<S> Middleware<S> for Headers {
    /// Method is called when request is ready. It may return
    /// future, which should resolve before next middleware get called.
    fn start(&self, req: &HttpRequest<S>) -> Result<Started> {
        let r = req.clone();
        let _view = r.headers().get("X-Custom-Id");

        // println!("Header: {:?}", view.unwrap());
        Ok(Started::Done)
    }

    /// Method is called when handler returns response,
    /// but before sending http message to peer.
    fn response(&self, _: &HttpRequest<S>, mut resp: HttpResponse) -> Result<Response> {
        resp.headers_mut().insert(
            header::HeaderName::try_from("X-VERSION").unwrap(),
            header::HeaderValue::from_static(&APPVER),
        );
        resp.headers_mut().insert(
            header::HeaderName::try_from("X-APP-NAME").unwrap(),
            header::HeaderValue::from_static(&APPNAME),
        );
        Ok(Response::Done(resp))
    }
}

const INCOMING_HEADERS: [&str; 7] = [
    "x-request-id",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-b3-parentspanid",
    "x-b3-sampled",
    "x-b3-flags",
    "x-ot-span-context",
];

lazy_static! {
    static ref APPNAME: String =
        std::env::var("MY_APP_NAME").unwrap_or_else(|_| env!("CARGO_PKG_NAME").to_string());
    static ref APPVER: String = env!("CARGO_PKG_VERSION").to_string();
    static ref TAC: String =
        std::env::var("MY_TAC_API").unwrap_or_else(|_| "http://127.0.0.1:8000/tac".to_string());
}

fn index(_: &HttpRequest) -> String {
    let ver: &str = &APPVER;
    format!("Hello! My version is: {}", ver)
}

fn tic(req: &HttpRequest) -> HttpResponse {
    //
    // We need to propagate header
    //
    let mut myheaders = Vec::new();
    let r = req.clone();
    for i in 0..INCOMING_HEADERS.len() {
        if r.headers().get(INCOMING_HEADERS[i]).is_some() {
            let val = r
                .headers()
                .get(INCOMING_HEADERS[i])
                .unwrap()
                .to_str()
                .unwrap();
            let headername = INCOMING_HEADERS[i].to_string();
            myheaders.push(MyHeader {
                name: headername.to_string(),
                value: val.to_string(),
            });
        }
    }
    info!("Global Headers: {:?}", myheaders);
    let mut injectheaders = reqwest::header::HeaderMap::new();
    let mut i = 0;
    for header in &myheaders {
        let MyHeader { name, .. } = header;
        if name == "x-request-id" {
            injectheaders.insert(
                "x-request-id",
                reqwest::header::HeaderValue::from_str(&myheaders[i].clone().value).unwrap(),
            );
        } else if name == "x-b3-traceid" {
            injectheaders.insert(
                "x-b3-traceid",
                reqwest::header::HeaderValue::from_str(&myheaders[i].clone().value).unwrap(),
            );
        } else if name == "x-b3-spanid" {
            injectheaders.insert(
                "x-b3-spanid",
                reqwest::header::HeaderValue::from_str(&myheaders[i].clone().value).unwrap(),
            );
        } else if name == "x-b3-parentspanid" {
            injectheaders.insert(
                "x-b3-parentspanid",
                reqwest::header::HeaderValue::from_str(&myheaders[i].clone().value).unwrap(),
            );
        } else if name == "x-b3-sampled" {
            injectheaders.insert(
                "x-b3-sampled",
                reqwest::header::HeaderValue::from_str(&myheaders[i].clone().value).unwrap(),
            );
        } else if name == "x-b3-flags" {
            injectheaders.insert(
                "x-b3-flags",
                reqwest::header::HeaderValue::from_str(&myheaders[i].clone().value).unwrap(),
            );
        } else if name == "x-ot-span-context" {
            injectheaders.insert(
                "x-ot-span-context",
                reqwest::header::HeaderValue::from_str(&myheaders[i].clone().value).unwrap(),
            );
        }
        i = i + 1;
    }
    info!("Injected Headers: {:?}", injectheaders);
    //
    // End of Header Propagation
    //

    let myclient = reqwest::Client::new();
    let mut response = myclient
        .get(&*TAC)
        .headers(injectheaders)
        .send()
        .expect("Failed to send request");
    info!("Status Response: {:?}", response.status());

    let mut buf = String::new();
    response
        .read_to_string(&mut buf)
        .expect("Failed to read response");

    info!("Response Body: {:?}", buf);
    HttpResponse::Ok().content_type("plain/text").body(buf)
}

fn tac(req: &HttpRequest) -> HttpResponse {
    let mut myheaders = Vec::new();
    let r = req.clone();
    for i in 0..INCOMING_HEADERS.len() {
        if r.headers().get(INCOMING_HEADERS[i]).is_some() {
            let val = r
                .headers()
                .get(INCOMING_HEADERS[i])
                .unwrap()
                .to_str()
                .unwrap();
            let headername = INCOMING_HEADERS[i].to_string();
            info!("Headers Tac: {:?}", val);
            myheaders.push(MyHeader {
                name: headername,
                value: val.to_string(),
            });
        }
    }
    let data = format!("tac");
    HttpResponse::Ok().content_type("plain/text").body(data)
}

const MAX_SIZE: usize = 262_144;

fn post_user(req: &HttpRequest) -> Box<Future<Item = HttpResponse, Error = Error>> {
    req.payload()
        .from_err()
        .fold(BytesMut::new(), move |mut body, chunk| {
            // limit max size of in-memory payload
            if (body.len() + chunk.len()) > MAX_SIZE {
                Err(error::ErrorBadRequest("overflow"))
            } else {
                body.extend_from_slice(&chunk);
                Ok(body)
            }
        })
        .and_then(|body| {
            let obj = serde_json::from_slice::<MyObj>(&body)?;
            Ok(HttpResponse::Ok().json(obj))
        })
        .responder()
}

fn span(req: &HttpRequest) -> HttpResponse {
    let r = req.clone();
    let _view = r.headers().get("X-Custom-Id");
    let (tracer, span_rx) = Tracer::new(AllSampler);
    std::thread::spawn(move || {
        let reporter = JaegerBinaryReporter::new(&APPNAME).unwrap();
        for span in span_rx {
            reporter.report(&[span]).unwrap();
        }
    });
    {
        let mut span = tracer
            .span("Span")
            .tag(Tag::new("App", "Sample server"))
            .tag(Tag::new("Fn", "span"))
            .start();
        span.log(|log| {
            log.std().message("Testing Span");
        });
        get_version(span, tracer);
    }
    let data = format!("Span generated");
    HttpResponse::Ok()
        .content_type("plain/text")
        .header("X-Hdr", "sample")
        .body(data)
}

fn get_version(context: Span, tracer: Tracer) -> String {
    let mut ver = String::new();
    let time: u64 = 5;
    let mut span1 = tracer
        .span("get-version")
        .child_of(&context)
        .tag(Tag::new("Version", "0.1"))
        .start();
    span1.log(|log| {
        log.std().message("Retrieve version from cargo.toml");
    });
    std::thread::sleep(Duration::from_millis(time));
    info!("Span0 {:?}", context);
    info!("Span1 {:?}", span1);
    ver.push_str(env!("CARGO_PKG_NAME"));
    ver
}

fn main() {
    ::std::env::set_var("RUST_LOG", "info,actix_web=info");
    let addr = match std::env::var("SERVER_HOST") {
        Ok(host) => host,
        Err(_e) => "0.0.0.0:8000".to_string(),
    };

    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    let sys = actix::System::new("sample-actix-server");
    server::new(|| {
        App::new()
            .middleware(middleware::Logger::default())
            .middleware(Headers)
            .resource("/user", |r| r.method(http::Method::POST).f(post_user))
            .resource("/", |r| r.method(http::Method::GET).f(index))
            .resource("/span", |r| r.method(http::Method::GET).f(span))
            .resource("/tic", |r| r.method(http::Method::GET).f(tic))
            .resource("/tac", |r| r.method(http::Method::GET).f(tac))
    })
    .bind(&addr)
    .unwrap()
    .shutdown_timeout(1)
    .start();
    // info!(json, "Application started"; "started_at" => format!("{}", time::now().rfc3339()));
    info!("Started http server {}", &addr);
    let _ = sys.run();
}
