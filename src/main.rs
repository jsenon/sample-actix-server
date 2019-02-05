extern crate actix;
extern crate actix_web;
extern crate bytes;
extern crate env_logger;
extern crate futures;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

#[macro_use] extern crate log;

use rustracing_jaeger::reporter::JaegerBinaryReporter;
use rustracing_jaeger::Tracer;
use rustracing::sampler::AllSampler;
use rustracing::tag::Tag;

use actix_web::{
    error, http, middleware, server, App, AsyncResponder, Error, HttpMessage,
    HttpRequest, HttpResponse, Result, client
};
use actix_web::middleware::{Middleware, Started, Response};

use http::{header, HttpTryFrom};

use bytes::BytesMut;
use futures::{Future, Stream};

use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
struct MyObj {
    name: String,
    age: i32,
}

struct Headers;  // <- Our middleware

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
    fn response(&self, _: &HttpRequest<S>, mut resp: HttpResponse)
        -> Result<Response>
    {
        resp.headers_mut().insert(
            header::HeaderName::try_from("X-VERSION").unwrap(),
            header::HeaderValue::from_static(&APPVER));
        resp.headers_mut().insert(
            header::HeaderName::try_from("X-APP-NAME").unwrap(),
            header::HeaderValue::from_static(&APPNAME));
        Ok(Response::Done(resp))
    }
}

lazy_static! {
        static ref APPNAME: String = std::env::var("MY_APP_NAME").unwrap_or_else(|_| "NONAME".to_string());
        static ref APPVER: String = std::env::var("MY_APP_VER").unwrap_or_else(|_| "0.0.0".to_string());
        static ref TAC: String = std::env::var("MY_TAC_API").unwrap_or_else(|_| "http://127.0.0.1:8000/tac".to_string());

}


fn index(_: &HttpRequest) -> String {
    format!("Hello")
}

fn tic(_req: &HttpRequest) -> Box<Future<Item = HttpResponse, Error = Error>> {
    client::ClientRequest::get(&*TAC)
        .finish().unwrap()
        .send()
        .map_err(Error::from)          // <- convert SendRequestError to an Error
        .and_then(
            |resp| resp.body()         // <- this is MessageBody type, resolves to complete body
                .from_err()            // <- convert PayloadError to an Error
                .and_then(|body| {     // <- we got complete body, now send as server response
                    Ok(HttpResponse::Ok().body(body))
                }))
        .responder()
}



fn tac(req: &HttpRequest) -> HttpResponse {
    let r = req.clone();
    let view = r.headers().get("X-APP-NAME");
    println!("Header {:?}", view);
    let data = format!("tac");
    HttpResponse::Ok()
        .content_type("plain/text")
        .body(data)
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
    let time : u64 = 5;
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
        {
            let mut span1 = tracer
                .span("Sleep")
                .child_of(&span)
                .tag(Tag::new("App", "Sample server"))
                .tag(Tag::new("Fn", "span:sleep"))
                .start();
            span1.log(|log| {
                log.std().message("Sleeping");
            });
            std::thread::sleep(Duration::from_millis(time));
        }
    }
    let data = format!("Span generated, stay {}ms sleeping", time);
    HttpResponse::Ok()
        .content_type("plain/text")
        .header("X-Hdr", "sample")
        .body(data)
}

fn main() {

    ::std::env::set_var("RUST_LOG", "actix_web=info");
    let addr = match std::env::var("SERVER_HOST") {
        Ok(host) => host,
        Err(_e) => "0.0.0.0:8000".to_string(),
    };
    env_logger::init();
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

    }).bind(&addr)
        .unwrap()
        .shutdown_timeout(1)
        .start();

    println!("Started http server: {}", &addr);
    let _ = sys.run();
}