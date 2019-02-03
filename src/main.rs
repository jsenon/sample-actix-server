extern crate actix;
extern crate actix_web;
extern crate bytes;
extern crate env_logger;
extern crate futures;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use rustracing_jaeger::reporter::JaegerCompactReporter;
use rustracing_jaeger::Tracer;
use rustracing::sampler::AllSampler;
use rustracing::tag::Tag;

use actix_web::{
    error, http, middleware, server, App, AsyncResponder, Error, HttpMessage,
    HttpRequest, HttpResponse, Result
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
    fn start(&self, _: &HttpRequest<S>) -> Result<Started> {
        Ok(Started::Done)
    }

    /// Method is called when handler returns response,
    /// but before sending http message to peer.
    fn response(&self, _: &HttpRequest<S>, mut resp: HttpResponse)
        -> Result<Response>
    {
        resp.headers_mut().insert(
            header::HeaderName::try_from("X-VERSION").unwrap(),
            header::HeaderValue::from_static("0.1.0"));
        resp.headers_mut().insert(
            header::HeaderName::try_from("X-APP-NAME").unwrap(),
            header::HeaderValue::from_static("Sample-Actix-server"));
        Ok(Response::Done(resp))
    }
}



fn index(_: &HttpRequest) -> String {
    format!("Hello")
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
    let view = r.headers().get("X-Custom-Id");
    
    println!("Header: {:?}", view);

    let time : u64 = 5;
    let (tracer, span_rx) = Tracer::new(AllSampler);
    std::thread::spawn(move || {
        let reporter = JaegerCompactReporter::new("SampleServer").unwrap();
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
                .tag(Tag::new("App", "Demo-Webapp"))
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
    env_logger::init();
    let sys = actix::System::new("sample-actix-server");
    server::new(|| {
        App::new()
            .middleware(middleware::Logger::default())
            .middleware(Headers)
            .resource("/user", |r| r.method(http::Method::POST).f(post_user))
            .resource("/", |r| r.method(http::Method::GET).f(index))
            .resource("/span", |r| r.method(http::Method::GET).f(span))
    }).bind("127.0.0.1:8080")
        .unwrap()
        .shutdown_timeout(1)
        .start();

    println!("Started http server: 127.0.0.1:8080");
    let _ = sys.run();
}