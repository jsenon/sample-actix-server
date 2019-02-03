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
    HttpRequest, HttpResponse,
};

use bytes::BytesMut;
use futures::{Future, Stream};


#[derive(Debug, Serialize, Deserialize)]
struct MyObj {
    name: String,
    age: i32,
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

fn main() {
    ::std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    let sys = actix::System::new("json-example");

    let (tracer, span_rx) = Tracer::new(AllSampler);
    std::thread::spawn(move || {
        let reporter = JaegerCompactReporter::new("SampleServer").unwrap();
        for span in span_rx {
            reporter.report(&[span]).unwrap();
        }
    });
    {
        let mut span = tracer
            .span("Main")
            .tag(Tag::new("App", "Sample server"))
            .tag(Tag::new("Fn", "main"))
            .start();
        span.log(|log| {
            log.std().message("Starting web server");
        });
    }
    
    server::new(|| {
        App::new()
            .middleware(middleware::Logger::default())
            .resource("/user", |r| r.method(http::Method::POST).f(post_user))
            .resource("/", |r| r.method(http::Method::GET).f(index))
    }).bind("127.0.0.1:8080")
        .unwrap()
        .shutdown_timeout(1)
        .start();

    println!("Started http server: 127.0.0.1:8080");
    let _ = sys.run();
}