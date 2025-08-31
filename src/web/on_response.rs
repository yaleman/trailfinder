use std::{fmt, time::Duration};

use axum::response::Response;

use tower_http::{LatencyUnit, trace::OnResponse};
use tracing::{Span, info};

struct Latency {
    unit: LatencyUnit,
    duration: Duration,
}

impl fmt::Display for Latency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.unit {
            LatencyUnit::Seconds => write!(f, "{} s", self.duration.as_secs_f64()),
            LatencyUnit::Millis => write!(f, "{} ms", self.duration.as_millis()),
            LatencyUnit::Micros => write!(f, "{} μs", self.duration.as_micros()),
            LatencyUnit::Nanos => write!(f, "{} ns", self.duration.as_nanos()),
            _ => {
                // Default to millis if an unknown unit is provided
                write!(f, "{} ms", self.duration.as_millis())
            }
        }
    }
}

/// The default [`OnResponse`] implementation used by [`Trace`].
///
/// [`Trace`]: super::Trace
#[derive(Clone, Debug)]
pub struct DefaultOnResponse {
    // level: Level,
    latency_unit: LatencyUnit,
    include_headers: bool,
}

impl Default for DefaultOnResponse {
    fn default() -> Self {
        Self {
            // level: Level::INFO,
            latency_unit: LatencyUnit::Millis,
            include_headers: false,
        }
    }
}

impl DefaultOnResponse {
    /// Create a new `DefaultOnResponse`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<B> OnResponse<B> for DefaultOnResponse {
    fn on_response(self, response: &Response<B>, latency: Duration, _: &Span) {
        let latency = Latency {
            unit: self.latency_unit,
            duration: latency,
        };
        let response_headers = self
            .include_headers
            .then(|| tracing::field::debug(response.headers()));

        info!(
            %latency,
            status = status(response),
            response_headers,
        );
    }
}

fn status<B>(res: &Response<B>) -> Option<i32> {
    // gRPC-over-HTTP2 uses the "application/grpc[+format]" content type, and gRPC-Web uses
    // "application/grpc-web[+format]" or "application/grpc-web-text[+format]", where "format" is
    // the message format, e.g. +proto, +json.
    //
    // So, valid grpc content types include (but are not limited to):
    //  - application/grpc
    //  - application/grpc+proto
    //  - application/grpc-web+proto
    //  - application/grpc-web-text+proto
    //
    // For simplicity, we simply check that the content type starts with "application/grpc".

    Some(res.status().as_u16().into())
}
