//! Fehlerantworten im Bitwarden-Format.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub body: Value,
}

pub type ApiResult<T> = Result<T, ApiError>;

fn model(msg: &str) -> Value {
    json!({
        "message": msg,
        "validationErrors": null,
        "errorModel": {"message": msg, "object": "error"},
        "object": "error"
    })
}

impl ApiError {
    pub fn new(status: StatusCode, msg: &str) -> ApiError {
        ApiError { status, body: model(msg) }
    }
    pub fn bad(msg: &str) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, msg)
    }
    pub fn unauthorized() -> ApiError {
        ApiError::new(StatusCode::UNAUTHORIZED, "Nicht angemeldet oder Sitzung abgelaufen.")
    }
    pub fn not_found() -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, "Nicht gefunden.")
    }
    pub fn too_many(msg: &str) -> ApiError {
        ApiError::new(StatusCode::TOO_MANY_REQUESTS, msg)
    }
    pub fn forbidden(msg: &str) -> ApiError {
        ApiError::new(StatusCode::FORBIDDEN, msg)
    }
    /// Interner Fehler: Details nur ins Log, nie an den Client.
    pub fn internal(e: impl std::fmt::Display) -> ApiError {
        eprintln!("FEHLER: {e}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Interner Fehler.")
    }
    /// Fehler fuer `/identity/connect/token` (OAuth-Format).
    pub fn grant(msg: &str) -> ApiError {
        ApiError {
            status: StatusCode::BAD_REQUEST,
            body: json!({
                "error": "invalid_grant",
                "error_description": msg,
                "ErrorModel": {"Message": msg, "Object": "error"}
            }),
        }
    }
}

impl From<turso::Error> for ApiError {
    fn from(e: turso::Error) -> Self {
        ApiError::internal(format!("Datenbank: {e}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}
