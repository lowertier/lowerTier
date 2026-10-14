use crate::proto::{api::control::v1::ApiError, rpc_types::error::Error as RpcError};

#[derive(Debug)]
pub struct CliError(pub ApiError);
impl CliError {
    pub fn new(code: &str, message: impl Into<String>, field_path: &str) -> Self {
        Self(ApiError {
            code: code.into(),
            message: message.into(),
            field_path: field_path.into(),
            retryable: matches!(code, "unavailable" | "deadline_exceeded"),
        })
    }
    pub fn exit_code(&self) -> u8 {
        match self.0.code.as_str() {
            "invalid_argument" | "validation" => 2,
            "permission_denied" | "unauthenticated" => 3,
            "not_found" | "ambiguous" => 4,
            "conflict" | "restart_required" => 5,
            "unavailable" | "deadline_exceeded" => 6,
            "partial_failure" => 7,
            _ => 1,
        }
    }
}
impl From<ApiError> for CliError {
    fn from(error: ApiError) -> Self {
        Self(error)
    }
}
impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::new("invalid_argument", error.to_string(), "values")
    }
}
impl From<RpcError> for CliError {
    fn from(error: RpcError) -> Self {
        match error {
            RpcError::Timeout(_) => Self::new(
                "deadline_exceeded",
                "The control request exceeded its deadline.",
                "",
            ),
            RpcError::TunnelError(_) | RpcError::Shutdown => {
                Self::new("unavailable", "The control connection is unavailable.", "")
            }
            _ => Self::new("internal", "The control RPC failed.", ""),
        }
    }
}
pub type Result<T> = std::result::Result<T, CliError>;
