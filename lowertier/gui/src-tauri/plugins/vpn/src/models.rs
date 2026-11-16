#[derive(serde::Serialize)]
pub struct Request {
    pub action: String,
    pub payload: serde_json::Value,
}
