#[derive(serde::Serialize)]
pub struct Request {
    pub action: String,
    pub payload: String,
}
