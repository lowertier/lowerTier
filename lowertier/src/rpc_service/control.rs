use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::control::v1::*,
        rpc_types::{controller::BaseController, error::Result},
    },
};

mod token;
pub use token::ControlToken;

#[derive(Clone)]
pub struct ControlPlaneService {
    manager: Arc<NetworkInstanceManager>,
    token: Arc<ControlToken>,
}

impl ControlPlaneService {
    pub fn new(manager: Arc<NetworkInstanceManager>, token: ControlToken) -> Self {
        Self {
            manager,
            token: Arc::new(token),
        }
    }

    fn authorize(&self, meta: Option<&RequestMeta>) -> std::result::Result<(), ApiError> {
        if meta.is_some_and(|meta| self.token.matches(&meta.control_token)) {
            return Ok(());
        }
        Err(ApiError {
            code: "UNAUTHENTICATED".into(),
            message: "A valid control token is required.".into(),
            field_path: "meta.control_token".into(),
            retryable: false,
        })
    }
}

#[async_trait::async_trait]
impl ControlPlaneV1Rpc for ControlPlaneService {
    type Controller = BaseController;

    async fn get_capabilities(
        &self,
        _: BaseController,
        request: GetCapabilitiesRequest,
    ) -> Result<GetCapabilitiesResponse> {
        if let Err(error) = self.authorize(request.meta.as_ref()) {
            return Ok(GetCapabilitiesResponse {
                error: Some(error),
                ..Default::default()
            });
        }
        Ok(GetCapabilitiesResponse {
            api_version: "1".into(),
            methods: vec!["GetCapabilities".into()],
            max_page_size: 256,
            max_watch_wait_ms: 20_000,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn control_token_is_required() {
        let dir = tempfile::tempdir().unwrap();
        let service = ControlPlaneService::new(
            Arc::new(NetworkInstanceManager::new()),
            ControlToken::load_or_create(&dir.path().join("control.token")).unwrap(),
        );
        let response = service
            .get_capabilities(BaseController::default(), GetCapabilitiesRequest::default())
            .await
            .unwrap();
        assert_eq!(response.error.unwrap().code, "UNAUTHENTICATED");
    }
}
