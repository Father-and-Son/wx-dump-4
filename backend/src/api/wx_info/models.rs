use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WxInfoResponse {
    pub pid: u32,
    pub version: String,
    pub account: Option<String>,
    pub mobile: Option<String>,
    pub nickname: Option<String>,
    pub mail: Option<String>,
    pub wxid: Option<String>,
    pub key: Option<String>,
    pub wx_dir: Option<String>,
}

/// Hook 状态响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookStatusResponse {
    pub available: bool,
    pub message: String,
}

/// Hook 获取密钥响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookKeyResponse {
    pub success: bool,
    pub key: Option<String>,
    pub message: String,
}
