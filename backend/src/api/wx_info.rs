use axum::{Json, Router, routing::{get, post}, extract::Path};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::core::wx_info::{get_wx_info, get_info_details};
use crate::core::wx_key_hook;
use crate::models::wx::WxInfoResponse;
use crate::config::{load_wx_offs, save_wx_offs};
use crate::utils::{AppError, Result};

pub fn router(wx_offs: HashMap<String, Vec<u32>>) -> Router {
    let wx_offs = Arc::new(wx_offs);
    
    Router::new()
        .route(
            "/api/wx/info",
            post({
                let wx_offs = wx_offs.clone();
                move |_: ()| get_wx_info_handler(wx_offs)
            }),
        )
        .route(
            "/api/wx/info/:pid",
            get({
                let wx_offs = wx_offs.clone();
                move |path: Path<u32>| get_wx_info_by_pid_handler(path, wx_offs)
            }),
        )
        .route(
            "/api/wx/version/list",
            get(get_version_list_handler),
        )
        .route(
            "/api/wx/version/offs",
            post(add_version_offs_handler),
        )
        // Hook 相关的路由
        .route(
            "/api/wx/hook/status",
            get(check_hook_status_handler),
        )
        .route(
            "/api/wx/hook/key/:pid",
            post(get_key_by_hook_handler),
        )
}

async fn get_wx_info_handler(
    wx_offs: Arc<HashMap<String, Vec<u32>>>,
) -> Result<Json<Vec<WxInfoResponse>>> {
    let infos = get_wx_info(&wx_offs)?;
    
    let responses: Vec<WxInfoResponse> = infos
        .into_iter()
        .map(|info| WxInfoResponse {
            pid: info.pid,
            version: info.version,
            account: info.account,
            mobile: info.mobile,
            nickname: info.nickname,
            mail: info.mail,
            wxid: info.wxid,
            key: info.key,
            wx_dir: info.wx_dir,
        })
        .collect();

    Ok(Json(responses))
}

async fn get_wx_info_by_pid_handler(
    Path(pid): Path<u32>,
    wx_offs: Arc<HashMap<String, Vec<u32>>>,
) -> Result<Json<WxInfoResponse>> {
    let info = get_info_details(pid, &wx_offs)
        .map_err(|_| AppError::NotFound(format!("WeChat process {} not found", pid)))?;
    
    Ok(Json(WxInfoResponse {
        pid: info.pid,
        version: info.version,
        account: info.account,
        mobile: info.mobile,
        nickname: info.nickname,
        mail: info.mail,
        wxid: info.wxid,
        key: info.key,
        wx_dir: info.wx_dir,
    }))
}

async fn get_version_list_handler() -> Result<Json<VersionListResponse>> {
    let wx_offs = load_wx_offs()?;
    let versions: Vec<String> = wx_offs.keys().cloned().collect();
    
    Ok(Json(VersionListResponse { versions }))
}

#[derive(Debug, Deserialize)]
pub struct AddVersionOffsRequest {
    pub version: String,
    pub offs: Vec<u32>,
}

#[derive(Debug, Serialize)]
pub struct VersionListResponse {
    pub versions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AddVersionOffsResponse {
    pub success: bool,
    pub message: String,
}

async fn add_version_offs_handler(
    Json(req): Json<AddVersionOffsRequest>,
) -> Result<Json<AddVersionOffsResponse>> {
    let mut wx_offs = load_wx_offs()?;
    
    if wx_offs.contains_key(&req.version) {
        return Ok(Json(AddVersionOffsResponse {
            success: false,
            message: format!("版本 {} 已存在", req.version),
        }));
    }
    
    wx_offs.insert(req.version.clone(), req.offs);
    save_wx_offs(&wx_offs)?;
    
    Ok(Json(AddVersionOffsResponse {
        success: true,
        message: format!("成功添加版本 {} 的偏移量", req.version),
    }))
}

// =============== Hook 相关的响应结构体 ===============

#[derive(Debug, Serialize)]
pub struct HookStatusResponse {
    pub available: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct HookKeyResponse {
    pub success: bool,
    pub key: Option<String>,
    pub message: String,
}

// =============== Hook 相关的处理函数 ===============
// ⚠️ 安全警告：以下 Hook 功能可能触发微信安全检测，导致账号被封禁！
// 仅用于开发调试，生产环境请使用手动配置密钥的方式

/// 检查 keykey.dll 是否可用
async fn check_hook_status_handler() -> Result<Json<HookStatusResponse>> {
    let available = wx_key_hook::is_wx_key_available();
    
    Ok(Json(HookStatusResponse {
        available,
        message: if available {
            "⚠️ keykey.dll 已加载。警告：使用 Hook 功能可能触发微信安全检测导致封号！建议使用 wx_key.exe 独立获取密钥后手动配置。".to_string()
        } else {
            "keykey.dll 未找到。这是安全的，建议使用 wx_key.exe 独立工具获取密钥后手动配置。".to_string()
        },
    }))
}

/// ⚠️ 已弃用：通过 Hook 方式获取指定 PID 的密钥
/// 警告：此 API 可能触发微信安全检测导致封号！
/// 推荐使用 wx_key.exe 独立工具获取密钥后手动配置
async fn get_key_by_hook_handler(
    Path(pid): Path<u32>,
) -> Result<Json<HookKeyResponse>> {
    // ⚠️ 严重安全警告
    tracing::warn!("⚠️ 危险操作：正在使用 Hook 方式获取密钥，这可能触发微信安全检测！");
    tracing::warn!("⚠️ 如果账号被强制下线或提示风险，请立即停止使用此功能！");
    
    // 检查 DLL 是否可用
    if !wx_key_hook::is_wx_key_available() {
        return Ok(Json(HookKeyResponse {
            success: false,
            key: None,
            message: "keykey.dll 不可用。建议使用 wx_key.exe 独立工具获取密钥。".to_string(),
        }));
    }
    
    tracing::info!("开始 Hook 获取密钥，请在微信中进行操作（如切换聊天窗口）以触发数据库访问...");
    
    // 使用 Hook 方式获取密钥，超时 60 秒
    // 注意：Hook 只有在微信访问数据库时才能捕获密钥
    match wx_key_hook::get_key_by_hook(pid, Duration::from_secs(60)) {
        Ok(key) => {
            Ok(Json(HookKeyResponse {
                success: true,
                key: Some(key),
                message: "⚠️ 成功获取密钥。警告：此操作可能已被微信检测，请注意账号安全！".to_string(),
            }))
        }
        Err(e) => {
            Ok(Json(HookKeyResponse {
                success: false,
                key: None,
                message: format!("获取密钥失败: {}。建议使用 wx_key.exe 独立工具获取。", e),
            }))
        }
    }
}
