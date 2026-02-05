use axum::{Json, Router, routing::{get, post}, extract::Path};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::core::wx_info::{get_wx_info, get_info_details};
use crate::core::wx_key_hook;
use crate::core::key_finder::KeyFinder;
use crate::core::version_detection::VersionOffsetDetector;
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
        // 新的密钥搜索路由（安全方式）
        .route(
            "/api/wx/key/search/:pid",
            post(search_key_handler),
        )
        .route(
            "/api/wx/key/candidates/:pid",
            get(get_key_candidates_handler),
        )
        .route(
            "/api/wx/key/verify",
            post(verify_key_handler),
        )
        // Hook 相关的路由（旧方式，有风险）
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

// =============== 新的密钥搜索功能（安全方式，不使用 Hook）===============

#[derive(Debug, Serialize)]
pub struct KeySearchResponse {
    pub success: bool,
    pub key: Option<String>,
    pub candidates_count: usize,
    pub best_confidence: u32,
    pub method: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct KeyCandidateResponse {
    pub key_hex: String,
    pub address: String,
    pub confidence: u32,
    pub method: String,
}

#[derive(Debug, Serialize)]
pub struct KeyCandidatesResponse {
    pub success: bool,
    pub candidates: Vec<KeyCandidateResponse>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyKeyRequest {
    pub pid: u32,
    pub key: String,
    pub db_path: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyKeyResponse {
    pub success: bool,
    pub valid: bool,
    pub message: String,
}

/// 通过内存搜索自动查找密钥（安全方式）
async fn search_key_handler(
    Path(pid): Path<u32>,
) -> Result<Json<KeySearchResponse>> {
    tracing::info!("开始内存搜索获取密钥 (PID: {})", pid);
    
    // 首先获取微信版本
    let wx_offs = load_wx_offs()?;
    let info = get_info_details(pid, &wx_offs)
        .map_err(|_| AppError::NotFound(format!("WeChat process {} not found", pid)))?;
    
    let version = info.version;
    
    // 使用新的密钥查找器
    let finder = KeyFinder::new(pid, &version);
    
    match finder.find_keys() {
        Ok(candidates) => {
            if candidates.is_empty() {
                Ok(Json(KeySearchResponse {
                    success: false,
                    key: None,
                    candidates_count: 0,
                    best_confidence: 0,
                    method: "memory_scan".to_string(),
                    message: "未找到任何候选密钥。请确保微信已登录并且有聊天记录。".to_string(),
                }))
            } else {
                let best = &candidates[0];
                Ok(Json(KeySearchResponse {
                    success: true,
                    key: Some(best.key_hex.clone()),
                    candidates_count: candidates.len(),
                    best_confidence: best.confidence,
                    method: best.method.clone(),
                    message: format!(
                        "找到 {} 个候选密钥。最佳候选置信度: {}%",
                        candidates.len(),
                        best.confidence
                    ),
                }))
            }
        }
        Err(e) => {
            Ok(Json(KeySearchResponse {
                success: false,
                key: None,
                candidates_count: 0,
                best_confidence: 0,
                method: "memory_scan".to_string(),
                message: format!("密钥搜索失败: {}", e),
            }))
        }
    }
}

/// 获取所有候选密钥（供用户选择）
async fn get_key_candidates_handler(
    Path(pid): Path<u32>,
) -> Result<Json<KeyCandidatesResponse>> {
    tracing::info!("获取所有候选密钥 (PID: {})", pid);
    
    // 首先获取微信版本
    let wx_offs = load_wx_offs()?;
    let info = get_info_details(pid, &wx_offs)
        .map_err(|_| AppError::NotFound(format!("WeChat process {} not found", pid)))?;
    
    let version = info.version;
    
    match VersionOffsetDetector::get_key_candidates(pid, &version) {
        Ok(candidates) => {
            let response_candidates: Vec<KeyCandidateResponse> = candidates
                .into_iter()
                .map(|c| KeyCandidateResponse {
                    key_hex: c.key_hex,
                    address: format!("0x{:x}", c.address),
                    confidence: c.confidence,
                    method: c.method,
                })
                .collect();
            
            Ok(Json(KeyCandidatesResponse {
                success: true,
                candidates: response_candidates,
                message: "获取候选密钥成功".to_string(),
            }))
        }
        Err(e) => {
            Ok(Json(KeyCandidatesResponse {
                success: false,
                candidates: vec![],
                message: format!("获取候选密钥失败: {}", e),
            }))
        }
    }
}

/// 验证密钥是否正确
async fn verify_key_handler(
    Json(req): Json<VerifyKeyRequest>,
) -> Result<Json<VerifyKeyResponse>> {
    tracing::info!("验证密钥 (PID: {}, 数据库: {})", req.pid, req.db_path);
    
    let db_path = std::path::Path::new(&req.db_path);
    
    if !db_path.exists() {
        return Ok(Json(VerifyKeyResponse {
            success: false,
            valid: false,
            message: format!("数据库文件不存在: {}", req.db_path),
        }));
    }
    
    // 获取微信版本
    let wx_offs = load_wx_offs()?;
    let info = get_info_details(req.pid, &wx_offs)
        .map_err(|_| AppError::NotFound(format!("WeChat process {} not found", req.pid)))?;
    
    let version = info.version;
    let finder = KeyFinder::new(req.pid, &version);
    
    match finder.verify_key_with_database(&req.key, db_path) {
        Ok(valid) => {
            Ok(Json(VerifyKeyResponse {
                success: true,
                valid,
                message: if valid {
                    "密钥验证成功！可以用于解密数据库。".to_string()
                } else {
                    "密钥验证失败。这可能不是正确的密钥。".to_string()
                },
            }))
        }
        Err(e) => {
            Ok(Json(VerifyKeyResponse {
                success: false,
                valid: false,
                message: format!("验证过程出错: {}", e),
            }))
        }
    }
}
