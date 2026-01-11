use axum::Json;
use axum::extract::Path;
use std::collections::HashMap;
use std::time::Duration;

use crate::core::wx_info::get_wx_info;
use crate::core::wx_key_hook;
use crate::utils::Result;
use super::models::*;

pub async fn get_wx_info_handler(
    wx_offs: axum::extract::State<HashMap<String, Vec<u32>>>,
) -> Result<Json<Vec<WxInfoResponse>>> {
    let infos = get_wx_info(&wx_offs)?;

    let responses: Vec<WxInfoResponse> = infos.into_iter().map(|info| {
        WxInfoResponse {
            pid: info.pid,
            version: info.version,
            account: info.account,
            mobile: info.mobile,
            nickname: info.nickname,
            mail: info.mail,
            wxid: info.wxid,
            key: info.key,
            wx_dir: info.wx_dir,
        }
    }).collect();

    Ok(Json(responses))
}

/// 检查 keykey.dll 是否可用
pub async fn check_hook_status_handler() -> Result<Json<HookStatusResponse>> {
    let available = wx_key_hook::is_wx_key_available();
    
    Ok(Json(HookStatusResponse {
        available,
        message: if available {
            "keykey.dll 已加载，Hook 功能可用".to_string()
        } else {
            "keykey.dll 未找到。请从 https://github.com/ycccccccy/wx_key/releases 下载并放置到 backend/dll/ 目录".to_string()
        },
    }))
}

/// 通过 Hook 方式获取指定 PID 的密钥
pub async fn get_key_by_hook_handler(
    Path(pid): Path<u32>,
) -> Result<Json<HookKeyResponse>> {
    // 检查 DLL 是否可用
    if !wx_key_hook::is_wx_key_available() {
        return Ok(Json(HookKeyResponse {
            success: false,
            key: None,
            message: "keykey.dll 不可用。请从 https://github.com/ycccccccy/wx_key/releases 下载并放置到 backend/dll/ 目录".to_string(),
        }));
    }
    
    // 使用 Hook 方式获取密钥，超时 30 秒
    match wx_key_hook::get_key_by_hook(pid, Duration::from_secs(30)) {
        Ok(key) => {
            Ok(Json(HookKeyResponse {
                success: true,
                key: Some(key),
                message: "成功获取密钥".to_string(),
            }))
        }
        Err(e) => {
            Ok(Json(HookKeyResponse {
                success: false,
                key: None,
                message: format!("获取密钥失败: {}", e),
            }))
        }
    }
}
