use crate::utils::Result;
use std::ffi::{c_char, c_int, CStr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

/// keykey.dll 的函数类型定义
type InitializeHookFn = unsafe extern "C" fn(target_pid: u32) -> bool;
type PollKeyDataFn = unsafe extern "C" fn(key_buffer: *mut c_char, buffer_size: c_int) -> bool;
type GetStatusMessageFn = unsafe extern "C" fn(status_buffer: *mut c_char, buffer_size: c_int, out_level: *mut c_int) -> bool;
type CleanupHookFn = unsafe extern "C" fn() -> bool;
type GetLastErrorMsgFn = unsafe extern "C" fn() -> *const c_char;

/// keykey.dll 管理器
pub struct WxKeyDll {
    #[allow(dead_code)]
    library: libloading::Library,
    initialize_hook: InitializeHookFn,
    poll_key_data: PollKeyDataFn,
    get_status_message: GetStatusMessageFn,
    cleanup_hook: CleanupHookFn,
    get_last_error_msg: GetLastErrorMsgFn,
}

impl WxKeyDll {
    /// 加载 keykey.dll
    pub fn load() -> Result<Self> {
        let dll_path = Self::find_dll_path()?;
        
        tracing::info!("Loading keykey.dll from: {:?}", dll_path);
        
        unsafe {
            let library = libloading::Library::new(&dll_path)
                .map_err(|e| anyhow::anyhow!("Failed to load keykey.dll: {}", e))?;
            
            // 先获取所有函数指针到临时变量
            let init_fn: InitializeHookFn = *library
                .get::<InitializeHookFn>(b"InitializeHook")
                .map_err(|e| anyhow::anyhow!("Failed to get InitializeHook: {}", e))?;
            
            let poll_fn: PollKeyDataFn = *library
                .get::<PollKeyDataFn>(b"PollKeyData")
                .map_err(|e| anyhow::anyhow!("Failed to get PollKeyData: {}", e))?;
            
            let status_fn: GetStatusMessageFn = *library
                .get::<GetStatusMessageFn>(b"GetStatusMessage")
                .map_err(|e| anyhow::anyhow!("Failed to get GetStatusMessage: {}", e))?;
            
            let cleanup_fn: CleanupHookFn = *library
                .get::<CleanupHookFn>(b"CleanupHook")
                .map_err(|e| anyhow::anyhow!("Failed to get CleanupHook: {}", e))?;
            
            let error_fn: GetLastErrorMsgFn = *library
                .get::<GetLastErrorMsgFn>(b"GetLastErrorMsg")
                .map_err(|e| anyhow::anyhow!("Failed to get GetLastErrorMsg: {}", e))?;
            
            // 现在可以安全地移动 library
            Ok(Self {
                library,
                initialize_hook: init_fn,
                poll_key_data: poll_fn,
                get_status_message: status_fn,
                cleanup_hook: cleanup_fn,
                get_last_error_msg: error_fn,
            })
        }
    }
    
    /// 查找 keykey.dll 路径
    fn find_dll_path() -> Result<PathBuf> {
        // 搜索多个可能的位置
        let search_paths = [
            // 当前目录下的 dll 目录（cargo run 时）
            std::env::current_dir()
                .ok()
                .map(|p| p.join("dll").join("keykey.dll")),
            // 项目根目录/backend/dll 目录
            std::env::current_dir()
                .ok()
                .map(|p| p.join("backend").join("dll").join("keykey.dll")),
            // 可执行文件同级的 dll 目录
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("dll").join("keykey.dll"))),
            // 可执行文件同级目录直接放置
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("keykey.dll"))),
            // 可执行文件上级目录的 dll 目录（适用于 target/debug 目录）
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent()
                    .and_then(|p| p.parent())
                    .and_then(|p| p.parent())
                    .map(|p| p.join("dll").join("keykey.dll"))),
        ];
        
        for path in search_paths.into_iter().flatten() {
            tracing::debug!("Checking DLL path: {:?}", path);
            if path.exists() {
                return Ok(path);
            }
        }
        
        Err(anyhow::anyhow!(
            "keykey.dll not found. Please download from https://github.com/ycccccccy/wx_key/releases and place it in backend/dll/ folder"
        ).into())
    }
    
    /// 初始化 Hook
    pub fn initialize(&self, pid: u32) -> Result<()> {
        tracing::info!("Initializing hook for PID: {}", pid);
        
        let success = unsafe { (self.initialize_hook)(pid) };
        
        if !success {
            let error = self.get_last_error();
            return Err(anyhow::anyhow!("Failed to initialize hook: {}", error).into());
        }
        
        Ok(())
    }
    
    /// 轮询获取密钥（非阻塞）
    pub fn poll_key(&self) -> Option<String> {
        let mut buffer = [0i8; 65];
        
        let has_data = unsafe {
            (self.poll_key_data)(buffer.as_mut_ptr(), buffer.len() as c_int)
        };
        
        if has_data {
            let key = unsafe {
                CStr::from_ptr(buffer.as_ptr())
                    .to_string_lossy()
                    .to_string()
            };
            Some(key)
        } else {
            None
        }
    }
    
    /// 获取状态消息
    pub fn get_status(&self) -> Option<(String, StatusLevel)> {
        let mut buffer = [0i8; 256];
        let mut level: c_int = 0;
        
        let has_status = unsafe {
            (self.get_status_message)(buffer.as_mut_ptr(), buffer.len() as c_int, &mut level)
        };
        
        if has_status {
            let message = unsafe {
                CStr::from_ptr(buffer.as_ptr())
                    .to_string_lossy()
                    .to_string()
            };
            let status_level = match level {
                0 => StatusLevel::Info,
                1 => StatusLevel::Success,
                2 => StatusLevel::Error,
                _ => StatusLevel::Info,
            };
            Some((message, status_level))
        } else {
            None
        }
    }
    
    /// 清理 Hook
    pub fn cleanup(&self) -> Result<()> {
        tracing::info!("Cleaning up hook");
        
        let success = unsafe { (self.cleanup_hook)() };
        
        if !success {
            let error = self.get_last_error();
            return Err(anyhow::anyhow!("Failed to cleanup hook: {}", error).into());
        }
        
        Ok(())
    }
    
    /// 获取最后一次错误
    pub fn get_last_error(&self) -> String {
        unsafe {
            let ptr = (self.get_last_error_msg)();
            if ptr.is_null() {
                "Unknown error".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().to_string()
            }
        }
    }
}

impl Drop for WxKeyDll {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// 状态级别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusLevel {
    Info,
    Success,
    Error,
}

/// 全局 DLL 实例（延迟加载）
static WX_KEY_DLL: OnceLock<Option<WxKeyDll>> = OnceLock::new();

/// 获取全局 DLL 实例
pub fn get_wx_key_dll() -> Result<&'static WxKeyDll> {
    // 确保只初始化一次
    WX_KEY_DLL.get_or_init(|| {
        match WxKeyDll::load() {
            Ok(dll) => Some(dll),
            Err(e) => {
                tracing::warn!("Failed to load keykey.dll: {}", e);
                None
            }
        }
    });
    
    WX_KEY_DLL.get()
        .and_then(|opt| opt.as_ref())
        .ok_or_else(|| anyhow::anyhow!("keykey.dll not loaded").into())
}

/// 检查 keykey.dll 是否可用
pub fn is_wx_key_available() -> bool {
    get_wx_key_dll().is_ok()
}

/// 使用 Hook 方式获取微信密钥
/// 
/// 这个函数会：
/// 1. 初始化 Hook
/// 2. 等待密钥捕获（最多等待 timeout 时间）
/// 3. 返回捕获到的密钥
/// 4. 清理 Hook
pub fn get_key_by_hook(pid: u32, timeout: Duration) -> Result<String> {
    let dll = get_wx_key_dll()?;
    
    // 初始化 Hook
    dll.initialize(pid)?;
    
    let start = std::time::Instant::now();
    let mut key: Option<String> = None;
    
    // 轮询等待密钥
    while start.elapsed() < timeout {
        // 检查状态消息
        while let Some((msg, level)) = dll.get_status() {
            match level {
                StatusLevel::Info => tracing::info!("[wx_key] {}", msg),
                StatusLevel::Success => tracing::info!("[wx_key] ✓ {}", msg),
                StatusLevel::Error => tracing::error!("[wx_key] ✗ {}", msg),
            }
        }
        
        // 尝试获取密钥
        if let Some(k) = dll.poll_key() {
            key = Some(k);
            break;
        }
        
        thread::sleep(Duration::from_millis(100));
    }
    
    // 清理 Hook
    dll.cleanup()?;
    
    key.ok_or_else(|| anyhow::anyhow!("Timeout waiting for key capture").into())
}

/// 异步获取密钥的任务管理器
/// 用于后台轮询获取密钥，目前未使用但保留以备后续扩展
#[allow(dead_code)]
pub struct KeyCaptureTask {
    pid: u32,
    key: Arc<Mutex<Option<String>>>,
    running: Arc<AtomicBool>,
    error: Arc<Mutex<Option<String>>>,
}

#[allow(dead_code)]
impl KeyCaptureTask {
    /// 创建新任务
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            key: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            error: Arc::new(Mutex::new(None)),
        }
    }
    
    /// 启动后台捕获任务
    pub fn start(&self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Task already running").into());
        }
        
        let dll = get_wx_key_dll()?;
        dll.initialize(self.pid)?;
        
        self.running.store(true, Ordering::SeqCst);
        
        let key = self.key.clone();
        let running = self.running.clone();
        let error = self.error.clone();
        
        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                if let Ok(dll) = get_wx_key_dll() {
                    // 处理状态消息
                    while let Some((msg, level)) = dll.get_status() {
                        match level {
                            StatusLevel::Info => tracing::info!("[wx_key] {}", msg),
                            StatusLevel::Success => tracing::info!("[wx_key] ✓ {}", msg),
                            StatusLevel::Error => {
                                tracing::error!("[wx_key] ✗ {}", msg);
                                if let Ok(mut e) = error.lock() {
                                    *e = Some(msg);
                                }
                            }
                        }
                    }
                    
                    // 尝试获取密钥
                    if let Some(k) = dll.poll_key() {
                        if let Ok(mut key_guard) = key.lock() {
                            *key_guard = Some(k);
                        }
                        running.store(false, Ordering::SeqCst);
                        break;
                    }
                }
                
                thread::sleep(Duration::from_millis(100));
            }
        });
        
        Ok(())
    }
    
    /// 检查是否获取到密钥
    pub fn get_key(&self) -> Option<String> {
        self.key.lock().ok().and_then(|k| k.clone())
    }
    
    /// 检查是否正在运行
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
    
    /// 获取错误信息
    pub fn get_error(&self) -> Option<String> {
        self.error.lock().ok().and_then(|e| e.clone())
    }
    
    /// 停止任务
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Ok(dll) = get_wx_key_dll() {
            let _ = dll.cleanup();
        }
    }
}

impl Drop for KeyCaptureTask {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_find_dll_path() {
        // 这个测试只检查逻辑，不实际加载 DLL
        let result = WxKeyDll::find_dll_path();
        println!("DLL path search result: {:?}", result);
    }
    
    #[test]
    fn test_is_available() {
        let available = is_wx_key_available();
        println!("keykey.dll available: {}", available);
    }
}
