use crate::core::{memory::MemoryManager, memory_map::MemoryMap, process::ProcessManager};
use crate::core::key_finder::{KeyFinder, KeyCandidate};
use crate::utils::Result;
use std::collections::HashMap;
use std::path::Path;

/// 版本偏移量自动检测
pub struct VersionOffsetDetector;

impl VersionOffsetDetector {
    /// 自动检测指定版本的偏移量
    /// 通过内存搜索特征码来定位偏移量
    pub fn detect_offsets(pid: u32, version: &str) -> Result<Vec<u32>> {
        let process = ProcessManager::open(pid)?;
        let memory = MemoryManager::new(process.handle);

        // 获取主要逻辑模块信息
        let module = match MemoryMap::find_wechatwin_dll(pid)? {
            Some(m) => m,
            None => {
                return Err(anyhow::anyhow!("Main module not found").into());
            }
        };

        let wechat_base_address = module.base_address;
        let module_size = module.size;

        let addr_len = if version.starts_with("4.") || version.starts_with("5.") {
            8 // 64位
        } else {
            4 // 32位
        };

        // 尝试检测各个偏移量
        let name_bias = Self::detect_name_offset(&memory, wechat_base_address, module_size, addr_len)?;
        let account_bias = Self::detect_account_offset(&memory, wechat_base_address, module_size, addr_len)?;
        let mobile_bias = Self::detect_mobile_offset(&memory, wechat_base_address, module_size, addr_len)?;
        let mail_bias = Self::detect_mail_offset(&memory, wechat_base_address, module_size, addr_len)?;
        let key_bias = Self::detect_key_offset(&memory, wechat_base_address, module_size, addr_len)?;

        Ok(vec![name_bias, account_bias, mobile_bias, mail_bias, key_bias])
    }

    /// 直接搜索密钥（不依赖偏移量）
    /// 这是微信 4.x 版本推荐的获取密钥方式
    pub fn find_key_directly(pid: u32, version: &str) -> Result<Option<String>> {
        tracing::info!("使用直接内存搜索方式查找密钥 (PID: {}, 版本: {})", pid, version);
        
        let finder = KeyFinder::new(pid, version);
        let candidates = finder.find_keys()?;
        
        if candidates.is_empty() {
            tracing::warn!("未找到任何候选密钥");
            return Ok(None);
        }
        
        // 返回置信度最高的密钥
        let best = &candidates[0];
        tracing::info!(
            "最佳候选密钥: {} (地址: 0x{:x}, 置信度: {}, 方法: {})",
            best.key_hex,
            best.address,
            best.confidence,
            best.method
        );
        
        Ok(Some(best.key_hex.clone()))
    }
    
    /// 直接搜索并验证密钥
    /// 使用实际数据库文件验证候选密钥
    pub fn find_and_verify_key(pid: u32, version: &str, db_path: &Path) -> Result<Option<String>> {
        tracing::info!("使用内存搜索查找密钥并验证 (数据库: {:?})", db_path);
        
        let finder = KeyFinder::new(pid, version);
        let candidates = finder.find_keys()?;
        
        if candidates.is_empty() {
            return Ok(None);
        }
        
        // 按置信度顺序尝试验证
        for candidate in candidates {
            tracing::info!(
                "尝试验证密钥: {} (置信度: {}, 方法: {})",
                candidate.key_hex,
                candidate.confidence,
                candidate.method
            );
            
            if finder.verify_key_with_database(&candidate.key_hex, db_path)? {
                tracing::info!("密钥验证成功！");
                return Ok(Some(candidate.key_hex));
            }
        }
        
        tracing::warn!("所有候选密钥验证失败");
        Ok(None)
    }
    
    /// 获取所有候选密钥（供用户选择）
    pub fn get_key_candidates(pid: u32, version: &str) -> Result<Vec<KeyCandidate>> {
        let finder = KeyFinder::new(pid, version);
        finder.find_keys()
    }

    /// 检测昵称偏移量
    /// 通过搜索特征码来定位
    fn detect_name_offset(
        memory: &MemoryManager,
        base_address: usize,
        module_size: usize,
        _addr_len: usize,
    ) -> Result<u32> {
        // 搜索特征码（这里需要根据实际情况调整）
        // 通常昵称在某个固定的相对位置
        let search_pattern = b"nickname";
        let results = memory.search_memory(search_pattern, base_address, base_address + module_size, 10)?;

        if let Some(&address) = results.first() {
            // 计算相对偏移
            let offset = address as u32 - base_address as u32;
            return Ok(offset);
        }

        // 如果搜索失败，返回0表示未找到
        Ok(0)
    }

    /// 检测账号偏移量
    fn detect_account_offset(
        memory: &MemoryManager,
        base_address: usize,
        module_size: usize,
        _addr_len: usize,
    ) -> Result<u32> {
        // 类似昵称的检测方法
        let search_pattern = b"account";
        let results = memory.search_memory(search_pattern, base_address, base_address + module_size, 10)?;

        if let Some(&address) = results.first() {
            let offset = address as u32 - base_address as u32;
            return Ok(offset);
        }

        Ok(0)
    }

    /// 检测手机号偏移量
    fn detect_mobile_offset(
        _memory: &MemoryManager,
        _base_address: usize,
        _module_size: usize,
        _addr_len: usize,
    ) -> Result<u32> {
        // 搜索手机号特征（通常是11位数字）
        // 这里使用简化的搜索方法
        Ok(0) // 暂时返回0，需要更精确的检测方法
    }

    /// 检测邮箱偏移量
    fn detect_mail_offset(
        _memory: &MemoryManager,
        _base_address: usize,
        _module_size: usize,
        _addr_len: usize,
    ) -> Result<u32> {
        // 搜索邮箱特征（包含@符号）
        Ok(0) // 暂时返回0
    }

    /// 检测密钥偏移量
    /// 对于微信 4.x，推荐使用 find_key_directly 直接搜索密钥
    fn detect_key_offset(
        _memory: &MemoryManager,
        _base_address: usize,
        _module_size: usize,
        _addr_len: usize,
    ) -> Result<u32> {
        // 密钥偏移量检测已被新的直接搜索方法取代
        // 对于 4.x 版本，请使用 find_key_directly 方法
        Ok(0)
    }

    /// 验证检测到的偏移量是否有效
    pub fn validate_offsets(
        pid: u32,
        version: &str,
        offsets: &[u32],
        _wx_offs: &HashMap<String, Vec<u32>>,
    ) -> Result<bool> {
        if offsets.len() < 5 {
            return Ok(false);
        }

        // 如果所有偏移量都是0，认为无效
        if offsets.iter().all(|&x| x == 0) {
            return Ok(false);
        }

        // 尝试使用这些偏移量获取微信信息
        // 如果能够成功获取，则认为偏移量有效
        let process = ProcessManager::open(pid)?;
        let memory = MemoryManager::new(process.handle);

        let wechat_base_address = match MemoryMap::get_wechatwin_base_address(pid) {
            Ok(addr) => addr,
            Err(_) => return Ok(false),
        };

        let addr_len = if version.starts_with("4.") || version.starts_with("5.") {
            8
        } else {
            4
        };

        // 尝试读取昵称（如果偏移量不为0）
        if offsets[0] > 0 {
            let name_address = wechat_base_address + offsets[0] as usize;
            if let Ok(ptr) = memory.read_pointer(name_address, addr_len) {
                if ptr > 0 {
                    if memory.read_string(ptr, 64).is_ok() {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }
}
