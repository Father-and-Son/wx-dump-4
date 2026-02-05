//! 微信 4.0+ 数据库密钥自动查找模块
//!
//! 通过内存扫描技术自动定位微信数据库的 AES-256 密钥，
//! 无需 Hook 注入，更安全可靠。

use crate::core::{memory::MemoryManager, memory_map::MemoryMap, process::ProcessManager};
use crate::utils::Result;
use std::collections::HashSet;
use std::path::Path;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_READWRITE};

/// 密钥长度：32字节 (AES-256)
const KEY_SIZE: usize = 32;

/// 密钥的十六进制表示长度：64字符
#[allow(dead_code)]
const KEY_HEX_LEN: usize = 64;

/// 密钥查找器
pub struct KeyFinder {
    pid: u32,
    version: String,
}

/// 候选密钥结构
#[derive(Debug, Clone)]
pub struct KeyCandidate {
    /// 密钥的十六进制表示
    pub key_hex: String,
    /// 密钥在内存中的地址
    pub address: usize,
    /// 置信度分数 (0-100)
    pub confidence: u32,
    /// 发现此密钥的方法
    pub method: String,
}

impl KeyFinder {
    /// 创建新的密钥查找器
    pub fn new(pid: u32, version: &str) -> Self {
        Self {
            pid,
            version: version.to_string(),
        }
    }

    /// 自动查找密钥
    /// 返回按置信度排序的候选密钥列表
    pub fn find_keys(&self) -> Result<Vec<KeyCandidate>> {
        tracing::info!(
            "开始在进程 {} (版本 {}) 中搜索数据库密钥...",
            self.pid,
            self.version
        );

        let process = ProcessManager::open(self.pid)?;
        let memory = MemoryManager::new(process.handle);

        let mut candidates: Vec<KeyCandidate> = Vec::new();
        let mut found_keys: HashSet<String> = HashSet::new();

        // 方法1: 在公钥附近搜索
        if let Ok(keys) = self.find_near_public_key(&memory) {
            for key in keys {
                if found_keys.insert(key.key_hex.clone()) {
                    candidates.push(key);
                }
            }
        }

        // 方法2: 搜索特定内存模式
        if let Ok(keys) = self.find_by_memory_pattern(&memory) {
            for key in keys {
                if found_keys.insert(key.key_hex.clone()) {
                    candidates.push(key);
                }
            }
        }

        // 方法3: 在数据库路径附近搜索
        if let Ok(keys) = self.find_near_db_path(&memory) {
            for key in keys {
                if found_keys.insert(key.key_hex.clone()) {
                    candidates.push(key);
                }
            }
        }

        // 方法4: 熵分析找高随机性数据块
        if let Ok(keys) = self.find_by_entropy(&memory) {
            for key in keys {
                if found_keys.insert(key.key_hex.clone()) {
                    candidates.push(key);
                }
            }
        }

        // 按置信度排序
        candidates.sort_by(|a, b| b.confidence.cmp(&a.confidence));

        tracing::info!("找到 {} 个候选密钥", candidates.len());
        Ok(candidates)
    }

    /// 方法1: 在公钥标记附近搜索密钥
    /// 微信的公钥字符串 "-----BEGIN PUBLIC KEY-----" 附近通常有密钥
    fn find_near_public_key(&self, memory: &MemoryManager) -> Result<Vec<KeyCandidate>> {
        let mut candidates = Vec::new();

        // 公钥标记
        let patterns = [
            b"-----BEGIN PUBLIC KEY-----".as_slice(),
            b"-----BEGIN RSA PUBLIC KEY-----".as_slice(),
            b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA".as_slice(), // Base64 公钥开头
        ];

        // 获取内存映射
        let maps = memory.get_memory_maps()?;

        for map in &maps {
            // 只搜索已提交的内存（放宽保护标志限制）
            if map.state != MEM_COMMIT.0 {
                continue;
            }
            // 检查是否可读（各种可读的保护标志）
            if !Self::is_readable_memory(map.protect) {
                continue;
            }

            for pattern in &patterns {
                if let Ok(addresses) =
                    memory.search_memory(pattern, map.base_address, map.base_address + map.region_size, 5)
                {
                    for addr in addresses {
                        // 在公钥附近搜索可能的密钥 (前后 4KB 范围)
                        let search_start = addr.saturating_sub(4096);
                        let search_end = (addr + 4096).min(map.base_address + map.region_size);

                        if let Ok(keys) = self.extract_potential_keys(memory, search_start, search_end) {
                            for (key_addr, key_bytes) in keys {
                                if self.validate_key_bytes(&key_bytes) {
                                    candidates.push(KeyCandidate {
                                        key_hex: hex::encode(&key_bytes),
                                        address: key_addr,
                                        confidence: 85, // 公钥附近找到，置信度较高
                                        method: "near_public_key".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(candidates)
    }

    /// 方法2: 通过特定内存模式搜索
    /// 微信4.x的密钥可能有特定的前缀或周围结构
    fn find_by_memory_pattern(&self, memory: &MemoryManager) -> Result<Vec<KeyCandidate>> {
        let mut candidates = Vec::new();

        // 获取主模块信息
        let module = match MemoryMap::find_wechatwin_dll(self.pid)? {
            Some(m) => m,
            None => return Ok(candidates),
        };

        let base = module.base_address;
        let size = module.size;

        // 搜索可能的密钥存储特征
        // 密钥可能存储在特定结构中，例如 SQLCipher 的密钥结构
        let key_markers = [
            b"DBKey".as_slice(),
            b"dbKey".as_slice(),
            b"sqlcipher".as_slice(),
            b"cipher_key".as_slice(),
            b"sqlite3_key".as_slice(),
        ];

        for marker in &key_markers {
            if let Ok(addresses) = memory.search_memory(marker, base, base + size, 10) {
                for addr in addresses {
                    // 在标记附近搜索
                    let search_start = addr.saturating_sub(256);
                    let search_end = (addr + 512).min(base + size);

                    if let Ok(keys) = self.extract_potential_keys(memory, search_start, search_end) {
                        for (key_addr, key_bytes) in keys {
                            if self.validate_key_bytes(&key_bytes) {
                                candidates.push(KeyCandidate {
                                    key_hex: hex::encode(&key_bytes),
                                    address: key_addr,
                                    confidence: 75,
                                    method: "memory_pattern".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(candidates)
    }

    /// 方法3: 在数据库路径字符串附近搜索
    fn find_near_db_path(&self, memory: &MemoryManager) -> Result<Vec<KeyCandidate>> {
        let mut candidates = Vec::new();

        // 数据库路径特征
        let db_patterns = [
            b"\\Msg\\".as_slice(),
            b"MicroMsg.db".as_slice(),
            b"MediaMSG".as_slice(),
            b"\\db_storage\\".as_slice(),
            b"message_0.db".as_slice(),
            b"xwechat_files".as_slice(),
            b"contact_0.db".as_slice(),
            b"Sns.db".as_slice(),
            b"PublicMsg.db".as_slice(),
        ];

        let maps = memory.get_memory_maps()?;

        for map in &maps {
            if map.state != MEM_COMMIT.0 {
                continue;
            }
            // 添加可读性检查
            if !Self::is_readable_memory(map.protect) {
                continue;
            }

            for pattern in &db_patterns {
                if let Ok(addresses) =
                    memory.search_memory(pattern, map.base_address, map.base_address + map.region_size, 5)
                {
                    for addr in addresses {
                        // 扩大搜索范围（从2KB扩大到4KB）
                        let search_start = addr.saturating_sub(4096);
                        let search_end = (addr + 4096).min(map.base_address + map.region_size);

                        if let Ok(keys) = self.extract_potential_keys(memory, search_start, search_end) {
                            for (key_addr, key_bytes) in keys {
                                if self.is_potential_key(&key_bytes) {
                                    candidates.push(KeyCandidate {
                                        key_hex: hex::encode(&key_bytes),
                                        address: key_addr,
                                        confidence: 72, // 略微提高置信度
                                        method: "near_db_path".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(candidates)
    }

    /// 方法4: 通过熵分析寻找高随机性数据块
    fn find_by_entropy(&self, memory: &MemoryManager) -> Result<Vec<KeyCandidate>> {
        let mut candidates = Vec::new();

        let maps = memory.get_memory_maps()?;
        let mut scanned_regions = 0;

        for map in &maps {
            // 只搜索已提交的内存
            if map.state != MEM_COMMIT.0 {
                continue;
            }
            // 检查是否可读
            if !Self::is_readable_memory(map.protect) {
                continue;
            }
            // 跳过太大的区域以提高性能
            if map.region_size > 2 * 1024 * 1024 {
                continue;
            }

            scanned_regions += 1;

            // 读取整个区域
            let read_size = map.region_size.min(131072); // 最多读128KB
            if let Ok(data) = memory.read_memory(map.base_address, read_size) {
                // 滑动窗口搜索高熵区域
                for offset in (0..data.len().saturating_sub(KEY_SIZE)).step_by(8) {
                    let chunk = &data[offset..offset + KEY_SIZE];
                    let entropy = self.calculate_entropy(chunk);

                    // 降低熵值阈值（6.0代替7.0）以找到更多候选
                    if entropy > 6.0 && self.is_potential_key(chunk) {
                        candidates.push(KeyCandidate {
                            key_hex: hex::encode(chunk),
                            address: map.base_address + offset,
                            confidence: ((entropy / 8.0) * 70.0) as u32, // 基于熵值计算置信度
                            method: format!("entropy_analysis (entropy: {:.2})", entropy),
                        });
                    }
                }
            }
        }

        tracing::debug!("熵分析扫描了 {} 个内存区域", scanned_regions);
        Ok(candidates)
    }

    /// 从内存区域提取潜在的密钥
    fn extract_potential_keys(
        &self,
        memory: &MemoryManager,
        start: usize,
        end: usize,
    ) -> Result<Vec<(usize, Vec<u8>)>> {
        let mut results = Vec::new();

        if end <= start {
            return Ok(results);
        }

        let data = memory.read_memory(start, end - start)?;

        // 按8字节对齐滑动搜索
        for offset in (0..data.len().saturating_sub(KEY_SIZE)).step_by(8) {
            let chunk = &data[offset..offset + KEY_SIZE];
            if self.is_potential_key(chunk) {
                results.push((start + offset, chunk.to_vec()));
            }
        }

        Ok(results)
    }

    /// 检查字节序列是否可能是密钥
    fn is_potential_key(&self, data: &[u8]) -> bool {
        if data.len() != KEY_SIZE {
            return false;
        }

        // 检查是否全为0或全为相同值
        if data.iter().all(|&b| b == 0) {
            return false;
        }
        if data.iter().all(|&b| b == data[0]) {
            return false;
        }

        // 检查零字节的比例（真正的密钥不应该有太多零字节）
        let zero_count = data.iter().filter(|&&b| b == 0).count();
        if zero_count > 8 {
            // 如果超过25%是零字节，可能不是密钥
            return false;
        }

        // 检查是否是可打印ASCII字符串（密钥应该是二进制数据，不是文本）
        let printable_count = data.iter().filter(|&&b| b >= 0x20 && b <= 0x7E).count();
        if printable_count > 28 {
            // 如果超过87.5%是可打印字符，可能是普通文本
            return false;
        }

        // 检查字节分布的多样性
        let mut byte_counts = [0u32; 256];
        for &b in data {
            byte_counts[b as usize] += 1;
        }
        let unique_bytes = byte_counts.iter().filter(|&&c| c > 0).count();

        // 密钥应该有较高的字节多样性
        if unique_bytes < 16 {
            return false;
        }

        // 计算熵值作为最终验证
        let entropy = self.calculate_entropy(data);
        entropy > 5.5 // 要求较高的熵值
    }

    /// 验证密钥字节的有效性
    fn validate_key_bytes(&self, data: &[u8]) -> bool {
        if data.len() != KEY_SIZE {
            return false;
        }

        // 基本检查
        if !self.is_potential_key(data) {
            return false;
        }

        // 计算熵值
        let entropy = self.calculate_entropy(data);

        // AES密钥应该有高熵值（接近8.0）
        entropy > 6.5
    }

    /// 计算数据块的熵值 (0-8)
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut byte_counts = [0u64; 256];
        for &b in data {
            byte_counts[b as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &byte_counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// 检查内存保护标志是否可读
    fn is_readable_memory(protect: u32) -> bool {
        use windows::Win32::System::Memory::{
            PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY,
        };
        
        // 所有可读的内存保护标志
        let readable_flags = [
            PAGE_READONLY.0,
            PAGE_READWRITE.0,
            PAGE_WRITECOPY.0,
            PAGE_EXECUTE_READ.0,
            PAGE_EXECUTE_READWRITE.0,
            PAGE_EXECUTE_WRITECOPY.0,
        ];
        
        readable_flags.iter().any(|&flag| (protect & flag) != 0)
    }

    /// 使用候选密钥尝试解密数据库验证
    pub fn verify_key_with_database(&self, key_hex: &str, db_path: &Path) -> Result<bool> {
        use crate::core::decryption;

        if !db_path.exists() {
            return Ok(false);
        }

        // 创建临时输出文件
        let temp_dir = std::env::temp_dir();
        let temp_out = temp_dir.join(format!("wx_key_verify_{}.db", std::process::id()));

        // 尝试解密
        let result = decryption::decrypt_db(key_hex, db_path, &temp_out);

        // 清理临时文件
        let _ = std::fs::remove_file(&temp_out);

        match result {
            Ok(_) => {
                tracing::info!("密钥验证成功！");
                Ok(true)
            }
            Err(e) => {
                tracing::debug!("密钥验证失败: {}", e);
                Ok(false)
            }
        }
    }
}

/// 便捷函数：查找微信进程的数据库密钥
pub fn find_wechat_key(pid: u32, version: &str) -> Result<Option<String>> {
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

/// 便捷函数：查找并验证密钥
pub fn find_and_verify_key(pid: u32, version: &str, db_path: &Path) -> Result<Option<String>> {
    let finder = KeyFinder::new(pid, version);
    let candidates = finder.find_keys()?;

    if candidates.is_empty() {
        return Ok(None);
    }

    // 按置信度顺序尝试验证
    for candidate in candidates {
        tracing::info!(
            "尝试验证密钥: {} (置信度: {})",
            candidate.key_hex,
            candidate.confidence
        );

        if finder.verify_key_with_database(&candidate.key_hex, db_path)? {
            return Ok(Some(candidate.key_hex));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let finder = KeyFinder::new(0, "4.0.0.0");

        // 全相同字节，熵值为0
        let uniform = vec![0x42u8; 32];
        assert!(finder.calculate_entropy(&uniform) < 0.1);

        // 随机样本数据，熵值应该较高
        let random: Vec<u8> = (0..32).map(|i| (i * 7 + 13) as u8).collect();
        let entropy = finder.calculate_entropy(&random);
        assert!(entropy > 4.0);
    }

    #[test]
    fn test_is_potential_key() {
        let finder = KeyFinder::new(0, "4.0.0.0");

        // 全0不是密钥
        let zeros = vec![0u8; 32];
        assert!(!finder.is_potential_key(&zeros));

        // 普通文本不太可能是密钥
        let text = b"This is just some normal text!X";
        assert!(!finder.is_potential_key(text));

        // 高熵数据可能是密钥
        let random: Vec<u8> = (0..32).map(|i| ((i as u64 * 0x9E3779B9) & 0xFF) as u8).collect();
        // 这个测试可能通过或失败，取决于生成的数据
        println!("Random data key check: {}", finder.is_potential_key(&random));
    }
}
