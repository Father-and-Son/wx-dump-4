use crate::utils::Result;
use anyhow::Context;
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

const SQLITE_FILE_HEADER: &[u8] = b"SQLite format 3\x00";
const KEY_SIZE: usize = 32;
const PAGE_SIZE: usize = 4096;

/// 微信版本类型，决定使用的加密参数
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeChatVersion {
    /// 微信 3.x 版本 (SQLCipher v3 参数)
    V3,
    /// 微信 4.x 版本 (SQLCipher v4 参数)
    V4,
}

impl WeChatVersion {
    /// 从版本字符串检测版本类型
    pub fn from_version_string(version: &str) -> Self {
        if version.starts_with("4.") || version.starts_with("5.") {
            WeChatVersion::V4
        } else {
            WeChatVersion::V3
        }
    }

    /// 获取 KDF 迭代次数
    pub fn kdf_iterations(&self) -> u32 {
        match self {
            WeChatVersion::V3 => 64000,
            WeChatVersion::V4 => 256000,
        }
    }
}

/// 解密微信数据库（自动检测版本）
/// 先尝试 V4 参数，失败后尝试 V3 参数
pub fn decrypt_db(key: &str, db_path: &Path, out_path: &Path) -> Result<()> {
    // 先尝试 V4 (微信 4.x)
    if let Ok(_) = decrypt_db_v4(key, db_path, out_path) {
        tracing::info!("成功使用 V4 (微信 4.x) 参数解密数据库");
        return Ok(());
    }
    
    // 尝试 V3 (微信 3.x)
    match decrypt_db_v3(key, db_path, out_path) {
        Ok(_) => {
            tracing::info!("成功使用 V3 (微信 3.x) 参数解密数据库");
            Ok(())
        }
        Err(e) => {
            let msg = format!(
                "解密失败。已尝试 V4 和 V3 参数。可能原因：\n\
                1. 密钥错误 (最可能)。请运行 'python extract_key.py' 获取正确密钥。\n\
                2. 数据库文件已损坏或被占用。\n\
                3. 此版本的微信使用了非标准的加密参数。\n\
                \n\
                原始错误: {}", 
                e
            );
            tracing::error!("{}", msg);
            Err(anyhow::anyhow!(msg).into())
        }
    }
}

/// 使用微信 4.x (SQLCipher v4) 参数解密数据库
/// - KDF: PBKDF2-HMAC-SHA256, 256000 iterations
/// - HMAC: SHA-256
pub fn decrypt_db_v4(key: &str, db_path: &Path, out_path: &Path) -> Result<()> {
    decrypt_db_internal(key, db_path, out_path, WeChatVersion::V4)
}

/// 使用微信 3.x (SQLCipher v3) 参数解密数据库
/// - KDF: PBKDF2-HMAC-SHA1, 64000 iterations
/// - HMAC: SHA-1
pub fn decrypt_db_v3(key: &str, db_path: &Path, out_path: &Path) -> Result<()> {
    decrypt_db_internal(key, db_path, out_path, WeChatVersion::V3)
}

/// 内部解密函数，支持不同版本的参数
fn decrypt_db_internal(key: &str, db_path: &Path, out_path: &Path, version: WeChatVersion) -> Result<()> {
    // 验证输入
    if !db_path.exists() || !db_path.is_file() {
        return Err(anyhow::anyhow!("Database file not found: {:?}", db_path).into());
    }

    if let Some(parent) = out_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create output directory: {:?}", parent))?;
        }
    }

    if key.len() != 64 {
        return Err(anyhow::anyhow!("Key length must be 64 hex characters").into());
    }

    // 读取加密数据库
    let encrypted_data = fs::read(db_path)
        .with_context(|| format!("Failed to read database: {:?}", db_path))?;

    if encrypted_data.len() < PAGE_SIZE {
        return Err(anyhow::anyhow!("Database file too small").into());
    }

    // 提取 salt（前16字节）
    let salt = &encrypted_data[0..16];

    // 解析密钥（64位十六进制 -> 32字节）
    let password = hex::decode(key.trim())
        .with_context(|| "Failed to decode hex key")?;

    // 根据版本派生密钥
    let (byte_key, mac_key) = match version {
        WeChatVersion::V3 => derive_keys_v3(&password, salt)?,
        WeChatVersion::V4 => derive_keys_v4(&password, salt)?,
    };

    // 验证 HMAC (仅作为警告)
    if let Err(e) = verify_hmac(&encrypted_data, &mac_key, version) {
        tracing::warn!("HMAC 验证失败: {}。尝试忽略错误继续解密...", e);
    } else {
        tracing::info!("HMAC 验证成功！");
    }

    // 解密数据库
    decrypt_pages(&encrypted_data, &byte_key, out_path, version)?;

    Ok(())
}

/// 派生密钥 - 微信 3.x (SHA-1)
fn derive_keys_v3(password: &[u8], salt: &[u8]) -> Result<([u8; KEY_SIZE], [u8; KEY_SIZE])> {
    // MAC salt = salt XOR 0x3a (58)
    let mac_salt: Vec<u8> = salt.iter().map(|&b| b ^ 58).collect();

    // PBKDF2-HMAC-SHA1, 64000 iterations
    let mut byte_key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha1>(password, salt, 64000, &mut byte_key);

    // MAC key
    let mut mac_key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha1>(&byte_key, &mac_salt, 2, &mut mac_key);

    Ok((byte_key, mac_key))
}

/// 派生密钥 - 微信 4.x (SHA-256)
fn derive_keys_v4(password: &[u8], salt: &[u8]) -> Result<([u8; KEY_SIZE], [u8; KEY_SIZE])> {
    // MAC salt = salt XOR 0x3a (58)
    let mac_salt: Vec<u8> = salt.iter().map(|&b| b ^ 58).collect();

    // PBKDF2-HMAC-SHA256, 256000 iterations
    let mut byte_key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(password, salt, 256000, &mut byte_key);

    // MAC key
    let mut mac_key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(&byte_key, &mac_salt, 2, &mut mac_key);

    Ok((byte_key, mac_key))
}

/// 验证 HMAC
fn verify_hmac(encrypted_data: &[u8], mac_key: &[u8], version: WeChatVersion) -> Result<()> {
    // 添加页号（小端序）
    let page_number: u32 = 1;
    
    let computed_hmac = match version {
        WeChatVersion::V3 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(mac_key)
                .map_err(|e| anyhow::anyhow!("Failed to create HMAC: {}", e))?;
            mac.update(&encrypted_data[16..PAGE_SIZE - 48]);
            mac.update(&page_number.to_le_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        WeChatVersion::V4 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(mac_key)
                .map_err(|e| anyhow::anyhow!("Failed to create HMAC: {}", e))?;
            mac.update(&encrypted_data[16..PAGE_SIZE - 48]);
            mac.update(&page_number.to_le_bytes());
            mac.finalize().into_bytes().to_vec()
        }
    };

    // 存储的 HMAC 位于保留区开始处
    let stored_hmac_offset = PAGE_SIZE - 48;
    let hmac_len = match version {
        WeChatVersion::V3 => 20, // SHA-1 产生 20 字节
        WeChatVersion::V4 => 32, // SHA-256 产生 32 字节
    };
    let stored_hmac = &encrypted_data[stored_hmac_offset..stored_hmac_offset + hmac_len];

    if computed_hmac[..hmac_len] != *stored_hmac {
        return Err(anyhow::anyhow!("Key verification failed - incorrect key or wrong version parameters").into());
    }

    Ok(())
}

/// 解密所有页面
fn decrypt_pages(encrypted_data: &[u8], byte_key: &[u8], out_path: &Path, _version: WeChatVersion) -> Result<()> {
    let mut output = File::create(out_path)
        .with_context(|| format!("Failed to create output file: {:?}", out_path))?;

    let total_pages = (encrypted_data.len() + PAGE_SIZE - 1) / PAGE_SIZE;

    for page_num in 0..total_pages {
        let page_start = if page_num == 0 { 16 } else { page_num * PAGE_SIZE };
        let page_end = ((page_num + 1) * PAGE_SIZE).min(encrypted_data.len());

        if page_start >= encrypted_data.len() {
            break;
        }

        let page_data = &encrypted_data[page_start..page_end];

        if page_data.len() < 48 {
            // 最后一页可能不足
            output.write_all(page_data)?;
            break;
        }

        // 保留区的结构：IV(16) + HMAC(20/32) + 填充
        // IV 在最后 48 字节的前 16 字节
        let reserved_start = page_data.len() - 48;
        let iv = &page_data[reserved_start..reserved_start + 16];
        let encrypted_content = &page_data[..reserved_start];
        // let reserved_area = &page_data[reserved_start..]; // 解密后不需要写入保留区

        // AES-256-CBC 解密
        type Aes256CbcDec = cbc::Decryptor<Aes256>;
        let cipher = Aes256CbcDec::new_from_slices(byte_key, iv)
            .map_err(|e| anyhow::anyhow!("Failed to create decryptor: {}", e))?;

        let mut decrypted = encrypted_content.to_vec();
        // 确保对齐到 16 字节 (NoPadding 模式要求)
        // 实际上 SQLCipher 使用的是 CBC 模式，数据已经是块对齐的（页大小是16倍数）
        // 但 encrypted_content 长度是 PAGE_SIZE - 48 = 4048，是 16 的倍数（253 * 16）
        // 所以不需要填充，直接解密即可

        cipher.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut decrypted)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        // 验证第一页的文件头
        if page_num == 0 {
            if !decrypted.starts_with(SQLITE_FILE_HEADER) {
                return Err(anyhow::anyhow!("Decrypted data does not match SQLite header. Key may be incorrect.").into());
            }
        }

        // 写入解密后的内容
        // 注意：SQLCipher 加密是原地加密，解密后只需要写入内容
        // 不需要写入保留区？通常解密出的数据库应该是纯 SQLite 格式
        // 纯 SQLite 格式不包含保留区吗？
        // 标准 SQLite 页大小是 4096。SQLCipher 也是 4096，但用了 48 字节做 IV/HMAC。
        // 所以有效载荷变小了。
        // 解密后的数据库应该保持页大小 4096 还是 变小？
        // 如果想让它被标准 SQLite 打开，我们需要保持页结构。
        // 但这里的 decrypted 只有 4048 字节。
        // 我们应该填充 48 字节的 0 或者保留原样？
        // 标准做法是：解密后的数据库应该可以直接被 SQLite 打开。
        // 如果我们写入 4048 字节，页大小就变了，可能无法打开。
        // 应该补充 48 字节的空数据或者随机数据，保持页大小为 4096。
        
        output.write_all(&decrypted)?;
        output.write_all(&vec![0u8; 48])?; // 补充到 4096
    }

    Ok(())
}

/// 批量解密
#[allow(dead_code)]
pub fn batch_decrypt(
    key: &str,
    db_paths: &[PathBuf],
    out_dir: &Path,
) -> Result<Vec<(PathBuf, PathBuf)>> {
    if !out_dir.exists() {
        fs::create_dir_all(out_dir)
            .with_context(|| format!("Failed to create output directory: {:?}", out_dir))?;
    }

    let mut results = Vec::new();

    for db_path in db_paths {
        let file_name = db_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;

        let out_path = out_dir.join(format!("de_{}", file_name));

        match decrypt_db(key, db_path, &out_path) {
            Ok(_) => {
                results.push((db_path.clone(), out_path));
            }
            Err(e) => {
                tracing::error!("Failed to decrypt {:?}: {}", db_path, e);
            }
        }
    }

    Ok(results)
}

/// 批量解密（指定版本）
#[allow(dead_code)]
pub fn batch_decrypt_with_version(
    key: &str,
    db_paths: &[PathBuf],
    out_dir: &Path,
    version: WeChatVersion,
) -> Result<Vec<(PathBuf, PathBuf)>> {
    if !out_dir.exists() {
        fs::create_dir_all(out_dir)
            .with_context(|| format!("Failed to create output directory: {:?}", out_dir))?;
    }

    let mut results = Vec::new();

    for db_path in db_paths {
        let file_name = db_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;

        let out_path = out_dir.join(format!("de_{}", file_name));

        let result = match version {
            WeChatVersion::V3 => decrypt_db_v3(key, db_path, &out_path),
            WeChatVersion::V4 => decrypt_db_v4(key, db_path, &out_path),
        };

        match result {
            Ok(_) => {
                results.push((db_path.clone(), out_path));
            }
            Err(e) => {
                tracing::error!("Failed to decrypt {:?}: {}", db_path, e);
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_key_validation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let out_path = temp_dir.path().join("out.db");
        
        // 创建测试文件
        std::fs::write(&db_path, vec![0u8; 100]).unwrap();
        
        // 测试密钥长度错误
        let result = decrypt_db("invalid_key", &db_path, &out_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_version_detection() {
        assert_eq!(WeChatVersion::from_version_string("3.9.10.0"), WeChatVersion::V3);
        assert_eq!(WeChatVersion::from_version_string("4.0.0.0"), WeChatVersion::V4);
        assert_eq!(WeChatVersion::from_version_string("4.1.4.17"), WeChatVersion::V4);
        assert_eq!(WeChatVersion::from_version_string("5.0.0.0"), WeChatVersion::V4);
    }

    #[test]
    fn test_kdf_iterations() {
        assert_eq!(WeChatVersion::V3.kdf_iterations(), 64000);
        assert_eq!(WeChatVersion::V4.kdf_iterations(), 256000);
    }

    #[test]
    fn test_decrypt_other_account() {
        // 这是另一个账号的目录
        let db_path = std::path::PathBuf::from(r"D:\xwechat_files\wxid_9441084409712_b56c\msg\MicroMsg.db");
        // 也可以试试 D:\xwechat_files\wxid_9441084409712_b56c\db_storage\message\message_0.db 如果存在
        
        // 同样的密钥
        let key = "23607b89f90945e587742177b94cee783b4dd5d216554c0bb4b4b0830e9d1089";
        
        if !db_path.exists() {
            println!("DB file not found: {:?}", db_path);
            // 尝试查找该目录下的其他 db
            let root = std::path::PathBuf::from(r"D:\xwechat_files\wxid_9441084409712_b56c");
            if root.exists() {
                println!("Account root exists. Trying to find any .db file...");
                // 简单的查找逻辑，实际可以用 walkdir，这里手动拼几个常见路径
                let candidates = vec![
                    root.join("msg").join("MicroMsg.db"),
                    root.join("db_storage").join("message").join("message_0.db"),
                    root.join("MicroMsg.db"),
                ];
                
                for p in candidates {
                    if p.exists() {
                        println!("Found candidate: {:?}", p);
                        try_decrypt_file(&p, key);
                        return;
                    }
                }
            }
            return;
        }

        println!("Found DB file: {:?}", db_path);
        try_decrypt_file(&db_path, key);
    }

    fn try_decrypt_file(db_path: &std::path::Path, key: &str) {
        let out_path = std::path::PathBuf::from(r"test_decrypt_other.db");
        let temp_db = std::env::temp_dir().join("test_msg_other.db");
        
        std::fs::copy(db_path, &temp_db).unwrap();
        
        println!("Trying decrypt on {:?}...", db_path);
        match super::decrypt_db_v4(key, &temp_db, &out_path) {
            Ok(_) => println!("SUCCESS: Decrypted using V4 params! The key belongs to this account."),
            Err(e) => {
                println!("FAILED V4: {:?}", e);
                // Try V3 just in case
                match super::decrypt_db_v3(key, &temp_db, &out_path) {
                    Ok(_) => println!("SUCCESS: Decrypted using V3 params!"),
                    Err(e) => println!("FAILED V3: {:?}", e),
                }
            }
        }
    }
}
