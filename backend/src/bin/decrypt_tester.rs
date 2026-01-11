use std::path::PathBuf;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use hex::FromHex;

const DB_PATH: &str = r"D:\xwechat_files\wxid_4fmddgv0yhee22_cd66\msg\MicroMsg.db";
// 您的密钥
const KEY_HEX: &str = "23607b89f90945e587742177b94cee783b4dd5d216554c0bb4b4b0830e9d1089";

fn main() {
    println!("=== 微信数据库解密参数爆破工具 ===");
    println!("使用密钥: {}", KEY_HEX);
    println!("目标文件: {}\n", DB_PATH);

    let key_bytes = match Vec::from_hex(KEY_HEX) {
        Ok(k) => k,
        Err(e) => {
            println!("密钥 Hex 格式错误: {}", e);
            return;
        }
    };

    let mut file = match File::open(DB_PATH) {
        Ok(f) => f,
        Err(e) => {
            println!("无法打开文件: {}", e);
            return;
        }
    };

    let mut buf = vec![0u8; 4096];
    if file.read_exact(&mut buf).is_err() {
        println!("无法读取文件头");
        return;
    }

    let salt = &buf[0..16];
    let expected_header = b"SQLite format 3";

    println!("Salt (Hex): {}", hex::encode(salt));

    // 定义参数空间
    let page_sizes = [1024, 4096];
    let kdf_iters = [4000, 64000, 128000, 256000];
    let hmac_algos = ["SHA1", "SHA256", "SHA512"];
    let kdf_algos = ["SHA1", "SHA256", "SHA512"];
    let iv_offsets = ["Reserve-Start", "Reserve-End"];

    // 1. 尝试作为 RAW KEY (直接使用，跳过 KDF)
    println!("\n--- 尝试模式 1: RAW KEY (跳过 KDF) ---");
    try_decrypt(&buf, &key_bytes, "RAW", 0, "NONE", "NONE", &page_sizes, &iv_offsets);
    
    // 2. 尝试作为 PASSWORD (使用 KDF)
    println!("\n--- 尝试模式 2: PASSWORD (使用 KDF) ---");
    for &ps in &page_sizes {
        for &iter in &kdf_iters {
            for &kdf_algo in &kdf_algos {
                // Generate Key
                let mut derived_key = [0u8; 32];
                match kdf_algo {
                    "SHA1" => pbkdf2_hmac::<Sha1>(&key_bytes, salt, iter, &mut derived_key),
                    "SHA256" => pbkdf2_hmac::<Sha256>(&key_bytes, salt, iter, &mut derived_key),
                    "SHA512" => {
                        let mut temp = [0u8; 64]; // SHA512 produces 64 bytes
                        pbkdf2_hmac::<Sha512>(&key_bytes, salt, iter, &mut temp);
                        derived_key.copy_from_slice(&temp[0..32]);
                    },
                    _ => {}
                }
                
                try_decrypt(&buf, &derived_key.to_vec(), "PASSWORD", iter, kdf_algo, "See_Logic", &[ps], &iv_offsets);
            }
        }
    }
}

fn try_decrypt(
    page_buf: &[u8], 
    key: &[u8], 
    mode: &str, 
    iter: u32, 
    kdf_algo: &str, 
    _hmac_algo: &str, 
    page_sizes: &[usize],
    iv_locs: &[&str]
) {
    // Aes Key is ready.
    // In SQLCipher, the first block (after salt) is encrypted.
    // Layout: [Salt 16] [C1 16] ... [Reserve 48/64]
    
    // C1 is always at offset 16 (if Salt is 16).
    let c1_slice = &page_buf[16..32];
    
    let aes_key = aes::cipher::Key::<Aes256>::from_slice(key);
    let cipher = Aes256::new(aes_key);
    
    // Decrypt C1
    let mut block = aes::Block::default();
    block.copy_from_slice(c1_slice);
    cipher.decrypt_block(&mut block);
    
    // The result Block = P1 XOR IV.
    // We need to XOR with IV to see if P1 is "SQLite format 3".
    
    for &ps in page_sizes {
        // Find IV
        // Reserve usually 48.
        let reserve_sz = 48;
        
        // IV locations relative to page end
        let iv_candidates = vec![
            (ps - reserve_sz, "Reserve-Start"), 
            (ps - 16, "Reserve-End"),
            (ps - reserve_sz + 32, "Reserve-Start+32"), // HMAC(32)+IV(16)
            (ps - reserve_sz, "Reserve-IV-HMAC") // IV(16)+HMAC(32)
        ];

        for (iv_offset, loc_name) in iv_candidates {
            if iv_offset + 16 > page_buf.len() { continue; }
            if iv_offset < 32 { continue; }
            
            let iv = &page_buf[iv_offset..iv_offset+16];
            
            let mut p1 = block.clone();
            // XOR
            for i in 0..16 {
                p1[i] ^= iv[i];
            }
            
            if p1.starts_with(b"SQLite format 3") {
                println!("\n!!!! 找到可能的配置 !!!!");
                println!("Key Mode: {}", mode);
                println!("Page Size: {}", ps);
                println!("KDF Iter: {}", iter);
                println!("KDF Algo: {}", kdf_algo);
                println!("IV Location: Offset {} ({})", iv_offset, loc_name);
                println!("Header: {:?}", String::from_utf8_lossy(&p1));
                println!("!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            }
        }
    }
}
