//! 微信密钥验证工具
//!
//! 用候选密钥尝试解密微信数据库，验证密钥是否正确。
//!
//! 使用方法:
//! cargo run --bin wx_key_verifier -- <db_path> <key_hex>

use std::env;
use std::fs;
use std::path::Path;

use wx_dump_4_backend::core::decryption;

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║              微信密钥验证工具 v1.0                             ║");
    println!("║  验证候选密钥是否能正确解密数据库                              ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    let args: Vec<String> = env::args().collect();
    
    if args.len() < 3 {
        println!("用法: {} <db_path> <key_hex>", args[0]);
        println!();
        println!("参数:");
        println!("  db_path   - 加密的数据库文件路径");
        println!("  key_hex   - 64字符的十六进制密钥");
        println!();
        println!("示例:");
        println!("  {} \"C:\\path\\to\\message_0.db\" \"abcd1234...\"", args[0]);
        return;
    }

    let db_path = Path::new(&args[1]);
    let key_hex = &args[2];

    // 验证密钥格式
    if key_hex.len() != 64 {
        println!("❌ 密钥长度错误！应为64个十六进制字符（32字节）");
        println!("   当前长度: {} 字符", key_hex.len());
        return;
    }

    if hex::decode(key_hex).is_err() {
        println!("❌ 密钥格式错误，不是有效的十六进制字符串");
        return;
    }

    // 检查数据库文件
    if !db_path.exists() {
        println!("❌ 数据库文件不存在: {:?}", db_path);
        return;
    }

    println!("数据库文件: {:?}", db_path);
    println!("密钥: {}...{}", &key_hex[..16], &key_hex[48..]);
    println!();

    // 创建临时输出文件
    let temp_dir = std::env::temp_dir();
    let temp_out = temp_dir.join(format!("wx_verify_test_{}.db", std::process::id()));

    println!("尝试解密中...");
    
    // 尝试解密
    match decryption::decrypt_db(key_hex, db_path, &temp_out) {
        Ok(_) => {
            // 清理临时文件
            let _ = fs::remove_file(&temp_out);
            
            println!();
            println!("═══════════════════════════════════════════════════════════════");
            println!("✅ 密钥验证成功！");
            println!("═══════════════════════════════════════════════════════════════");
            println!();
            println!("密钥: {}", key_hex);
            println!();
            println!("您现在可以使用此密钥解密数据库。");
        }
        Err(e) => {
            // 清理临时文件
            let _ = fs::remove_file(&temp_out);
            
            println!();
            println!("❌ 密钥验证失败: {}", e);
            println!("   这个密钥无法解密此数据库");
        }
    }
}
