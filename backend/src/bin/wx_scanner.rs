use std::path::PathBuf;
use std::mem::size_of;
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_READWRITE, PAGE_READONLY, PAGE_EXECUTE_READWRITE
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use aes::cipher::{BlockDecrypt, KeyInit, Key};
use aes::Aes256;

// 目标文件头
const SQLITE_HEADER: &[u8] = b"SQLite format 3\0";

fn main() {
    println!("=== 微信密钥内存暴力扫描器 (Rust/Win32版) ===");
    println!("原理：跳过 KDF，直接暴力搜索内存中能解密数据库的 Raw AES Key");

    // 1. 准备验证数据
    let db_path = PathBuf::from(r"D:\xwechat_files\wxid_4fmddgv0yhee22_cd66\msg\MicroMsg.db"); 
    
    if !db_path.exists() {
        println!("错误: 找不到数据库文件 {:?}", db_path);
        return;
    }

    println!("正在读取数据库文件头: {:?}", db_path);
    let file_data = match std::fs::read(&db_path) {
        Ok(data) => data,
        Err(e) => {
            println!("无法读取文件: {}", e);
            return;
        }
    };

    if file_data.len() < 4096 {
        println!("错误: 文件大小不足 4096 字节");
        return;
    }

    let c1_slice = &file_data[16..32];
    let mut c1_block = aes::Block::default();
    c1_block.copy_from_slice(c1_slice);

    // IV1: Offset 4096 - 48 (Reserve Start)
    let iv1_slice = &file_data[4048..4064];
    // IV2: Offset 4096 - 16 (Reserve End)
    let iv2_slice = &file_data[4080..4096];
    
    println!("验证数据准备: C1={:?}", c1_slice);
    println!("尝试 IV1: {:?}", iv1_slice);
    println!("尝试 IV2: {:?}", iv2_slice);

    // 2. 查找微信进程
    let pid = find_wx_pid().expect("未找到 Weixin.exe 或 WeChat.exe，请先登录微信！");
    println!("微信 PID: {}", pid);

    // 3. 打开进程
    let process_handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)
    };

    if process_handle.is_err() {
        println!("错误: 无法打开进程。请以管理员身份运行！");
        return;
    }
    let process_handle = process_handle.unwrap();

    let mut found_key = None;
    let mut address = 0usize;
    let mut mem_info = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
    let mut scanned_bytes = 0usize;
    let mut attempts: u64 = 0;

    let patterns = vec![
        ("MicroMsg.db", "MicroMsg.db".as_bytes().to_vec()),
        ("message_0.db", "message_0.db".as_bytes().to_vec()),
        // UTF-16LE
        ("MicroMsg.db (Wide)", "MicroMsg.db".encode_utf16().flat_map(|u| u.to_le_bytes()).collect()),
    ];

    println!("开始智能上下文扫描 (Context-Aware Scanning)...");
    println!("正在搜索数据库路径字符串，并在附近寻找 Key...");

    loop {
        let result = unsafe {
            VirtualQueryEx(
                process_handle,
                Some(address as *const c_void),
                &mut mem_info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        let is_target_mem = mem_info.State == MEM_COMMIT && 
            ((mem_info.Protect & PAGE_READWRITE) != windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0) || 
             (mem_info.Protect & PAGE_EXECUTE_READWRITE) != windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0));

        if is_target_mem {
            let region_size = mem_info.RegionSize;
            let mut buffer = vec![0u8; region_size];
            let mut bytes_read = 0;

            let success = unsafe {
                ReadProcessMemory(
                    process_handle,
                    mem_info.BaseAddress,
                    buffer.as_mut_ptr() as *mut c_void,
                    region_size,
                    Some(&mut bytes_read),
                )
            };

            if success.is_ok() && bytes_read > 0 {
                // 1. Search for patterns
                for (pat_name, pat_bytes) in &patterns {
                     // Simple byte search
                     for i in 0..bytes_read.saturating_sub(pat_bytes.len()) {
                         if &buffer[i..i+pat_bytes.len()] == pat_bytes.as_slice() {
                             // Pattern Found!
                             // println!("找到路径特征: {} @ Offset {}", pat_name, i);
                             
                             // 2. Context Scan: [i - 1024, i + 1024]
                             let start_scan = i.saturating_sub(1024);
                             let end_scan = (i + 1024).min(bytes_read.saturating_sub(32));
                             
                             for j in (start_scan..end_scan).step_by(4) { // Step 4
                                attempts += 1;
                                let key_candidate = &buffer[j..j+32];
                                if key_candidate[0] == 0 && key_candidate[1] == 0 { continue; }

                                let key = Key::<Aes256>::from_slice(key_candidate);
                                let cipher = Aes256::new(key);

                                // Try IV 1
                                let mut block = c1_block.clone();
                                cipher.decrypt_block(&mut block);
                                for k in 0..16 { block[k] ^= iv1_slice[k]; }
                                if block.starts_with(SQLITE_HEADER) {
                                    found_key = Some(key_candidate.to_vec());
                                    println!("*** 在 {} 附近找到 Key! IV1 模式 ***", pat_name);
                                    break;
                                }

                                // Try IV 2
                                let mut block2 = c1_block.clone();
                                cipher.decrypt_block(&mut block2);
                                for k in 0..16 { block2[k] ^= iv2_slice[k]; }
                                if block2.starts_with(SQLITE_HEADER) {
                                    found_key = Some(key_candidate.to_vec());
                                    println!("*** 在 {} 附近找到 Key! IV2 模式 ***", pat_name);
                                    break;
                                }
                             }
                         }
                         if found_key.is_some() { break; }
                     }
                     if found_key.is_some() { break; }
                }
            }
            if found_key.is_some() { break; }
            
            scanned_bytes += region_size;
            if scanned_bytes % (500 * 1024 * 1024) < region_size {
                 println!("已扫描 {:.2} GB...", scanned_bytes as f64 / 1024.0 / 1024.0 / 1024.0);
            }
        }
        address += mem_info.RegionSize;
    }

    unsafe { CloseHandle(process_handle) };

    if let Some(key) = found_key {
        println!("\n\n===========================================");
        println!("🎉 通过暴力破解找到 AES 密钥！");
        println!("Key (Hex 64): {}", hex::encode(&key));
        println!("这是否就是我们要找的 Raw AES Key?");
        println!("请复制上面的 Hex 字符串去尝试解密！");
        println!("===========================================\n");
    } else {
        println!("扫描结束，未找到密钥。");
    }
}

fn find_wx_pid() -> Option<u32> {
    unsafe {
        // CreateToolhelp32Snapshot return Result<HANDLE> in windows crate 0.52+ (usually)
        // But checking docs, it actually returns Result<HANDLE>.
        let snapshot_result = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if let Ok(snapshot) = snapshot_result {
            let mut entry = std::mem::zeroed::<PROCESSENTRY32>();
            entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

            if Process32First(snapshot, &mut entry).is_ok() {
                loop {
                    // string from entry.szExeFile
                    let name = String::from_utf8_lossy(
                        &entry.szExeFile.iter()
                            .take_while(|&&c| c != 0)
                            .map(|&c| c as u8)
                            .collect::<Vec<u8>>()
                    ).to_string();
                    
                    if name.eq_ignore_ascii_case("Weixin.exe") || name.eq_ignore_ascii_case("WeChat.exe") {
                        let _ = CloseHandle(snapshot);
                        return Some(entry.th32ProcessID);
                    }

                    if Process32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
    }
    None
}
