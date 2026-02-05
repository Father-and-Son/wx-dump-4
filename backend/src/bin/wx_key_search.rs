//! 微信高熵密钥搜索工具 v2.0
//!
//! 专门搜索高熵值（接近真正AES密钥特征）的数据块

use std::io::{self, Write};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_READONLY, 
    PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::ProcessStatus::{
    K32EnumProcesses, K32GetModuleBaseNameW, K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// 候选密钥
#[derive(Clone)]
struct KeyCandidate {
    key_hex: String,
    address: usize,
    entropy: f64,
}

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║         微信高熵密钥搜索工具 v2.0                              ║");
    println!("║  搜索整个进程内存，寻找高熵值密钥候选                          ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    // 查找微信进程
    let pids = find_wechat_processes();
    if pids.is_empty() {
        println!("❌ 未找到运行中的微信进程！");
        return;
    }

    println!("✓ 找到 {} 个微信进程:", pids.len());
    for (i, (pid, mem_size)) in pids.iter().enumerate() {
        println!("   [{}] PID: {} (内存: {} MB)", i + 1, pid, mem_size / 1024 / 1024);
    }

    let main_pid = pids[0].0;
    println!();
    println!("→ 选择主进程 PID: {}", main_pid);
    println!();

    // 开始搜索
    match search_high_entropy_keys(main_pid) {
        Ok(keys) => {
            println!();
            println!("════════════════════════════════════════════════════════════════");
            println!("搜索完成！找到 {} 个高熵值候选密钥", keys.len());
            println!("════════════════════════════════════════════════════════════════");
            println!();
            
            for (i, key) in keys.iter().enumerate() {
                println!("[{}] 熵值: {:.3}, 地址: 0x{:x}", i + 1, key.entropy, key.address);
                println!("    密钥: {}", key.key_hex);
                println!();
            }
            
            if keys.is_empty() {
                println!("未找到高熵值密钥。建议:");
                println!("  1. 确保微信已登录并打开过聊天");
                println!("  2. 尝试在微信中切换聊天后重新运行");
                println!("  3. 使用 wx_key.exe 等外部工具获取密钥");
            } else {
                println!("请使用 wx_key_verifier 工具验证这些密钥:");
                println!("  cargo run --bin wx_key_verifier -- <db_path> <key_hex>");
            }
        }
        Err(e) => {
            println!("❌ 搜索出错: {}", e);
        }
    }
}

fn find_wechat_processes() -> Vec<(u32, usize)> {
    let mut pids = [0u32; 4096];
    let mut bytes_returned = 0u32;

    unsafe {
        let result = K32EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * std::mem::size_of::<u32>()) as u32,
            &mut bytes_returned,
        );
        if !result.as_bool() {
            return vec![];
        }
    }

    let count = bytes_returned as usize / std::mem::size_of::<u32>();
    let mut results = Vec::new();

    for &pid in &pids[..count] {
        if pid == 0 {
            continue;
        }

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                let mut name_buf = [0u16; 260];
                let len = K32GetModuleBaseNameW(handle, None, &mut name_buf);

                if len > 0 {
                    let name = String::from_utf16_lossy(&name_buf[..len as usize]);
                    if name.to_lowercase().contains("weixin") || name.to_lowercase().contains("wechat") {
                        let mut mem_info = PROCESS_MEMORY_COUNTERS::default();
                        mem_info.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;

                        let mem_result = K32GetProcessMemoryInfo(
                            handle,
                            &mut mem_info,
                            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
                        );
                        if mem_result.as_bool() {
                            results.push((pid, mem_info.WorkingSetSize));
                        }
                    }
                }
                let _ = CloseHandle(handle);
            }
        }
    }

    results.sort_by(|a, b| b.1.cmp(&a.1));
    results
}

fn search_high_entropy_keys(pid: u32) -> Result<Vec<KeyCandidate>, Box<dyn std::error::Error>> {
    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?
    };

    println!("开始扫描进程内存...");
    println!("这可能需要几分钟，请耐心等待...");
    println!();

    let mut candidates: Vec<KeyCandidate> = Vec::new();
    let mut addr: usize = 0;
    let mut regions_scanned = 0usize;
    let mut bytes_scanned = 0usize;
    let start_time = Instant::now();
    let mut last_report = Instant::now();

    // 遍历所有内存区域
    loop {
        let mut mem_info = MEMORY_BASIC_INFORMATION::default();
        let result = unsafe {
            VirtualQueryEx(
                handle,
                Some(addr as *const _),
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        let base = mem_info.BaseAddress as usize;
        let size = mem_info.RegionSize;
        let next_addr = base.saturating_add(size);

        // 只扫描已提交的可读内存
        if mem_info.State == MEM_COMMIT && is_readable(mem_info.Protect.0) {
            // 限制单次读取大小
            let max_read = 2 * 1024 * 1024; // 2MB
            let read_size = size.min(max_read);

            if let Some(data) = read_memory(handle, base, read_size) {
                bytes_scanned += data.len();
                
                // 滑动窗口搜索32字节高熵数据
                for offset in (0..data.len().saturating_sub(32)).step_by(16) {
                    let chunk = &data[offset..offset + 32];
                    
                    // 快速预筛选
                    if !quick_filter(chunk) {
                        continue;
                    }
                    
                    let entropy = calculate_entropy(chunk);
                    
                    // 只保留高熵值的候选 (>= 6.5)
                    if entropy >= 6.5 {
                        let key_hex = hex::encode(chunk);
                        
                        // 去重
                        if !candidates.iter().any(|k| k.key_hex == key_hex) {
                            candidates.push(KeyCandidate {
                                key_hex,
                                address: base + offset,
                                entropy,
                            });
                        }
                    }
                }
            }

            regions_scanned += 1;
        }

        // 定期报告进度
        if last_report.elapsed() > Duration::from_secs(3) {
            print!("\r扫描进度: {} 区域, {} MB, {} 候选密钥    ",
                regions_scanned,
                bytes_scanned / 1024 / 1024,
                candidates.len()
            );
            io::stdout().flush().ok();
            last_report = Instant::now();
        }

        addr = next_addr;
        
        // 防止无限循环
        if next_addr <= base {
            break;
        }
    }

    println!();
    println!("扫描完成: {} 区域, {} MB, 耗时 {:.1}s",
        regions_scanned,
        bytes_scanned / 1024 / 1024,
        start_time.elapsed().as_secs_f64()
    );

    unsafe { let _ = CloseHandle(handle); }

    // 按熵值排序
    candidates.sort_by(|a, b| b.entropy.partial_cmp(&a.entropy).unwrap());
    
    // 只返回前20个最高熵值的候选
    Ok(candidates.into_iter().take(20).collect())
}

fn is_readable(protect: u32) -> bool {
    let readable = [
        PAGE_READONLY.0,
        PAGE_READWRITE.0,
        PAGE_WRITECOPY.0,
        PAGE_EXECUTE_READ.0,
        PAGE_EXECUTE_READWRITE.0,
    ];
    readable.iter().any(|&p| protect & p != 0)
}

fn read_memory(handle: HANDLE, address: usize, size: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0usize;

    unsafe {
        let result = ReadProcessMemory(
            handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        );

        if result.is_ok() && bytes_read > 0 {
            buffer.truncate(bytes_read);
            Some(buffer)
        } else {
            None
        }
    }
}

/// 快速预筛选：排除明显不是密钥的数据
fn quick_filter(data: &[u8]) -> bool {
    if data.len() != 32 {
        return false;
    }

    // 全零检查
    if data.iter().all(|&b| b == 0) {
        return false;
    }

    // 全相同值检查
    if data.iter().all(|&b| b == data[0]) {
        return false;
    }

    // 零字节太多（最多4个）
    let zero_count = data.iter().filter(|&&b| b == 0).count();
    if zero_count > 4 {
        return false;
    }

    // 可打印字符太多（文本数据）
    let printable = data.iter().filter(|&&b| b >= 0x20 && b <= 0x7E).count();
    if printable > 24 {
        return false;
    }

    // 唯一字节数检查
    let mut seen = [false; 256];
    for &b in data {
        seen[b as usize] = true;
    }
    let unique = seen.iter().filter(|&&s| s).count();
    
    unique >= 18
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}
