//! 微信交互式密钥监控工具 v3.0
//!
//! 通过监控内存变化来捕获数据库密钥
//! 使用方法：
//! 1. 运行此程序
//! 2. 按提示操作微信
//! 3. 程序会检测内存变化并尝试找到密钥

use std::collections::HashMap;
use std::io::{self, Read, Write};
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

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║         微信交互式密钥监控工具 v3.0                            ║");
    println!("║  操作微信时检测内存变化，自动捕获密钥                          ║");
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

    // 交互式监控
    interactive_monitor(main_pid);
}

fn interactive_monitor(pid: u32) {
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) } {
        Ok(h) => h,
        Err(e) => {
            println!("❌ 无法打开进程: {}", e);
            return;
        }
    };

    println!("════════════════════════════════════════════════════════════════");
    println!("准备开始监控！请按以下步骤操作：");
    println!("════════════════════════════════════════════════════════════════");
    println!();

    // 第一阶段：拍摄初始快照
    println!("📸 第一步：拍摄初始内存快照");
    println!("   请确保微信已打开但不要进行任何操作");
    println!();
    wait_for_enter("按 Enter 键拍摄初始快照...");
    
    println!("正在拍摄初始快照...");
    let snapshot1 = take_snapshot(handle);
    println!("✓ 初始快照完成！记录了 {} 个内存区域\n", snapshot1.len());

    // 第二阶段：用户操作
    println!("════════════════════════════════════════════════════════════════");
    println!("🔧 第二步：请在微信中进行以下操作：");
    println!("   1. 切换到一个聊天对话");
    println!("   2. 向上滚动查看历史消息");
    println!("   3. 发送一条消息");
    println!("   4. 打开联系人资料");
    println!("   5. 点击朋友圈");
    println!();
    println!("   执行完上述操作后按 Enter 继续...");
    println!("════════════════════════════════════════════════════════════════");
    wait_for_enter("");

    // 第三阶段：拍摄操作后快照
    println!("📸 第三步：拍摄操作后的内存快照");
    println!("正在拍摄...");
    let snapshot2 = take_snapshot(handle);
    println!("✓ 操作后快照完成！记录了 {} 个内存区域\n", snapshot2.len());

    // 分析变化
    println!("════════════════════════════════════════════════════════════════");
    println!("🔍 第四步：分析内存变化，搜索密钥...");
    println!("════════════════════════════════════════════════════════════════");
    
    analyze_changes(handle, &snapshot1, &snapshot2);

    unsafe { let _ = CloseHandle(handle); }
}

fn wait_for_enter(prompt: &str) {
    if !prompt.is_empty() {
        print!("{}", prompt);
    }
    io::stdout().flush().ok();
    let mut buffer = [0u8; 32];
    let _ = io::stdin().read(&mut buffer);
}

/// 内存区域快照
type MemorySnapshot = HashMap<usize, Vec<u8>>;

fn take_snapshot(handle: HANDLE) -> MemorySnapshot {
    let mut snapshot = HashMap::new();
    let mut addr: usize = 0;
    let mut count = 0;

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

        // 只快照可能包含密钥的区域（可读写的堆内存）
        if mem_info.State == MEM_COMMIT 
            && is_readable(mem_info.Protect.0)
            && size <= 4 * 1024 * 1024  // 最大4MB
        {
            if let Some(data) = read_memory(handle, base, size.min(65536)) {
                // 只保存数据的hash来节省内存
                snapshot.insert(base, compute_hash(&data));
                count += 1;
            }
        }

        addr = next_addr;
        if next_addr <= base {
            break;
        }
    }

    print!("   扫描了 {} 个区域\r", count);
    io::stdout().flush().ok();
    snapshot
}

fn compute_hash(data: &[u8]) -> Vec<u8> {
    // 简单hash: 前32字节 + 中间32字节 + 后32字节
    let mut hash = Vec::with_capacity(96);
    
    if data.len() >= 32 {
        hash.extend_from_slice(&data[..32]);
    }
    
    if data.len() >= 64 {
        let mid = data.len() / 2;
        let start = mid.saturating_sub(16);
        let end = (start + 32).min(data.len());
        hash.extend_from_slice(&data[start..end]);
    }
    
    if data.len() >= 32 {
        let start = data.len().saturating_sub(32);
        hash.extend_from_slice(&data[start..]);
    }
    
    hash
}

fn analyze_changes(handle: HANDLE, before: &MemorySnapshot, after: &MemorySnapshot) {
    let mut changed_regions = Vec::new();
    let mut new_regions = Vec::new();

    // 找出变化的区域
    for (addr, hash_after) in after {
        if let Some(hash_before) = before.get(addr) {
            if hash_before != hash_after {
                changed_regions.push(*addr);
            }
        } else {
            new_regions.push(*addr);
        }
    }

    println!();
    println!("📊 分析结果:");
    println!("   - 变化的区域: {} 个", changed_regions.len());
    println!("   - 新增的区域: {} 个", new_regions.len());
    println!();

    if changed_regions.is_empty() && new_regions.is_empty() {
        println!("❌ 未检测到内存变化。可能原因：");
        println!("   1. 微信没有实际访问数据库");
        println!("   2. 密钥缓存在其他位置");
        return;
    }

    // 在变化的区域中搜索密钥
    println!("🔑 在变化的内存区域中搜索密钥...\n");
    
    let mut all_candidates = Vec::new();
    let regions_to_scan: Vec<usize> = changed_regions.into_iter().chain(new_regions).collect();
    
    for (i, &addr) in regions_to_scan.iter().enumerate() {
        if i % 100 == 0 {
            print!("\r   扫描进度: {}/{}    ", i, regions_to_scan.len());
            io::stdout().flush().ok();
        }

        // 读取完整区域数据
        if let Some(data) = read_memory(handle, addr, 65536) {
            // 在数据中搜索可能的密钥
            for offset in (0..data.len().saturating_sub(32)).step_by(8) {
                let chunk = &data[offset..offset + 32];
                
                let entropy = calculate_entropy(chunk);
                let zero_count = chunk.iter().filter(|&&b| b == 0).count();
                let unique_count = count_unique(chunk);
                
                // 放宽条件：熵值>5.0, 零字节<8, 唯一字节>=12
                if entropy > 5.0 && zero_count < 8 && unique_count >= 12 {
                    all_candidates.push((addr + offset, hex::encode(chunk), entropy, unique_count));
                }
            }
        }
    }

    println!("\r                                              ");
    
    // 按熵值排序并显示结果
    all_candidates.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
    
    if all_candidates.is_empty() {
        println!("❌ 在变化的区域中未找到高熵值数据");
        println!();
        println!("尝试降低筛选条件再次搜索...");
        
        // 第二遍：更宽松的条件
        for &addr in &regions_to_scan {
            if let Some(data) = read_memory(handle, addr, 65536) {
                for offset in (0..data.len().saturating_sub(32)).step_by(8) {
                    let chunk = &data[offset..offset + 32];
                    
                    let entropy = calculate_entropy(chunk);
                    let zero_count = chunk.iter().filter(|&&b| b == 0).count();
                    
                    // 非常宽松：熵值>4.0, 零字节<12
                    if entropy > 4.0 && zero_count < 12 {
                        all_candidates.push((addr + offset, hex::encode(chunk), entropy, count_unique(chunk)));
                    }
                }
            }
        }
        
        all_candidates.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
    }

    // 去重
    let mut seen = std::collections::HashSet::new();
    all_candidates.retain(|c| seen.insert(c.1.clone()));

    println!();
    println!("════════════════════════════════════════════════════════════════");
    println!("🔑 找到 {} 个候选密钥（按熵值排序）:", all_candidates.len().min(30));
    println!("════════════════════════════════════════════════════════════════");
    println!();

    for (i, (addr, key, entropy, unique)) in all_candidates.iter().take(30).enumerate() {
        println!("[{:2}] 熵值:{:.2} 唯一字节:{:2} 地址:0x{:x}", i + 1, entropy, unique, addr);
        println!("     密钥: {}", key);
        println!();
    }

    if !all_candidates.is_empty() {
        println!("════════════════════════════════════════════════════════════════");
        println!("请使用以下命令验证密钥：");
        println!("  cargo run --bin wx_key_verifier -- <db_path> <key_hex>");
        println!("════════════════════════════════════════════════════════════════");
    }
}

fn count_unique(data: &[u8]) -> usize {
    let mut seen = [false; 256];
    for &b in data {
        seen[b as usize] = true;
    }
    seen.iter().filter(|&&s| s).count()
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
