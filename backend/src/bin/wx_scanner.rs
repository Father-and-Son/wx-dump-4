use std::path::PathBuf;
use sysinfo::{Pid, System};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use rayon::prelude::*;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use std::sync::atomic::{AtomicBool, Ordering};

// 目标文件头
const SQLITE_HEADER: &[u8] = b"SQLite format 3\0";

fn main() {
    println!("=== 微信密钥内存暴力扫描器 (Rust版) ===");
    println!("此工具通过暴力扫描已登录微信的内存，寻找能解密数据库的 AES Key (Raw Key)。");
    println!("请确保微信已登录！");

    // 1. 准备验证数据
    let db_path = PathBuf::from(r"D:\xwechat_files\wxid_4fmddgv0yhee22_cd66\msg\MicroMsg.db"); 
    // 也可以试试 db_storage\message\message_0.db，只要是 SQLCipher v4 加密的即可
    
    if !db_path.exists() {
        println!("错误: 找不到数据库文件 {:?}", db_path);
        return;
    }

    println!("正在读取数据库文件头用于验证: {:?}", db_path);
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

    // 提取 Page 1 (offset 16-4096)
    // C1: Page 1 的第一个 16 字节块 (Offset 16 in file)
    let c1_slice = &file_data[16..32];
    let mut c1_block = aes::Block::default();
    c1_block.copy_from_slice(c1_slice);

    // IV: Page 1 的末尾保留区 (Offset 4096 - 48) 的前 16 字节
    // File Offset: 4096 - 48 = 4048
    let iv_slice = &file_data[4048..4064];
    
    println!("验证数据准备完成。");
    println!("C1: {:?}", c1_slice);
    println!("IV: {:?}", iv_slice);

    // 2. 查找微信进程
    let mut system = System::new_all();
    system.refresh_all();
    
    let pid = system.processes_by_name("Weixin.exe")
        .next()
        .map(|p| p.pid().as_u32())
        .or_else(|| {
            // 备用：尝试 WeChat.exe
            system.processes_by_name("WeChat.exe")
                .next()
                .map(|p| p.pid().as_u32())
        });

    let pid = match pid {
        Some(p) => p,
        None => {
            println!("错误: 未找到 Weixin.exe 或 WeChat.exe 进程。请先启动微信。");
            return;
        }
    };

    println!("找到微信进程 PID: {}", pid);

    // 3. 打开进程
    let process_handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)
    };

    if process_handle == 0 || process_handle == INVALID_HANDLE_VALUE {
        println!("错误: 无法打开进程 (OpenProcess 失败)。请尝试以【管理员身份】运行此程序！");
        return;
    }

    println!("已打开进程句柄。开始内存扫描...");
    println!("这可能需要几分钟，取决于内存大小...");

    let found = AtomicBool::new(false);
    
    // 4. 遍历内存区域
    let mut address: usize = 0;
    let mut mem_info = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
    let mut regions_scanned = 0;
    let mut bytes_scanned = 0usize;

    loop {
        if found.load(Ordering::Relaxed) {
            break;
        }

        let result = unsafe {
            VirtualQueryEx(
                process_handle,
                address as *const _,
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        // 只扫描已提交的、可读写的内存
        // Key 通常在堆上，堆内存通常是 ReadWrite
        if mem_info.State == MEM_COMMIT && 
           (mem_info.Protect & PAGE_READWRITE) != 0 {
            
            let region_size = mem_info.RegionSize;
            let base_addr = mem_info.BaseAddress as usize;
            
            // 读取这块内存
            let mut buffer = vec![0u8; region_size];
            let mut bytes_read = 0;
            
            let success = unsafe {
                ReadProcessMemory(
                    process_handle,
                    base_addr as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    region_size,
                    &mut bytes_read,
                )
            };

            if success != 0 && bytes_read > 32 {
                // 并行扫描 Buffer
                // Key 是 32 字节。我们假设它是 8 字节对齐的（通常堆分配是对齐的）
                // 为了保险，也可以步长为 4 或 1。步长越小越慢。
                // 这里用 chunk 迭代，或者 window。
                // 32 字节 Key, 步长 8.
                
                // 为了性能，我们通过 par_bridge 或者 chunks
                // buffer.par_window... no window in rayon.
                // 我们可以按块处理。
                
                // 筛选优化：AES Key 的熵很高，不太可能是全0。
                // 但这里我们主要依赖 CPU 的 AES 指令集速度。
                
                let scan_result = buffer.par_windows(32)
                    // 步长优化：只从 8 的倍数位置开始
                    .step_by(8) 
                    .find_any(|key_candidate| {
                        if found.load(Ordering::Relaxed) { return false; }

                        // 简单的熵检查：如果全是0，跳过
                        if key_candidate[0] == 0 && key_candidate[1] == 0 && key_candidate[2] == 0 {
                            return false;
                        }

                        // 尝试解密
                        let key = aes::Key::from_slice(key_candidate);
                        let cipher = Aes256::new(key);
                        let mut block = c1_block.clone();
                        
                        cipher.decrypt_block(&mut block);
                        
                        // XOR IV
                        // block ^= iv_slice
                        let block_bytes = block.as_mut_slice();
                        for i in 0..16 {
                            block_bytes[i] ^= iv_slice[i];
                        }
                        
                        // Check Header
                        if block_bytes.starts_with(SQLITE_HEADER) {
                            // double check: print full header
                            // println!("Candidate Header: {:?}", block_bytes);
                            return true;
                        }
                        false
                    });
                
                if let Some(key) = scan_result {
                    let key_hex = hex::encode(key);
                    println!("\n\n===========================================");
                    println!("🎉 成功找到密钥！");
                    println!("===========================================");
                    println!("Key (Hex): {}", key_hex);
                    println!("Memory Address: 0x{:x}", base_addr); // 这里的偏移没加上，不过不重要
                    println!("===========================================\n");
                    
                    found.store(true, Ordering::Relaxed);
                }
            }
            
            regions_scanned += 1;
            bytes_scanned += region_size;
            
            // 每扫描 1GB 打印一次进度
            if bytes_scanned % (1024 * 1024 * 1024) < region_size {
                 println!("已扫描: {:.2} GB, Regions: {}", bytes_scanned as f64 / 1024.0 / 1024.0 / 1024.0, regions_scanned);
            }
        }

        address += mem_info.RegionSize;
    }

    unsafe { CloseHandle(process_handle) };
    
    if !found.load(Ordering::Relaxed) {
        println!("扫描完成，未能找到 Key。");
        println!("可能原因：");
        println!("1. 微信数据不在内存中（尝试打开一个聊天窗口触发加载）");
        println!("2. 权限不足（请使用管理员运行）");
        println!("3. 密钥未对齐（当前步长 8）");
    }
}
