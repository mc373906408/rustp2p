use std::ffi::CStr;
use std::net::Ipv4Addr;
use async_shutdown::ShutdownManager;
use std::sync::Arc;
use std::str::FromStr;

use crate::protocol::node_id::{GroupCode, NodeID};
use crate::tunnel::PeerNodeAddress;
use crate::{Builder, Endpoint};
use std::os::raw::c_char;
use std::ffi::c_void;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "use-kcp")]
use crate::reliable::{KcpListener, KcpStream};

// C-compatible enum for Transport Protocol
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocolC {
    TCP = 0,
    UDP = 1,
    Unknown = 2, // Fallback
}

// C类型别名
#[allow(non_camel_case_types)]
pub type size_t = usize;

/// 为C语言导出的类型定义 - Endpoint句柄
#[allow(non_camel_case_types)]
pub type EndpointHandle = *mut c_void;

/// C语言接口的回调函数类型定义
/// @param source_ip 发送者的IP地址（网络字节序）
/// @param message_ptr 消息内容的指针
/// @param message_len 消息长度
/// @param protocol 传输协议
#[allow(non_camel_case_types)]
pub type MessageCallback = extern "C" fn(*const u8, *const u8, size_t, TransportProtocolC) -> ();

/// KCP流句柄
#[allow(non_camel_case_types)]
pub type KcpStreamHandle = *mut c_void;

/// KCP监听器句柄
#[allow(non_camel_case_types)]
pub type KcpListenerHandle = *mut c_void;

/// 加密算法类型
#[repr(C)]
pub enum CipherType {
    None = 0,             // 不使用加密
    AesGcm = 1,           // AES-GCM 加密
    ChaCha20Poly1305 = 2, // ChaCha20-Poly1305 加密
}

/// NAT类型
#[repr(C)]
pub enum NatTypeC {
    Unknown = 0,   // 未知NAT类型
    Cone = 1,      // 锥形NAT
    Symmetric = 2, // 对称NAT
    None = 3,      // 无NAT
}

/// 传输类型
#[repr(C)]
pub enum TransportType {
    Tcp = 0, // TCP传输
    Kcp = 1, // KCP传输
}

// Endpoint包装器，包含Endpoint和运行时
struct EndpointWrapper {
    endpoint: Arc<Endpoint>,
    runtime: tokio::runtime::Runtime,
    shutdown_manager: ShutdownManager<()>,
    receiver_task: Option<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "use-kcp")]
    #[allow(dead_code)]
    kcp_streams: std::collections::HashMap<u32, KcpStream>,
}

#[cfg(feature = "use-kcp")]
struct KcpStreamWrapper {
    stream: KcpStream,
    runtime: tokio::runtime::Runtime,
}

#[cfg(feature = "use-kcp")]
struct KcpListenerWrapper {
    listener: KcpListener,
    runtime: tokio::runtime::Runtime,
}

/// 初始化函数
///
/// @param node_ip IPv4地址字符串
/// @param tcp_port TCP端口
/// @param udp_port UDP端口
/// @param group_code 组代码
/// @param password 密码字符串
/// @param cipher_type 加密类型，参见 CipherType 枚举
/// @param use_kcp 是否启用KCP传输，0表示不启用，1表示启用
/// @return 成功返回EndpointHandle，失败返回NULL
#[no_mangle]
pub extern "C" fn rustp2p_init(
    node_ip: *const c_char,    // IPv4地址字符串
    tcp_port: u16,           // TCP端口
    udp_port: u16,           // UDP端口
    group_code: u32,         // 组代码
    password: *const c_char, // 密码字符串
    cipher_type: i32,        // 加密类型
    use_kcp: i32,            // 是否启用KCP传输
) -> EndpointHandle {
    // 安全转换
    if node_ip.is_null() || password.is_null() {
        return std::ptr::null_mut();
    }

    // 解析IP地址字符串
    let node_ip_str = unsafe {
        match CStr::from_ptr(node_ip).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    // 解析为Ipv4Addr
    let node_id = match Ipv4Addr::from_str(node_ip_str) {
        Ok(ip) => ip,
        Err(_) => return std::ptr::null_mut(),
    };

    let _password_str = unsafe {
        match CStr::from_ptr(password).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    // 使用tokio运行时
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return std::ptr::null_mut(),
    };

    // 构建Endpoint
    let endpoint_result = runtime.block_on(async {
        let mut builder = Builder::new()
            .node_id(node_id.into())
            .tcp_port(tcp_port)
            .udp_port(udp_port)
            .group_code(GroupCode::from(group_code as u128));

        // 根据 cipher_type 参数选择加密方式
        match cipher_type {
            0 => { // None
                println!("不使用加密");
                // 不设置加密，使用默认的无加密模式
            },
            1 => { // AesGcm
                #[cfg(any(feature = "aes-gcm-openssl", feature = "aes-gcm-ring"))]
                {
                    builder = builder.encryption(crate::cipher::Algorithm::AesGcm(_password_str.clone()));
                }
                #[cfg(not(any(feature = "aes-gcm-openssl", feature = "aes-gcm-ring")))]
                {
                    println!("AES-GCM 加密未启用，请在编译时启用 aes-gcm-openssl 或 aes-gcm-ring 特性");
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "AES-GCM 加密未启用"));
                }
            },
            2 => { // ChaCha20Poly1305
                #[cfg(any(feature = "chacha20-poly1305-openssl", feature = "chacha20-poly1305-ring"))]
                {
                    builder = builder.encryption(crate::cipher::Algorithm::ChaCha20Poly1305(_password_str.clone()));
                }
                #[cfg(not(any(feature = "chacha20-poly1305-openssl", feature = "chacha20-poly1305-ring")))]
                {
                    println!("ChaCha20-Poly1305 加密未启用，请在编译时启用 chacha20-poly1305-openssl 或 chacha20-poly1305-ring 特性");
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "ChaCha20-Poly1305 加密未启用"));
                }
            },
            _ => {
                println!("无效的加密类型: {}", cipher_type);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("无效的加密类型: {}", cipher_type)));
            }
        }

        // 如果启用KCP，确保编译时启用了use-kcp特性
        #[cfg(feature = "use-kcp")]
        if use_kcp > 0 {
            println!("启用KCP传输");
        }

        #[cfg(not(feature = "use-kcp"))]
        if use_kcp > 0 {
            println!("KCP传输未启用，请在编译时启用use-kcp特性");
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "KCP传输未启用"));
        }

        builder.build().await
    });

    match endpoint_result {
        Ok(endpoint) => {
            let shutdown_manager = ShutdownManager::new();

            // 将Endpoint转换为可以传递给C的句柄
            let boxed = Box::new(EndpointWrapper {
                endpoint: Arc::new(endpoint),
                runtime,
                shutdown_manager,
                receiver_task: None,
                #[cfg(feature = "use-kcp")]
                kcp_streams: std::collections::HashMap::new(),
            });
            Box::into_raw(boxed) as EndpointHandle
        }
        Err(e) => {
            println!("初始化失败: {}", e);
            std::ptr::null_mut()
        }
    }
}

/// 添加对等节点
///
/// @param handle EndpointHandle
/// @param peer_address 对等节点地址字符串
/// @return 成功返回true，失败返回false
#[no_mangle]
pub extern "C" fn rustp2p_add_peer(handle: EndpointHandle, peer_address: *const c_char) -> bool {
    if handle.is_null() || peer_address.is_null() {
        return false;
    }

    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };

    let peer_str = unsafe {
        match CStr::from_ptr(peer_address).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };

    match PeerNodeAddress::from_str(peer_str) {
        Ok(peer_addr) => {
            // 将peer添加到node_context的direct_nodes列表中
            let peers = vec![peer_addr];
            let result = wrapper.runtime.block_on(async {
                wrapper
                    .endpoint
                    .node_context()
                    .update_direct_nodes(peers)
                    .await
            });
            result.is_ok()
        }
        Err(_) => false,
    }
}

/// 发送消息（合并同步和异步功能）
///
/// @param handle EndpointHandle
/// @param peer_ip 对等节点IP地址字符串
/// @param data 消息数据
/// @param data_len 消息长度
/// @param reliable 是否使用可靠传输 (1=同步/可靠, 0=异步/不可靠)
/// @param protocol_used 用来存储使用的协议（TCP/UDP），0表示TCP，1表示UDP，2表示未知
/// @return 成功返回true，失败返回false
#[no_mangle]
pub extern "C" fn rustp2p_send(
    handle: EndpointHandle,
    peer_ip: *const c_char,
    data: *const u8,
    data_len: size_t,
    reliable: i32,
    protocol_used: *mut i32,
) -> bool {
    if handle.is_null() || peer_ip.is_null() || data.is_null() || data_len == 0 {
        return false;
    }

    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };

    // 解析IP地址字符串
    let peer_ip_str = unsafe {
        match CStr::from_ptr(peer_ip).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };

    // 解析为Ipv4Addr
    let peer_id = match Ipv4Addr::from_str(peer_ip_str) {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    
    let node_id = NodeID::from(peer_id);

    // 将C指针转换为Rust切片
    let buffer = unsafe { std::slice::from_raw_parts(data, data_len) };

    // 设置协议为未知（简化协议检测）
    if !protocol_used.is_null() {
        unsafe {
            *protocol_used = TransportProtocolC::Unknown as i32;
        }
    }

    if reliable > 0 {
        // 可靠传输：同步发送
        // 删除发送前的路由发现代码
        
        // 尝试发送消息
        let mut success = false;
        let endpoint_clone_send = wrapper.endpoint.clone();
        
        for _i in 0..3 {
            // 发送消息
            let result = wrapper
                .runtime
                .block_on(async {
                     endpoint_clone_send.send_to(buffer, node_id).await
                });

            if let Ok(_) = result {
                success = true;
                break;
            } else {
                // 发送失败，稍等片刻后重试
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        success
    } else {
        // 不可靠传输：异步发送
        // 复制数据，因为异步任务可能在原始数据被释放后才执行
        let data_vec: Vec<u8> = buffer.to_vec();

        let endpoint_clone = wrapper.endpoint.clone();
        let runtime_handle = wrapper.runtime.handle().clone();

        // 创建异步发送任务
        runtime_handle.spawn(async move {
            match endpoint_clone.send_to(data_vec.as_slice(), node_id).await {
                Ok(_) => {
                    // 发送成功
                }
                Err(e) => {
                    log::error!("[FFI Async] Failed to send message to {:?}: {:?}", node_id, e);
                }
            }
        });
        true // 异步发送总是返回true，因为只是提交了任务
    }
}

/// 启动消息接收循环
#[no_mangle]
pub extern "C" fn rustp2p_start_receiver(
    handle: EndpointHandle,
    callback: MessageCallback,
) -> bool {
    if handle.is_null() {
        return false;
    }

    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };

    // 确保接收器尚未运行
    if wrapper.receiver_task.is_some() {
        return false;
    }

    let endpoint = wrapper.endpoint.clone();
    let runtime_handle = wrapper.runtime.handle().clone();
    let shutdown_manager = wrapper.shutdown_manager.clone();

    let task = runtime_handle.spawn(async move {
        log::info!("[FFI Receiver] Started");
        loop {
            tokio::select! {
                biased; // 优先处理关闭信号
                _ = shutdown_manager.wait_shutdown_triggered() => {
                    log::info!("[FFI Receiver] Shutdown signal received");
                    break;
                }
                recv_result = tokio::time::timeout(std::time::Duration::from_millis(200), endpoint.recv_from()) => {
                    match recv_result {
                        Ok(Ok((data, metadata))) => {
                            // 获取发送者IP(网络字节序)
                            let sender_ip_net = match TryInto::<Ipv4Addr>::try_into(metadata.src_id()) {
                                Ok(addr) => {
                                    // 网络字节序转换为主机字节序
                                    let octets = addr.octets();
                                    // 直接将这四个字节传递给回调函数
                                    octets
                                },
                                Err(_) => {
                                    continue; // 跳过此消息
                                }
                            };

                            // 简化协议处理，统一设为未知（不再尝试检测）
                            let protocol = TransportProtocolC::Unknown;

                            // 获取数据并调用回调函数
                            let payload = data.payload();
                            // 不再转换为指针，直接传递字节数组的引用
                            callback(sender_ip_net.as_ptr(), payload.as_ptr(), payload.len(), protocol);
                        }
                        Ok(Err(e)) => {
                            // 仅记录非超时错误
                            if e.kind() != std::io::ErrorKind::WouldBlock && e.kind() != std::io::ErrorKind::TimedOut {
                                log::error!("[FFI Receiver] Error: {}", e);
                            }
                        }
                        Err(_) => {
                            // 超时，继续循环检查关闭信号
                        }
                    }
                }
            }
        }
        log::info!("[FFI Receiver] Stopped");
    });

    wrapper.receiver_task = Some(task);
    true
}

/// 停止接收循环
#[no_mangle]
pub extern "C" fn rustp2p_stop_receiver(handle: EndpointHandle) -> bool {
    if handle.is_null() {
        return false;
    }

    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };

    // 如果没有任务运行，返回成功
    let task = match wrapper.receiver_task.take() {
        Some(task) => task,
        None => {
            return true; // 没有任务需要停止
        }
    };

    // 触发关闭信号
    if wrapper.shutdown_manager.trigger_shutdown(()).is_err() {
        // 信号已经被触发，继续等待任务
    }

    // 获取运行时句柄等待任务完成
    let runtime_handle = wrapper.runtime.handle().clone();
    let wait_result = runtime_handle.block_on(async {
        // 添加超时以防任务卡住
        match tokio::time::timeout(std::time::Duration::from_secs(2), task).await {
            Ok(Ok(_)) => true,
            Ok(Err(_)) => false, // 任务出错或被取消
            Err(_) => false, // 超时
        }
    });

    wait_result
}

/// 关闭并释放资源
/// @param handle EndpointHandle
/// @param timeout_ms 等待接收器任务完成的超时时间（毫秒），0表示使用默认值(1000ms)
/// @return 成功返回true，失败返回false
#[no_mangle]
pub extern "C" fn rustp2p_cleanup(handle: EndpointHandle, timeout_ms: u64) -> bool {
    if handle.is_null() {
        return false;
    }

    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };
    
    // 使用提供的超时时间，如果为0则使用默认值
    let actual_timeout = if timeout_ms == 0 { 1000 } else { timeout_ms };
    
    // 1. 触发关闭信号
    let signal_result = wrapper.shutdown_manager.trigger_shutdown(()).is_ok();
    
    // 2. 等待接收器任务完成
    let mut task_completed = true;
    if let Some(task) = wrapper.receiver_task.take() {
        let runtime_handle = wrapper.runtime.handle().clone();
        task_completed = runtime_handle.block_on(async {
            match tokio::time::timeout(std::time::Duration::from_millis(actual_timeout), task).await {
                Ok(Ok(_)) => true,
                Ok(Err(_)) => false, // 任务出错或被取消
                Err(_) => false,     // 超时
            }
        });
    }
    
    // 3. 获取EndpointWrapper的所有权并释放资源
    let boxed_wrapper = unsafe { Box::from_raw(handle as *mut EndpointWrapper) };
    let EndpointWrapper { endpoint, runtime, .. } = *boxed_wrapper;
    
    // 4. 清理资源
    drop(endpoint);
    runtime.shutdown_background();
    
    signal_result && task_completed
}

/// 获取NAT信息
///
/// @param handle EndpointHandle
/// @param nat_type 输出参数，NAT类型
/// @param public_ip 输出参数，公网IP地址（网络字节序）
/// @param public_port 输出参数，公网端口
/// @return 成功返回true，失败返回false
#[no_mangle]
pub extern "C" fn rustp2p_get_nat_info(
    handle: EndpointHandle,
    nat_type: *mut i32,
    public_ip: *mut u32,
    public_port: *mut u16,
) -> bool {
    if handle.is_null() || nat_type.is_null() || public_ip.is_null() || public_port.is_null() {
        return false;
    }

    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };

    // 获取NAT信息
    let result = wrapper.runtime.block_on(async {
        // 直接设置默认值
        let nat_type_value = NatTypeC::Unknown as i32;
        unsafe { *nat_type = nat_type_value };

        // 尝试获取本地IP地址
        if let Ok(local_addr) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if let Ok(()) = local_addr.connect("8.8.8.8:53") {
                if let Ok(addr) = local_addr.local_addr() {
                    if let std::net::SocketAddr::V4(ipv4) = addr {
                        let ip = ipv4.ip();
                        // 转换为网络字节序（大端序）
                        let ip_value = u32::from_be_bytes(ip.octets());
                        unsafe { *public_ip = ip_value };
                        unsafe { *public_port = addr.port() };
                        return true;
                    }
                }
            }
        }

        // 如果无法获取地址，设置默认值
        unsafe { *public_ip = 0 };
        unsafe { *public_port = 0 };

        true
    });

    result
}

#[cfg(feature = "use-kcp")]
#[no_mangle]
pub extern "C" fn rustp2p_open_kcp_stream(handle: EndpointHandle, peer_ip: u32) -> KcpStreamHandle {
    if handle.is_null() {
        println!("[FFI] rustp2p_open_kcp_stream: handle is null");
        return std::ptr::null_mut();
    }

    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };
    let peer_id = Ipv4Addr::from(peer_ip.to_be_bytes());
    let node_id = NodeID::from(peer_id);

    println!(
        "[FFI] rustp2p_open_kcp_stream: Opening KCP stream to {}",
        peer_id
    );

    let endpoint_clone = wrapper.endpoint.clone();
    let stream_result = wrapper.runtime.block_on(async {
        println!("[FFI] rustp2p_open_kcp_stream: Sending hello messages to establish UDP route");
        let mut route_established = false;
        for i in 0..15 { 
            println!(
                "[FFI] rustp2p_open_kcp_stream: Sending hello message attempt {}",
                i + 1
            );
            if let Ok(_) = endpoint_clone
                .send_to(b"hello from kcp init", node_id)
                .await
            {
                println!("[FFI] rustp2p_open_kcp_stream: Hello message sent successfully");
                route_established = true;
                for _ in 0..3 {
                    let _ = endpoint_clone
                        .send_to(b"hello from kcp init", node_id)
                        .await;
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                break;
            }
            println!("[FFI] rustp2p_open_kcp_stream: Hello message failed, retrying...");
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }

        if !route_established {
            println!("[FFI] rustp2p_open_kcp_stream: Route establishment failed, trying direct KCP stream creation");
            for _ in 0..5 {
                let _ = endpoint_clone.send_to(b"route_discovery", node_id).await;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

        println!("[FFI] rustp2p_open_kcp_stream: Creating KCP stream");
        endpoint_clone.open_kcp_stream(node_id)
    });

    match stream_result {
        Ok(mut stream) => {
            println!("[FFI] rustp2p_open_kcp_stream: KCP stream created successfully");
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => {
                    println!("[FFI] rustp2p_open_kcp_stream: Runtime created successfully");
                    rt
                }
                Err(e) => {
                    println!(
                        "[FFI] rustp2p_open_kcp_stream: Failed to create runtime: {}",
                        e
                    );
                    return std::ptr::null_mut();
                }
            };

            let init_result = runtime.block_on(async {
                println!(
                    "[FFI] rustp2p_open_kcp_stream: Sending initial message to confirm connection"
                );
                stream.write_all(b"kcp_stream_init").await
            });

            if let Err(e) = init_result {
                println!(
                    "[FFI] rustp2p_open_kcp_stream: Failed to send initial message: {}",
                    e
                );
            }

            println!("[FFI] rustp2p_open_kcp_stream: Returning KCP stream handle");
            Box::into_raw(Box::new(KcpStreamWrapper { stream, runtime })) as KcpStreamHandle
        }
        Err(e) => {
            println!(
                "[FFI] rustp2p_open_kcp_stream: Failed to create KCP stream: {:?}",
                e
            );
            std::ptr::null_mut()
        }
    }
}

#[cfg(feature = "use-kcp")]
#[no_mangle]
pub extern "C" fn rustp2p_kcp_stream_send(
    handle: KcpStreamHandle,
    data: *const u8,
    data_len: size_t,
) -> bool {
    if handle.is_null() || data.is_null() || data_len == 0 {
        println!("[FFI] rustp2p_kcp_stream_send: Invalid parameters");
        return false;
    }

    println!("[FFI] rustp2p_kcp_stream_send: Sending {} bytes", data_len);
    let wrapper = unsafe { &mut *(handle as *mut KcpStreamWrapper) };

    let buffer = unsafe { std::slice::from_raw_parts(data, data_len) };

    let send_result = wrapper.runtime.block_on(async {
        println!("[FFI] rustp2p_kcp_stream_send: Writing to KCP stream");
        wrapper.stream.write_all(buffer).await
    });

    match send_result {
        Ok(_) => {
            println!("[FFI] rustp2p_kcp_stream_send: Send successful");
            true
        }
        Err(e) => {
            println!("[FFI] rustp2p_kcp_stream_send: Send failed: {}", e);
            false
        }
    }
}

#[cfg(feature = "use-kcp")]
#[no_mangle]
pub extern "C" fn rustp2p_kcp_stream_recv(
    handle: KcpStreamHandle,
    buffer: *mut u8,
    buffer_len: size_t,
    bytes_read: *mut size_t,
) -> bool {
    if handle.is_null() || buffer.is_null() || buffer_len == 0 || bytes_read.is_null() {
        println!("[FFI] rustp2p_kcp_stream_recv: Invalid parameters");
        return false;
    }

    println!(
        "[FFI] rustp2p_kcp_stream_recv: Receiving with buffer size {}",
        buffer_len
    );
    let wrapper = unsafe { &mut *(handle as *mut KcpStreamWrapper) };

    let mut rust_buffer = vec![0u8; buffer_len];

    let result = wrapper.runtime.block_on(async {
        println!("[FFI] rustp2p_kcp_stream_recv: Reading from KCP stream");
        wrapper.stream.read(&mut rust_buffer).await
    });

    match result {
        Ok(len) => {
            println!("[FFI] rustp2p_kcp_stream_recv: Received {} bytes", len);
            unsafe {
                std::ptr::copy_nonoverlapping(rust_buffer.as_ptr(), buffer, len);
                *bytes_read = len;
            }
            true
        }
        Err(e) => {
            println!("[FFI] rustp2p_kcp_stream_recv: Receive failed: {}", e);
            false
        }
    }
}

#[cfg(feature = "use-kcp")]
#[no_mangle]
pub extern "C" fn rustp2p_close_kcp_stream(handle: KcpStreamHandle) {
    if !handle.is_null() {
        unsafe {
            let _boxed = Box::from_raw(handle as *mut KcpStreamWrapper);
        }
    }
}

/// 创建KCP监听器
///
/// @param handle EndpointHandle
/// @return 成功返回KcpListenerHandle，失败返回NULL
#[cfg(feature = "use-kcp")]
#[no_mangle]
pub extern "C" fn rustp2p_create_kcp_listener(handle: EndpointHandle) -> KcpListenerHandle {
    if handle.is_null() {
        println!("[FFI] rustp2p_create_kcp_listener: handle is null");
        return std::ptr::null_mut();
    }

    println!("[FFI] rustp2p_create_kcp_listener: Creating KCP listener");
    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };

    let listener = wrapper.endpoint.kcp_listener();
    println!("[FFI] rustp2p_create_kcp_listener: KCP listener created");

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => {
            println!("[FFI] rustp2p_create_kcp_listener: Runtime created successfully");
            rt
        }
        Err(e) => {
            println!(
                "[FFI] rustp2p_create_kcp_listener: Failed to create runtime: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let _keep_alive = runtime.spawn(async {
        println!(
            "[FFI] rustp2p_create_kcp_listener: Starting background task to keep runtime alive"
        );
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });

    println!("[FFI] rustp2p_create_kcp_listener: Returning KCP listener handle");
    Box::into_raw(Box::new(KcpListenerWrapper { listener, runtime })) as KcpListenerHandle
}

/// 接受KCP连接
///
/// @param handle KcpListenerHandle
/// @param node_id_out 输出参数，连接的节点ID（网络字节序）
/// @return 成功返回KcpStreamHandle，失败返回NULL
#[cfg(feature = "use-kcp")]
#[no_mangle]
pub extern "C" fn rustp2p_accept_kcp_connection(
    handle: KcpListenerHandle,
    node_id_out: *mut u32,
) -> KcpStreamHandle {
    if handle.is_null() || node_id_out.is_null() {
        println!("[FFI] rustp2p_accept_kcp_connection: Invalid parameters");
        return std::ptr::null_mut();
    }

    println!("[FFI] rustp2p_accept_kcp_connection: Accepting KCP connection");
    let wrapper = unsafe { &mut *(handle as *mut KcpListenerWrapper) };

    let result = wrapper.runtime.block_on(async {
        println!("[FFI] rustp2p_accept_kcp_connection: Waiting for connection");

        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

        for i in 0..5 {
            println!("[FFI] rustp2p_accept_kcp_connection: Attempt {} to accept connection", i + 1);

            match tokio::time::timeout(
                std::time::Duration::from_secs(3),
                wrapper.listener.accept(),
            )
            .await
            {
                Ok(result) => return result,
                Err(_) => {
                    println!("[FFI] rustp2p_accept_kcp_connection: Timeout waiting for connection on attempt {}", i + 1);
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }

        println!("[FFI] rustp2p_accept_kcp_connection: All attempts failed, trying one last time");
        wrapper.listener.accept().await
    });

    match result {
        Ok((mut stream, node_id)) => {
            println!(
                "[FFI] rustp2p_accept_kcp_connection: Connection accepted from {:?}",
                node_id
            );
            let ipv4 = TryInto::<Ipv4Addr>::try_into(node_id).unwrap();
            let ip_bytes = ipv4.octets();
            let ip_uint32 = u32::from_be_bytes(ip_bytes);
            unsafe { *node_id_out = ip_uint32 };
            println!(
                "[FFI] rustp2p_accept_kcp_connection: Node ID set to {}",
                ipv4
            );

            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => {
                    println!("[FFI] rustp2p_accept_kcp_connection: Runtime created successfully");
                    rt
                }
                Err(e) => {
                    println!(
                        "[FFI] rustp2p_accept_kcp_connection: Failed to create runtime: {}",
                        e
                    );
                    return std::ptr::null_mut();
                }
            };

            let reply_result = runtime.block_on(async {
                println!("[FFI] rustp2p_accept_kcp_connection: Sending confirmation message");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                stream.write_all(b"kcp_connection_accepted").await
            });

            if let Err(e) = reply_result {
                println!(
                    "[FFI] rustp2p_accept_kcp_connection: Failed to send confirmation message: {}",
                    e
                );
            }

            println!("[FFI] rustp2p_accept_kcp_connection: Returning KCP stream handle");
            Box::into_raw(Box::new(KcpStreamWrapper { stream, runtime })) as KcpStreamHandle
        }
        Err(e) => {
            println!(
                "[FFI] rustp2p_accept_kcp_connection: Accept failed: {:?}",
                e
            );
            std::ptr::null_mut()
        }
    }
}

/// 关闭KCP监听器
///
/// @param handle KcpListenerHandle
#[cfg(feature = "use-kcp")]
#[no_mangle]
pub extern "C" fn rustp2p_close_kcp_listener(handle: KcpListenerHandle) {
    if !handle.is_null() {
        unsafe {
            let _boxed = Box::from_raw(handle as *mut KcpListenerWrapper);
        }
    }
}

/// 获取可靠隧道信息
///
/// @param handle EndpointHandle
/// @param tunnel_type 输出参数，隧道类型（TCP或KCP）
/// @param connected_peers 输出参数，已连接的对等节点数量
/// @return 成功返回true，失败返回false
#[no_mangle]
pub extern "C" fn rustp2p_get_tunnel_info(
    handle: EndpointHandle,
    tunnel_type: *mut i32,
    connected_peers: *mut u32,
) -> bool {
    if handle.is_null() || tunnel_type.is_null() || connected_peers.is_null() {
        return false;
    }

    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };

    wrapper.runtime.handle().block_on(async {
        let tunnel_type_value = TransportType::Tcp as i32;
        unsafe { *tunnel_type = tunnel_type_value };

        let peers_count = wrapper.endpoint.node_context().get_direct_nodes().len() as u32;
        unsafe { *connected_peers = peers_count };
    });

    true
}
