use async_shutdown::ShutdownManager;
use std::collections::HashMap;
use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;

use crate::protocol::node_id::{GroupCode, NodeID};
use crate::tunnel::PeerNodeAddress;
use crate::{Builder, Endpoint};
use std::ffi::c_void;
use std::os::raw::c_char;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "use-kcp")]
use crate::reliable::KcpStream;

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
#[allow(non_camel_case_types)]
pub type MessageCallback = extern "C" fn(*const u8, *const u8, size_t) -> ();

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
    Udp = 2, // UDP传输
}

// Endpoint包装器，包含Endpoint和运行时
struct EndpointWrapper {
    endpoint: Arc<Endpoint>,
    runtime: tokio::runtime::Runtime,
    shutdown_manager: ShutdownManager<()>,
    receiver_task: Option<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "use-kcp")]
    kcp_streams: Mutex<HashMap<String, KcpStream>>, // 使用IP字符串作为键存储KCP流
}

/// 初始化函数
///
/// @param node_ip IPv4地址字符串
/// @param tcp_port TCP端口
/// @param udp_port UDP端口
/// @param group_code 组代码
/// @param password 密码字符串
/// @param cipher_type 加密类型，参见 CipherType 枚举
/// @return 成功返回EndpointHandle，失败返回NULL
#[no_mangle]
pub extern "C" fn rustp2p_init(
    node_ip: *const c_char,  // IPv4地址字符串
    tcp_port: u16,           // TCP端口
    udp_port: u16,           // UDP端口
    group_code: u32,         // 组代码
    password: *const c_char, // 密码字符串
    cipher_type: i32,        // 加密类型
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
                kcp_streams: Mutex::new(HashMap::new()),
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
/// @return 成功返回true，失败返回false
#[no_mangle]
pub extern "C" fn rustp2p_send(
    handle: EndpointHandle,
    peer_ip: *const c_char,
    data: *const u8,
    data_len: size_t,
    reliable: i32,
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

    if reliable > 0 {
        // 可靠传输：优先使用KCP (如果可用)
        #[cfg(feature = "use-kcp")]
        {
            // 尝试使用或创建KCP流
            let result = wrapper.runtime.block_on(async {
                // 尝试获取已存在的KCP流
                let mut kcp_streams = wrapper.kcp_streams.lock().unwrap();

                if !kcp_streams.contains_key(peer_ip_str) {
                    // 需要创建新的KCP流
                    match wrapper.endpoint.open_kcp_stream(node_id) {
                        Ok(stream) => {
                            kcp_streams.insert(peer_ip_str.to_string(), stream);
                            log::debug!("[KCP] 创建新的KCP流到 {}", peer_ip_str);
                            println!("[KCP] 创建新的KCP流到 {}", peer_ip_str);
                        }
                        Err(e) => {
                            log::debug!("[KCP] 创建KCP流到 {} 失败: {:?}", peer_ip_str, e);
                            println!("[KCP] 创建KCP流到 {} 失败: {:?}", peer_ip_str, e);
                            // 如果无法创建KCP流，回退到普通发送
                            return wrapper.endpoint.send_to(buffer, node_id).await.is_ok();
                        }
                    }
                }

                // 现在我们应该有一个KCP流了
                if let Some(stream) = kcp_streams.get_mut(peer_ip_str) {
                    // 使用KCP流发送数据
                    match stream.write_all(buffer).await {
                        Ok(_) => {
                            log::debug!("[KCP] 通过KCP发送 {} 字节到 {}", buffer.len(), peer_ip_str);
                            println!("[KCP] 通过KCP发送 {} 字节到 {}", buffer.len(), peer_ip_str);
                            true
                        }
                        Err(e) => {
                            log::debug!("[KCP] 发送到 {} 出错: {:?}", peer_ip_str, e);
                            println!("[KCP] 发送到 {} 出错: {:?}", peer_ip_str, e);
                            // 移除错误的连接
                            kcp_streams.remove(peer_ip_str);
                            // 回退到普通发送
                            wrapper.endpoint.send_to(buffer, node_id).await.is_ok()
                        }
                    }
                } else {
                    // 这应该不会发生，但以防万一
                    wrapper.endpoint.send_to(buffer, node_id).await.is_ok()
                }
            });
            return result;
        }

        // 如果未启用KCP，或者上面的KCP代码没有执行，则回退到普通可靠发送
        #[cfg(not(feature = "use-kcp"))]
        {
            // 尝试发送消息
            let mut success = false;
            let endpoint_clone_send = wrapper.endpoint.clone();

            for _i in 0..3 {
                // 发送消息
                let result = wrapper
                    .runtime
                    .block_on(async { endpoint_clone_send.send_to(buffer, node_id).await });

                if let Ok(_) = result {
                    success = true;
                    break;
                } else {
                    // 发送失败，稍等片刻后重试
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
            success
        }
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
                    log::error!(
                        "[FFI Async] Failed to send message to {:?}: {:?}",
                        node_id,
                        e
                    );
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

    // 常规消息接收任务
    let normal_task = runtime_handle.spawn(async move {
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

                            // 获取数据并调用回调函数
                            let payload = data.payload();
                            // 不再转换为指针，直接传递字节数组的引用
                            callback(sender_ip_net.as_ptr(), payload.as_ptr(), payload.len());
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

    #[cfg(feature = "use-kcp")]
    {
        // KCP 接收任务 - 直接启动而不赋值给变量
        let endpoint_clone = wrapper.endpoint.clone();
        let shutdown_manager_clone = wrapper.shutdown_manager.clone();
        
        runtime_handle.spawn(async move {
            log::info!("[KCP] 接收器已启动");
            println!("[KCP] 接收器已启动");
            
            // 创建KCP监听器
            let kcp_listener = endpoint_clone.kcp_listener();
            
            loop {
                tokio::select! {
                    biased; // 优先处理关闭信号
                    _ = shutdown_manager_clone.wait_shutdown_triggered() => {
                        log::info!("[KCP] 接收到关闭信号");
                        println!("[KCP] 接收到关闭信号");
                        break;
                    }
                    accept_result = tokio::time::timeout(std::time::Duration::from_millis(500), kcp_listener.accept()) => {
                        match accept_result {
                            Ok(Ok((mut stream, remote_id))) => {
                                let remote_ip = match TryInto::<Ipv4Addr>::try_into(remote_id) {
                                    Ok(addr) => addr.octets(),
                                    Err(_) => continue, // 跳过无效的ID
                                };
                                
                                // 提取IP字符串用于日志
                                let ip_str = TryInto::<Ipv4Addr>::try_into(remote_id)
                                    .map(|addr| addr.to_string())
                                    .unwrap_or_else(|_| "unknown".to_string());

                                log::debug!("[KCP] 接受来自 {} 的新连接", ip_str);
                                println!("[KCP] 接受来自 {} 的新连接", ip_str);
                                
                                // 为每个连接创建一个专门的处理任务
                                let callback_clone = callback;
                                let shutdown_manager_clone = shutdown_manager_clone.clone();
                                
                                tokio::spawn(async move {
                                    let mut buffer = vec![0u8; 4096];
                                    
                                    loop {
                                        tokio::select! {
                                            biased; // 优先处理关闭信号
                                            _ = shutdown_manager_clone.wait_shutdown_triggered() => {
                                                break;
                                            }
                                            read_result = tokio::time::timeout(
                                                std::time::Duration::from_secs(60), // 60秒超时
                                                stream.read(&mut buffer)
                                            ) => {
                                                match read_result {
                                                    Ok(Ok(len)) => {
                                                        if len == 0 {
                                                            // 连接已关闭
                                                            log::debug!("[KCP] 来自 {} 的连接已关闭", ip_str);
                                                            println!("[KCP] 来自 {} 的连接已关闭", ip_str);
                                                            break;
                                                        }
                                                        
                                                        // 处理收到的KCP数据
                                                        log::debug!("[KCP] 从 {} 接收到 {} 字节数据", ip_str, len);
                                                        println!("[KCP] 从 {} 接收到 {} 字节数据", ip_str, len);
                                                        callback_clone(
                                                            remote_ip.as_ptr(),
                                                            buffer.as_ptr(),
                                                            len
                                                        );
                                                    }
                                                    Ok(Err(e)) => {
                                                        log::error!("[KCP] 从 {} 读取时出错: {}", ip_str, e);
                                                        println!("[KCP] 从 {} 读取时出错: {}", ip_str, e);
                                                        break;
                                                    }
                                                    Err(_) => {
                                                        // 读取超时
                                                        log::debug!("[KCP] 从 {} 读取超时", ip_str);
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    
                                    log::debug!("[FFI KCP Stream] Reader task for {} terminated", ip_str);
                                });
                            }
                            Ok(Err(e)) => {
                                log::error!("[KCP] 接受连接错误: {}", e);
                                println!("[KCP] 接受连接错误: {}", e);
                                // 短暂暂停避免CPU过载
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                            Err(_) => {
                                // 接受连接超时，继续循环
                            }
                        }
                    }
                }
            }
            
            log::info!("[KCP] 接收器已停止");
            println!("[KCP] 接收器已停止");
        });
    }

    #[cfg(feature = "use-kcp")]
    {
        wrapper.receiver_task = Some(normal_task);
    }
    
    #[cfg(not(feature = "use-kcp"))]
    {
        wrapper.receiver_task = Some(normal_task);
    }
    
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
            Err(_) => false,     // 超时
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
            match tokio::time::timeout(std::time::Duration::from_millis(actual_timeout), task).await
            {
                Ok(Ok(_)) => true,
                Ok(Err(_)) => false, // 任务出错或被取消
                Err(_) => false,     // 超时
            }
        });
    }

    // 3. 获取EndpointWrapper的所有权并释放资源
    let boxed_wrapper = unsafe { Box::from_raw(handle as *mut EndpointWrapper) };

    // 关闭所有KCP流
    #[cfg(feature = "use-kcp")]
    {
        if let Ok(mut kcp_streams) = boxed_wrapper.kcp_streams.lock() {
            kcp_streams.clear();
        }
    }

    // 4. 清理资源
    let EndpointWrapper {
        endpoint, runtime, ..
    } = *boxed_wrapper;

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

/// 获取可靠隧道信息
///
/// @param handle EndpointHandle
/// @param tunnel_type 输出参数，隧道类型（TCP、KCP或UDP）
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
        // 获取当前连接的节点信息
        let direct_nodes = wrapper.endpoint.node_context().get_direct_nodes();
        let peers_count = direct_nodes.len() as u32;
        
        // 分析节点使用的传输协议
        let mut has_tcp = false;
        let mut has_udp = false;
        
        for (node_addr, _) in direct_nodes {
            match node_addr {
                crate::tunnel::NodeAddress::Tcp(_) => has_tcp = true,
                crate::tunnel::NodeAddress::Udp(_) => has_udp = true,
            }
        }
        
        // 检查是否启用了KCP
        #[cfg(feature = "use-kcp")]
        {
            // 检查是否有活跃的KCP流
            let is_kcp_active = {
                if let Ok(kcp_streams) = wrapper.kcp_streams.lock() {
                    !kcp_streams.is_empty()
                } else {
                    false
                }
            };

            if is_kcp_active {
                // KCP优先级最高（因为它是在TCP/UDP之上的可靠传输层）
                unsafe { *tunnel_type = TransportType::Kcp as i32 };
                log::debug!("当前使用KCP传输");
            } else if has_tcp {
                // 有TCP连接但没有KCP
                unsafe { *tunnel_type = TransportType::Tcp as i32 };
                log::debug!("当前使用TCP传输");
            } else if has_udp {
                // 只有UDP连接
                unsafe { *tunnel_type = TransportType::Udp as i32 };
                log::debug!("当前使用UDP传输");
            } else {
                // 默认为TCP
                unsafe { *tunnel_type = TransportType::Tcp as i32 };
                log::debug!("没有活跃连接，默认为TCP");
            }
        }
        
        #[cfg(not(feature = "use-kcp"))]
        {
            // 没有启用KCP，只检查TCP和UDP
            if has_tcp {
                unsafe { *tunnel_type = TransportType::Tcp as i32 };
                log::debug!("当前使用TCP传输");
            } else if has_udp {
                unsafe { *tunnel_type = TransportType::Udp as i32 };
                log::debug!("当前使用UDP传输");
            } else {
                // 默认为TCP
                unsafe { *tunnel_type = TransportType::Tcp as i32 };
                log::debug!("没有活跃连接，默认为TCP");
            }
        }

        // 设置已连接的对等节点数量
        unsafe { *connected_peers = peers_count };
        log::debug!("已连接的对等节点数量: {}", peers_count);
    });

    true
}
