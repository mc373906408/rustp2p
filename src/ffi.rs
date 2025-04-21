use std::ffi::{c_char, c_void, CStr};
use std::net::Ipv4Addr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;

use crate::protocol::node_id::GroupCode;
use crate::tunnel::PeerNodeAddress;
use crate::{Builder, Endpoint};

/// 为C语言导出的类型定义 - Endpoint句柄
#[allow(non_camel_case_types)]
pub type EndpointHandle = *mut c_void;

/// C语言接口的回调函数类型定义
/// @param source_ip 发送者的IP地址
/// @param message_ptr 消息内容的指针
/// @param message_len 消息长度
#[allow(non_camel_case_types)]
pub type MessageCallback = extern "C" fn(*const u8, *const u8, usize) -> ();

// 内部使用的类型别名
#[allow(dead_code)]
type EndpointHandleInternal = EndpointHandle;

/// 加密算法类型
#[repr(C)]
pub enum CipherType {
    None = 0,             // 不使用加密
    AesGcm = 1,           // AES-GCM 加密
    ChaCha20Poly1305 = 2, // ChaCha20-Poly1305 加密
}

/// 初始化函数
///
/// @param node_ip IPv4地址表示为32位无符号整数
/// @param tcp_port TCP端口
/// @param udp_port UDP端口
/// @param group_code 组代码
/// @param password 密码字符串
/// @param cipher_type 加密类型，参见 CipherType 枚举
/// @return 成功返回EndpointHandle，失败返回NULL
#[no_mangle]
pub extern "C" fn rustp2p_init(
    node_ip: u32,            // IPv4地址表示为32位无符号整数
    tcp_port: u16,           // TCP端口
    udp_port: u16,           // UDP端口
    group_code: u32,         // 组代码
    password: *const c_char, // 密码字符串
    cipher_type: i32,        // 加密类型
) -> EndpointHandle {
    // 安全转换
    if password.is_null() {
        return std::ptr::null_mut();
    }

    let _password_str = unsafe {
        match CStr::from_ptr(password).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    // 创建IPv4地址
    let node_id = Ipv4Addr::from(node_ip.to_be_bytes());

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
            // 创建通道用于通信
            let (shutdown_tx, shutdown_rx) = mpsc::channel();

            // 将Endpoint转换为可以传递给C的句柄
            let boxed = Box::new(EndpointWrapper {
                endpoint,
                runtime,
                shutdown_tx,
                shutdown_rx: Some(shutdown_rx),
                receiver_thread: None,
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

/// 发送消息
///
/// @param handle EndpointHandle
/// @param peer_ip 对等节点IP地址
/// @param data 消息数据
/// @param data_len 消息长度
/// @return 成功返回true，失败返回false
#[no_mangle]
pub extern "C" fn rustp2p_send_message(
    handle: EndpointHandle,
    peer_ip: u32,
    data: *const u8,
    data_len: usize,
) -> bool {
    if handle.is_null() || data.is_null() || data_len == 0 {
        return false;
    }

    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };
    let peer_id = Ipv4Addr::from(peer_ip.to_be_bytes());

    // 将C指针转换为Rust切片
    let buffer = unsafe { std::slice::from_raw_parts(data, data_len) };

    // 使用block_on执行异步发送
    let result = wrapper
        .runtime
        .block_on(async { wrapper.endpoint.send_to(buffer, peer_id).await });

    // 检查结果
    result.is_ok()
}

/// 启动接收循环
///
/// @param handle EndpointHandle
/// @param callback 消息回调函数
/// @return 成功返回true，失败返回false
#[no_mangle]
pub extern "C" fn rustp2p_start_receiver(
    handle: EndpointHandle,
    callback: MessageCallback,
) -> bool {
    if handle.is_null() {
        return false;
    }

    // 获取原始Endpoint
    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };

    // 已经有线程在运行，无需再次启动
    if wrapper.receiver_thread.is_some() {
        return true;
    }

    // 取出接收通道
    let shutdown_rx = match wrapper.shutdown_rx.take() {
        Some(rx) => rx,
        None => return false, // 已经启动过了但线程可能已结束
    };

    // 复制EndpointWrapper中的关键组件给线程使用
    let runtime = &wrapper.runtime;
    let endpoint = &wrapper.endpoint;

    // 创建线程安全的共享引用
    let endpoint_ref = endpoint as *const _ as usize;
    let runtime_ref = runtime as *const _ as usize;

    // 创建接收线程
    let handle = std::thread::spawn(move || {
        // 从引用恢复对象（不安全，但在FFI中通常需要这样做）
        let endpoint = unsafe { &*(endpoint_ref as *const Endpoint) };
        let runtime = unsafe { &*(runtime_ref as *const tokio::runtime::Runtime) };

        // 循环直到收到关闭信号
        loop {
            // 检查是否收到停止信号
            if shutdown_rx.try_recv().is_ok() {
                break;
            }

            // 使用非阻塞接收，最多等待100毫秒
            let recv_result = runtime.block_on(async {
                let timeout = tokio::time::sleep(std::time::Duration::from_millis(100));
                tokio::pin!(timeout);

                tokio::select! {
                    result = endpoint.recv_from() => Some(result),
                    _ = &mut timeout => None,
                }
            });

            match recv_result {
                Some(Ok((data, metadata))) => {
                    // 得到发送者IP
                    let sender_id = match TryInto::<Ipv4Addr>::try_into(metadata.src_id()) {
                        Ok(addr) => {
                            let ip_bytes = addr.octets();
                            u32::from_be_bytes(ip_bytes)
                        }
                        Err(_) => continue,
                    };

                    // 获取数据
                    let payload = data.payload();

                    // 调用回调函数
                    // 正确的参数顺序是：发送者IP、消息指针、消息长度

                    // 将IP地址转换为网络字节序（大端序）
                    let network_order_ip = sender_id.to_be();
                    let sender_ip_ptr = &network_order_ip as *const u32;

                    callback(sender_ip_ptr as *const u8, payload.as_ptr(), payload.len());
                }
                Some(Err(_)) => {
                    // 处理错误，但继续循环
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                None => {
                    // 超时，不做特殊处理，下次循环将再次检查停止信号
                }
            }
        }
    });

    // 保存线程句柄
    wrapper.receiver_thread = Some(handle);

    true
}

/// 停止接收循环
///
/// @param handle EndpointHandle
/// @return 成功返回true，失败返回false
#[no_mangle]
pub extern "C" fn rustp2p_stop_receiver(handle: EndpointHandle) -> bool {
    if handle.is_null() {
        return false;
    }

    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };

    // 如果没有线程运行，返回成功
    if wrapper.receiver_thread.is_none() {
        return true;
    }

    // 发送停止信号
    if wrapper.shutdown_tx.send(()).is_err() {
        // 通道已关闭，线程可能已经退出
        wrapper.receiver_thread = None;
        return true;
    }

    // 等待线程结束
    if let Some(thread) = wrapper.receiver_thread.take() {
        if thread.join().is_err() {
            // 线程可能已经panic
            return false;
        }
    }

    // 重新创建接收通道，以便下次可以再次启动
    let (tx, rx) = mpsc::channel();
    wrapper.shutdown_tx = tx;
    wrapper.shutdown_rx = Some(rx);

    true
}

/// 释放资源
///
/// @param handle EndpointHandle
#[no_mangle]
pub extern "C" fn rustp2p_cleanup(handle: EndpointHandle) {
    if !handle.is_null() {
        unsafe {
            // 首先停止接收线程
            let wrapper = &mut *(handle as *mut EndpointWrapper);

            // 如果有线程在运行，发送停止信号并等待结束
            if wrapper.receiver_thread.is_some() {
                let _ = rustp2p_stop_receiver(handle);
            }

            // 将指针转换回Box并释放
            let _ = Box::from_raw(handle as *mut EndpointWrapper);
        }
    }
}

/// 主动触发ID路由查询以建立路由表
/// 自动尝试建立到特定目标节点的路由并验证连接
///
/// @param handle EndpointHandle
/// @param target_id 目标节点ID
/// @param max_attempts 最大尝试次数
/// @return 成功返回true，失败返回false
#[no_mangle]
pub extern "C" fn rustp2p_trigger_route_discovery(
    handle: EndpointHandle,
    target_id: u32,
    max_attempts: i32,
) -> bool {
    if handle.is_null() || max_attempts <= 0 {
        return false;
    }

    let wrapper = unsafe { &mut *(handle as *mut EndpointWrapper) };

    // 尝试不同的方式来表示NodeID
    let target_ip = Ipv4Addr::from(target_id.to_be_bytes());
    let target_node_id_ip = crate::protocol::node_id::NodeID::from(target_ip);
    let target_node_id_direct = crate::protocol::node_id::NodeID::from(target_id);

    // 使用block_on执行异步路由发现
    wrapper.runtime.block_on(async {
        // 获取节点上下文用于路由操作
        let node_context = wrapper.endpoint.node_context();

        // 首先更新直连节点
        let _ = node_context.update_direct_nodes0().await;

        // 等待网络建立
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // 尝试发送消息
        if let Ok(_) = wrapper.endpoint.send_to(b"hello from ip", target_ip).await {
            return true;
        }

        if let Ok(_) = wrapper
            .endpoint
            .send_to(b"hello from direct", target_node_id_direct)
            .await
        {
            return true;
        }

        // 如果简单方法失败，使用更复杂的方法
        for attempt in 1..=max_attempts {
            // 尝试广播来触发路由发现
            let _ = wrapper.endpoint.broadcast(b"hello broadcast").await;

            // 等待路由可能建立
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            // 尝试发送Echo请求以触发路由建立
            let mut echo_packet = wrapper.endpoint.allocate_send_packet();
            echo_packet.set_protocol(crate::protocol::protocol_type::ProtocolType::EchoRequest);
            echo_packet.set_ttl(20); // 设置较大的TTL

            let _ = wrapper
                .endpoint
                .send_packet_to(echo_packet, &target_node_id_ip)
                .await;

            // 等待路由可能建立
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            // 尝试直接发送消息
            if let Ok(_) = wrapper
                .endpoint
                .send_to(b"test after echo", target_ip)
                .await
            {
                return true;
            }

            if let Ok(_) = wrapper
                .endpoint
                .send_to(b"test after echo", target_node_id_direct)
                .await
            {
                return true;
            }

            // 如果是最后一次尝试，则广播消息
            if attempt == max_attempts {
                let final_msg = b"final broadcast attempt";
                let mut direct_packet = wrapper.endpoint.allocate_send_packet();
                direct_packet.set_payload(final_msg);
                direct_packet.set_dest_id(&target_node_id_ip);

                let _ = wrapper.endpoint.broadcast_packet(direct_packet).await;
            }

            // 如果不是最后一次尝试，等待后重试
            if attempt < max_attempts {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }

        false
    })
}

// Endpoint包装器，包含Endpoint和运行时
struct EndpointWrapper {
    endpoint: Endpoint,
    runtime: tokio::runtime::Runtime,
    shutdown_tx: Sender<()>,                 // 用于发送停止信号
    shutdown_rx: Option<Receiver<()>>,       // 用于接收停止信号
    receiver_thread: Option<JoinHandle<()>>, // 接收线程句柄
}

// 为了使C代码能够使用PeerNodeAddress::from_str
trait FromStr {
    type Err;
    fn from_str(s: &str) -> Result<Self, Self::Err>
    where
        Self: Sized;
}

impl FromStr for PeerNodeAddress {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse() {
            Ok(addr) => Ok(addr),
            Err(_) => Err(()),
        }
    }
}
