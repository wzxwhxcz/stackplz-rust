//! RPC server for remote breakpoint control. Mirrors `user/rpc/rpc.go`.
//!
//! Provides a TCP server that accepts JSON commands to:
//! - Add/remove hardware breakpoints dynamically
//! - Query active breakpoints
//! - Control breakpoint lifecycle

use crate::logger::Logger;
use crate::module::brk::{BrkConfig, BrkType, BrkLen};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// RPC command types
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "cmd")]
enum RpcCommand {
    #[serde(rename = "add_brk")]
    AddBreakpoint { pid: i32, addr: u64, brk_type: String, brk_len: u32 },
    
    #[serde(rename = "del_brk")]
    DeleteBreakpoint { id: u32 },
    
    #[serde(rename = "list_brk")]
    ListBreakpoints,
    
    #[serde(rename = "ping")]
    Ping,
}

/// RPC response
#[derive(Debug, Serialize)]
struct RpcResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

impl RpcResponse {
    fn success(message: String) -> Self {
        Self {
            success: true,
            message,
            data: None,
        }
    }

    fn success_with_data(message: String, data: serde_json::Value) -> Self {
        Self {
            success: true,
            message,
            data: Some(data),
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            message,
            data: None,
        }
    }
}

/// Active breakpoint entry
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BreakpointEntry {
    id: u32,
    config: BrkConfig,
}

pub struct RpcServer {
    addr: String,
    breakpoints: Arc<Mutex<HashMap<u32, BreakpointEntry>>>,
    next_id: Arc<Mutex<u32>>,
}

impl RpcServer {
    pub fn new(addr: String) -> Self {
        Self {
            addr,
            breakpoints: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }

    pub fn run(&self, logger: Arc<Logger>) -> Result<()> {
        logger.println(&format!("RpcServer: starting on {}", self.addr));

        let listener = TcpListener::bind(&self.addr)?;
        logger.println(&format!("RpcServer: listening on {}", self.addr));

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let logger = Arc::clone(&logger);
                    let breakpoints = Arc::clone(&self.breakpoints);
                    let next_id = Arc::clone(&self.next_id);
                    
                    std::thread::spawn(move || {
                        if let Err(e) = Self::handle_client(stream, logger.clone(), breakpoints, next_id) {
                            logger.println(&format!("RpcServer: client error: {}", e));
                        }
                    });
                }
                Err(e) => {
                    logger.println(&format!("RpcServer: accept error: {}", e));
                }
            }
        }

        Ok(())
    }

    fn handle_client(
        mut stream: TcpStream,
        logger: Arc<Logger>,
        breakpoints: Arc<Mutex<HashMap<u32, BreakpointEntry>>>,
        next_id: Arc<Mutex<u32>>,
    ) -> Result<()> {
        let peer = stream.peer_addr()?;
        logger.println(&format!("RpcServer: client connected from {}", peer));

        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();

        while reader.read_line(&mut line)? > 0 {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                line.clear();
                continue;
            }

            let response = match serde_json::from_str::<RpcCommand>(trimmed) {
                Ok(cmd) => Self::handle_command(cmd, &logger, &breakpoints, &next_id),
                Err(e) => RpcResponse::error(format!("invalid JSON: {}", e)),
            };

            let response_json = serde_json::to_string(&response)?;
            writeln!(stream, "{}", response_json)?;
            stream.flush()?;

            line.clear();
        }

        logger.println(&format!("RpcServer: client disconnected from {}", peer));
        Ok(())
    }

    fn handle_command(
        cmd: RpcCommand,
        logger: &Arc<Logger>,
        breakpoints: &Arc<Mutex<HashMap<u32, BreakpointEntry>>>,
        next_id: &Arc<Mutex<u32>>,
    ) -> RpcResponse {
        match cmd {
            RpcCommand::Ping => {
                RpcResponse::success("pong".to_string())
            }

            RpcCommand::AddBreakpoint { pid, addr, brk_type, brk_len } => {
                let brk_type_enum = match brk_type.as_str() {
                    "x" | "exec" => BrkType::Execute,
                    "w" | "write" => BrkType::Write,
                    "rw" | "readwrite" => BrkType::ReadWrite,
                    _ => return RpcResponse::error(format!("invalid brk_type: {}", brk_type)),
                };

                let brk_len_enum = match brk_len {
                    1 => BrkLen::Len1,
                    2 => BrkLen::Len2,
                    4 => BrkLen::Len4,
                    8 => BrkLen::Len8,
                    _ => return RpcResponse::error(format!("invalid brk_len: {}", brk_len)),
                };

                let config = BrkConfig::new(pid, addr)
                    .with_type(brk_type_enum)
                    .with_len(brk_len_enum);

                let id = {
                    let mut next = next_id.lock().unwrap();
                    let current = *next;
                    *next += 1;
                    current
                };

                let entry = BreakpointEntry { id, config };
                
                breakpoints.lock().unwrap().insert(id, entry.clone());

                logger.println(&format!(
                    "RpcServer: added breakpoint id={} pid={} addr=0x{:x}",
                    id, pid, addr
                ));

                RpcResponse::success_with_data(
                    format!("breakpoint added with id {}", id),
                    serde_json::json!({ "id": id }),
                )
            }

            RpcCommand::DeleteBreakpoint { id } => {
                let mut brks = breakpoints.lock().unwrap();
                if brks.remove(&id).is_some() {
                    logger.println(&format!("RpcServer: removed breakpoint id={}", id));
                    RpcResponse::success(format!("breakpoint {} removed", id))
                } else {
                    RpcResponse::error(format!("breakpoint {} not found", id))
                }
            }

            RpcCommand::ListBreakpoints => {
                let brks = breakpoints.lock().unwrap();
                let list: Vec<_> = brks.iter().map(|(id, entry)| {
                    serde_json::json!({
                        "id": id,
                        "pid": entry.config.pid,
                        "addr": format!("0x{:x}", entry.config.addr),
                        "type": format!("{:?}", entry.config.brk_type),
                        "len": entry.config.brk_len as u32,
                    })
                }).collect();

                RpcResponse::success_with_data(
                    format!("{} active breakpoints", list.len()),
                    serde_json::json!(list),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_command_deserialize() {
        let json = r#"{"cmd":"ping"}"#;
        let cmd: RpcCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, RpcCommand::Ping));

        let json = r#"{"cmd":"add_brk","pid":1234,"addr":1048576,"brk_type":"w","brk_len":8}"#;
        let cmd: RpcCommand = serde_json::from_str(json).unwrap();
        match cmd {
            RpcCommand::AddBreakpoint { pid, addr, .. } => {
                assert_eq!(pid, 1234);
                assert_eq!(addr, 1048576);
            }
            _ => panic!("wrong command type"),
        }
    }

    #[test]
    fn rpc_response_serialize() {
        let resp = RpcResponse::success("ok".to_string());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"message\":\"ok\""));
    }
}
