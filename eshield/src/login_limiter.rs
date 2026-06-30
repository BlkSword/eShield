use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 最大允许连续失败次数。
const MAX_ATTEMPTS: usize = 5;
/// 失败计数窗口时长。
const WINDOW: Duration = Duration::from_secs(60);
/// 触发锁定后的封禁时长。
const LOCKOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
struct AttemptEntry {
    attempts: Vec<Instant>,
    locked_until: Option<Instant>,
}

/// 登录接口暴力破解防护：按源 IP 统计失败次数并临时锁定。
#[derive(Debug, Default)]
pub struct LoginLimiter {
    inner: Mutex<HashMap<IpAddr, AttemptEntry>>,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// 检查该 IP 当前是否允许尝试登录。
    /// 若已被锁定或本次失败后将达到阈值，返回错误信息。
    pub fn check(&self, ip: IpAddr) -> Result<(), &'static str> {
        let now = Instant::now();
        let mut guard = self.inner.lock().unwrap();
        let entry = guard.entry(ip).or_insert_with(|| AttemptEntry {
            attempts: Vec::new(),
            locked_until: None,
        });

        // 清除过期失败记录
        entry.attempts.retain(|t| now.duration_since(*t) < WINDOW);

        // 检查是否仍处于锁定状态
        if let Some(locked_until) = entry.locked_until {
            if now < locked_until {
                return Err("too many failed login attempts, please try again later");
            }
            // 锁定已过期，自动解锁
            entry.locked_until = None;
        }

        // 如果当前失败次数已达上限，立即锁定并拒绝
        if entry.attempts.len() >= MAX_ATTEMPTS {
            entry.locked_until = Some(now + LOCKOUT);
            return Err("too many failed login attempts, please try again later");
        }

        Ok(())
    }

    /// 记录一次失败的登录尝试。
    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut guard = self.inner.lock().unwrap();
        let entry = guard.entry(ip).or_insert_with(|| AttemptEntry {
            attempts: Vec::new(),
            locked_until: None,
        });
        entry.attempts.retain(|t| now.duration_since(*t) < WINDOW);
        entry.attempts.push(now);
        if entry.attempts.len() >= MAX_ATTEMPTS {
            entry.locked_until = Some(now + LOCKOUT);
        }
    }

    /// 记录一次成功的登录，清除该 IP 的失败记录。
    pub fn record_success(&self, ip: IpAddr) {
        let mut guard = self.inner.lock().unwrap();
        guard.remove(&ip);
    }
}
