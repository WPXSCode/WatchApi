use anyhow::{anyhow, Result};
use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use watchapi_core::codex_files::CodexConfigBackup;
use watchapi_core::proxy::ProxyServer;
use watchapi_core::{AppConfig, HttpProbe, RuntimeCore};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("watch") => run_watch(&args[2..]),
        Some("proxy") => run_proxy(&args[2..]),
        _ => {
            eprintln!("用法:");
            eprintln!("  watchapi-cli watch --config <配置文件>");
            eprintln!("  watchapi-cli proxy --listen 127.0.0.1:8787 --upstream http://127.0.0.1:9000 --key <API_KEY>");
            Ok(())
        }
    }
}

fn run_watch(args: &[String]) -> Result<()> {
    let config_path = option_value(args, "--config").ok_or_else(|| anyhow!("缺少 --config"))?;
    let config = AppConfig::load(config_path)?;
    let _backup = if std::env::var("WATCHAPI_CODEX_BACKUP_OWNER").ok().as_deref() == Some("gui") {
        None
    } else {
        let mut backup = CodexConfigBackup::new(PathBuf::from(".watchapi-codex-backup.json"));
        backup.restore_pending()?;
        backup.capture(&[
            (
                config.codex_config_path.clone(),
                "codex_config_path".to_string(),
            ),
            (
                config.codex_auth_path.clone(),
                "codex_auth_path".to_string(),
            ),
        ])?;
        Some(BackupGuard(backup))
    };
    let interval = Duration::from_secs_f64(config.probe_interval_seconds);
    let probe = HttpProbe::new(config.request_timeout_seconds)?;
    let mut runtime = RuntimeCore::new(config);
    let tokio_runtime = tokio::runtime::Runtime::new()?;
    let running = Arc::new(AtomicBool::new(true));
    let running_for_handler = Arc::clone(&running);
    ctrlc::set_handler(move || {
        running_for_handler.store(false, Ordering::SeqCst);
    })?;
    while running.load(Ordering::SeqCst) {
        let selected = tokio_runtime.block_on(runtime.tick(&probe));
        if let Some(selected) = selected {
            println!("当前接口组：{}", selected.name);
        } else {
            println!("没有可用接口组");
        }
        thread::sleep(interval);
    }
    runtime.stop();
    Ok(())
}

struct BackupGuard(CodexConfigBackup);

impl Drop for BackupGuard {
    fn drop(&mut self) {
        let _ = self.0.restore();
    }
}

fn run_proxy(args: &[String]) -> Result<()> {
    let listen = option_value(args, "--listen").unwrap_or("127.0.0.1:8787");
    let upstream = option_value(args, "--upstream").ok_or_else(|| anyhow!("缺少 --upstream"))?;
    let key = option_value(args, "--key").ok_or_else(|| anyhow!("缺少 --key"))?;
    let (host, port) = listen
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("--listen 必须形如 127.0.0.1:8787"))?;
    let mut proxy = ProxyServer::new(
        host.to_string(),
        port.parse()?,
        upstream.to_string(),
        key.to_string(),
        true,
    );
    proxy.start()?;
    println!("本地中转代理已启动：http://{}:{}", host, proxy.port()?);
    let running = Arc::new(AtomicBool::new(true));
    let running_for_handler = Arc::clone(&running);
    ctrlc::set_handler(move || {
        running_for_handler.store(false, Ordering::SeqCst);
    })?;
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(3600));
    }
    proxy.stop();
    Ok(())
}

fn option_value<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == key)
        .map(|pair| pair[1].as_str())
}
