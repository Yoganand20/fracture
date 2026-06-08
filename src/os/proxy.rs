use std::io;
use tracing::{debug, error, info};

#[cfg(target_os = "windows")]
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
#[cfg(target_os = "windows")]
use winreg::RegKey;

pub struct SystemProxy;

impl SystemProxy {
    /// Enables the system-wide proxy on Windows
    #[cfg(target_os = "windows")]
    pub fn enable(port: u16) -> io::Result<()> {
        let proxy_server = format!("127.0.0.1:{}", port);
        debug!(
            port,
            key_path = "Internet Settings",
            "Attempting to modify system-wide Windows registry proxy configurations"
        );

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

        let key = hkcu.open_subkey_with_flags(path, KEY_READ | KEY_WRITE).map_err(|e| {
            error!(error = %e, path = %path, "Failed to open network settings registry keys with write permissions");
            e
        })?;

        // Turn the proxy ON
        key.set_value("ProxyEnable", &1u32).map_err(|e| {
            error!(error = %e, "Failed to apply 'ProxyEnable' state alteration inside target registry subkey");
            e
        })?;

        // Point the proxy to our fracture instance
        key.set_value("ProxyServer", &proxy_server).map_err(|e| {
            error!(error = %e, target_proxy = %proxy_server, "Failed to write target fallback connection address to 'ProxyServer' key");
            e
        })?;

        info!(target = %proxy_server, "System-wide network settings updated: runtime proxy is now ENABLED");

        // Note: For Chrome/Edge to detect this instantly without a restart,
        // we'd eventually want to trigger a wininet InternetSetOption refresh here.
        Ok(())
    }

    /// Disables the system-wide proxy on Windows
    #[cfg(target_os = "windows")]
    pub fn disable() -> io::Result<()> {
        debug!(
            key_path = "Internet Settings",
            "Attempting to purge automated system-wide proxy configurations"
        );

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

        let key = hkcu.open_subkey_with_flags(path, KEY_READ | KEY_WRITE).map_err(|e| {
            error!(error = %e, path = %path, "Failed to securely gain modifications access over internet registry variables");
            e
        })?;

        // Turn the proxy OFF
        key.set_value("ProxyEnable", &0u32).map_err(|e| {
            error!(error = %e, "Critical error mapping pipeline down: registry rewrite execution failed for 'ProxyEnable'");
            e
        })?;

        info!(
            "System-wide network adjustments written successfully: runtime proxy is now DISABLED"
        );
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn enable(port: u16) -> io::Result<()> {
        warn!(
            forwarding_port = port,
            manual_fallback = %format!("127.0.0.1:{}", port),
            "Automated system proxy toggling execution hook skipped: target operating system architecture is currently unsupported"
        );
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn disable() -> io::Result<()> {
        warn!("System proxy configuration teardown skipped: environment relies on cross-platform abstractions. Please verify manual proxy cleanup sequences.");
        Ok(())
    }
}
