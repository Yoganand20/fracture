use std::io;

#[cfg(target_os = "windows")]
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
#[cfg(target_os = "windows")]
use winreg::RegKey;

pub struct SystemProxy;

impl SystemProxy {
    /// Enables the system-wide proxy on Windows
    #[cfg(target_os = "windows")]
    pub fn enable(port: u16) -> io::Result<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
        
        let key = hkcu.open_subkey_with_flags(path, KEY_READ | KEY_WRITE)?;

        // Turn the proxy ON
        key.set_value("ProxyEnable", &1u32)?;
        
        // Point the proxy to our GreenTunnel instance
        let proxy_server = format!("127.0.0.1:{}", port);
        key.set_value("ProxyServer", &proxy_server)?;

        println!("System proxy ENABLED on {}", proxy_server);
        
        // Note: For Chrome/Edge to detect this instantly without a restart, 
        // we'd eventually want to trigger a wininet InternetSetOption refresh here.
        Ok(())
    }

    /// Disables the system-wide proxy on Windows
    #[cfg(target_os = "windows")]
    pub fn disable() -> io::Result<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
        
        let key = hkcu.open_subkey_with_flags(path, KEY_READ | KEY_WRITE)?;

        // Turn the proxy OFF
        key.set_value("ProxyEnable", &0u32)?;

        println!("System proxy DISABLED");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn enable(port: u16) -> io::Result<()> {
        println!("System proxy toggling is currently only implemented for Windows.");
        println!("Please set your system proxy manually to: 127.0.0.1:{}", port);
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn disable() -> io::Result<()> {
        println!("System proxy toggling is currently only implemented for Windows.");
        println!("Please disable your proxy manually in system settings.");
        Ok(())
    }
}