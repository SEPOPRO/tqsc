use std::fmt;

/// Error del módulo syscall.
#[derive(Debug)]
pub enum SyscallError {
    NoProcesos(String),
    AccesoDenegado(String),
    Sistema(String),
}

impl fmt::Display for SyscallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyscallError::NoProcesos(s) => write!(f, "Sin procesos: {}", s),
            SyscallError::AccesoDenegado(s) => write!(f, "Acceso denegado: {}", s),
            SyscallError::Sistema(s) => write!(f, "Error sistema: {}", s),
        }
    }
}

/// Información de un proceso.
#[derive(Debug)]
pub struct ProcesoInfo {
    pub pid: u32,
    pub nombre: String,
    pub exe: String,
    pub reflectivo: bool,
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ptr;

    pub fn enum_processes() -> Result<Vec<ProcesoInfo>, SyscallError> {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS, PROCESSENTRY32W,
        };

        let mut procesos = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                return Err(SyscallError::Sistema("CreateToolhelp32Snapshot falló".into()));
            }

            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry) == 0 {
                windows_sys::Win32::Foundation::CloseHandle(snapshot);
                return Err(SyscallError::NoProcesos("Process32FirstW falló".into()));
            }

            loop {
                let pid = entry.th32ProcessID;
                let nombre = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_string();
                let exe = format!("C:\\Windows\\System32\\{}", nombre);
                let reflectivo = exe.is_empty();

                procesos.push(ProcesoInfo { pid, nombre, exe, reflectivo });

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }

            windows_sys::Win32::Foundation::CloseHandle(snapshot);
        }

        Ok(procesos)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    pub fn enum_processes() -> Result<Vec<ProcesoInfo>, SyscallError> {
        Err(SyscallError::Sistema("SyscallMonitor solo soportado en Windows".into()))
    }
}

pub use platform::enum_processes;
