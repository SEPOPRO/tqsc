use std::fmt;

#[derive(Debug)]
pub enum PidError {
    NoProceso(String),
    AccesoDenegado(String),
    Sistema(String),
}

impl fmt::Display for PidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PidError::NoProceso(s) => write!(f, "No proceso: {}", s),
            PidError::AccesoDenegado(s) => write!(f, "Acceso denegado: {}", s),
            PidError::Sistema(s) => write!(f, "Sistema: {}", s),
        }
    }
}

#[derive(Debug)]
pub struct PidSignature {
    pub pid: u32,
    pub exe: String,
    pub hash_disco: String,
    pub reflectivo: bool,
}

pub fn read_process_memory(pid: u32, size: usize) -> Result<Vec<u8>, PidError> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows_sys::Win32::Foundation::CloseHandle;

        const PROCESS_VM_READ: u32 = 0x0010;
        let flags = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

        unsafe {
            // SAFETY: OpenProcess recibe pid del usuario, riesgo de TOCTOU.
            let handle = OpenProcess(flags, 0, pid);
            if handle.is_null() {
                return Err(PidError::AccesoDenegado(
                    format!("OpenProcess({}) falló", pid),
                ));
            }

            let mut buf = vec![0u8; size];
            let mut bytes_read: usize = 0;

            // SAFETY: ReadProcessMemory es inherentemente inseguro.
            // Solo leemos, no escribimos. El tamaño está acotado.
            let ok = ReadProcessMemory(
                handle,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut _,
                size,
                &mut bytes_read,
            );

            CloseHandle(handle);

            if ok == 0 {
                return Err(PidError::AccesoDenegado(
                    format!("ReadProcessMemory({}) falló", pid),
                ));
            }

            buf.truncate(bytes_read);
            Ok(buf)
        }
    }

    #[cfg(not(windows))]
    {
        let _ = pid;
        Err(PidError::Sistema("PIDSignature solo en Windows".into()))
    }
}

pub fn pid_signature(pid: u32) -> Result<PidSignature, PidError> {
    let nombre = get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));
    let exe = format!("C:\\Windows\\System32\\{}", nombre);

    let hash_disco = match std::fs::read(&exe) {
        Ok(data) => {
            let h = blake3_hash(&data);
            format!("{:016x}", h)
        }
        Err(_) => {
            let mem = read_process_memory(pid, 4096)?;
            let h = blake3_hash(&mem);
            return Ok(PidSignature {
                pid,
                exe: String::new(),
                hash_disco: format!("MEM:{:016x}", h),
                reflectivo: true,
            });
        }
    };

    Ok(PidSignature {
        pid,
        exe,
        hash_disco,
        reflectivo: false,
    })
}

fn blake3_hash(data: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    let mut h = DefaultHasher::new();
    h.write(data);
    h.finish()
}

#[cfg(windows)]
fn get_process_name(pid: u32) -> Option<String> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS, PROCESSENTRY32W,
    };
    use windows_sys::Win32::Foundation::CloseHandle;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return None;
        }

        loop {
            if entry.th32ProcessID == pid {
                let nombre = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_string();
                CloseHandle(snapshot);
                return Some(nombre);
            }
            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }
        CloseHandle(snapshot);
        None
    }
}

#[cfg(not(windows))]
fn get_process_name(pid: u32) -> Option<String> {
    let _ = pid;
    None
}
