use std::fmt;

/// Error del módulo cache.
#[derive(Debug)]
pub enum CacheError {
    Memoria(String),
    Sistema(String),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheError::Memoria(s) => write!(f, "Memoria: {}", s),
            CacheError::Sistema(s) => write!(f, "Sistema: {}", s),
        }
    }
}

/// Escribe `size` bytes de ruido para invalidar cachés CPU (L1/L2/L3).
/// En Windows usa VirtualAlloc + memset; en Linux mmap + memset.
pub fn cache_disrupt(size: usize) -> Result<u64, CacheError> {
    #[cfg(windows)]
    {
        use std::ptr;
        unsafe {
            let ptr = windows_sys::Win32::System::Memory::VirtualAlloc(
                std::ptr::null_mut(),
                size,
                windows_sys::Win32::System::Memory::MEM_COMMIT
                    | windows_sys::Win32::System::Memory::MEM_RESERVE,
                windows_sys::Win32::System::Memory::PAGE_READWRITE,
            );
            if ptr.is_null() {
                return Err(CacheError::Memoria("VirtualAlloc falló".into()));
            }
            // Escribir patrón rotativo (0xFF, 0xAA, 0x55) para asegurar
            // que todas las líneas de caché sean tocadas.
            let buf = std::slice::from_raw_parts_mut(ptr as *mut u8, size);
            for chunk in buf.chunks_mut(4096) {
                let patrón = match (chunk.as_ptr() as usize / 4096) % 3 {
                    0 => 0xFFu8,
                    1 => 0xAAu8,
                    _ => 0x55u8,
                };
                chunk.fill(patrón);
            }
            // Forzar escritura a memoria principal (evitar optimización del compilador)
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            let _ = &buf[0];

            windows_sys::Win32::System::Memory::VirtualFree(
                ptr,
                0,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
        Ok(size as u64)
    }

    #[cfg(not(windows))]
    {
        // Linux: mmap anónimo + memset
        #[cfg(target_os = "linux")]
        unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(CacheError::Memoria("mmap falló".into()));
            }
            std::ptr::write_bytes(ptr, 0xFF, size);
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            libc::munmap(ptr, size);
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Fallback: buffer del stack
            let mut buf = vec![0u8; size.min(1024 * 1024)];
            buf.fill(0xFF);
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        }
        Ok(size as u64)
    }
}
