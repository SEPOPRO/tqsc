use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::exceptions::PyRuntimeError;

pub mod syscall;
pub mod cache;
pub mod pid_sig;

/// SyscallMonitor: enumera procesos del sistema.
/// Retorna lista de dicts Python.
#[pyfunction]
fn enum_processes(py: Python<'_>) -> PyResult<PyObject> {
    let procs = syscall::enum_processes()
        .map_err(|e| PyRuntimeError::new_err(format!("enum_processes: {}", e)))?;
    let list = procs.into_iter()
        .map(|p| -> PyResult<PyObject> {
            let d = PyDict::new(py);
            d.set_item("pid", p.pid)?;
            d.set_item("nombre", &p.nombre)?;
            d.set_item("exe", &p.exe)?;
            d.set_item("reflectivo", p.reflectivo)?;
            Ok(d.into())
        })
        .collect::<PyResult<Vec<_>>>()?;
    Ok(list.into_py(py))
}

/// CacheDisruptor: invalida cachés CPU.
#[pyfunction]
fn cache_disrupt(size_mb: Option<u32>) -> PyResult<u64> {
    let size = size_mb.unwrap_or(1) as usize * 1024 * 1024;
    cache::cache_disrupt(size)
        .map_err(|e| PyRuntimeError::new_err(format!("cache_disrupt: {}", e)))
}

/// PIDSignature: hashea proceso en memoria.
#[pyfunction]
fn pid_signature(py: Python<'_>, pid: u32) -> PyResult<PyObject> {
    let sig = pid_sig::pid_signature(pid)
        .map_err(|e| PyRuntimeError::new_err(format!("pid_signature: {}", e)))?;
    let d = PyDict::new(py);
    d.set_item("pid", sig.pid)?;
    d.set_item("exe", &sig.exe)?;
    d.set_item("hash_disco", &sig.hash_disco)?;
    d.set_item("reflectivo", sig.reflectivo)?;
    Ok(d.into())
}

/// ReadProcessMemory: lee memoria de un proceso.
#[pyfunction]
fn read_process_memory(pid: u32, size: usize) -> PyResult<Vec<u8>> {
    pid_sig::read_process_memory(pid, size)
        .map_err(|e| PyRuntimeError::new_err(format!("read_process_memory: {}", e)))
}

/// Info del módulo nativo.
#[pyfunction]
fn info(py: Python<'_>) -> PyResult<PyObject> {
    let d = PyDict::new(py);
    d.set_item("version", env!("CARGO_PKG_VERSION"))?;
    d.set_item("rustc", "1.97.0")?;
    d.set_item("platform", std::env::consts::OS)?;
    Ok(d.into())
}

#[pymodule]
fn tqsc_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(enum_processes, m)?)?;
    m.add_function(wrap_pyfunction!(cache_disrupt, m)?)?;
    m.add_function(wrap_pyfunction!(pid_signature, m)?)?;
    m.add_function(wrap_pyfunction!(read_process_memory, m)?)?;
    m.add_function(wrap_pyfunction!(info, m)?)?;
    Ok(())
}
