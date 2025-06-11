use std::arch::naked_asm;
use std::ffi::{CStr, CString};
use std::fs;
use std::io::Result as Res;
use std::os::raw::{c_char, c_void};
use winapi::{
    shared::{
        minwindef::{BOOL, DWORD, FALSE, HINSTANCE, LPVOID, TRUE},
        ntdef::HANDLE,
    },
    um::{
        consoleapi::AllocConsole,
        libloaderapi::{GetProcAddress, LoadLibraryA},
        processenv::SetStdHandle,
        winbase::STD_OUTPUT_HANDLE,
    },
};

static mut FUNC_1: *const c_void = std::ptr::null();
static mut FUNC_2: *const c_void = std::ptr::null();
static mut FUNC_3: *const c_void = std::ptr::null();
static mut FUNC_4: *const c_void = std::ptr::null();
static mut FUNC_5: *const c_void = std::ptr::null();

static mut HAS_CONSOLE: bool = false;

#[no_mangle]
#[allow(unused_variables)]
pub extern "system" fn DllMain(
    dll_module: HINSTANCE,
    call_reason: DWORD,
    reserved: LPVOID,
) -> BOOL {
    const DLL_PROCESS_ATTACH: DWORD = 1;

    match call_reason {
        DLL_PROCESS_ATTACH => init(),
        _ => TRUE,
    }
}

macro_rules! error {
	($($arg:tt)*) => {
		unsafe {
			if !HAS_CONSOLE {
				AllocConsole();
				SetStdHandle(STD_OUTPUT_HANDLE, 0 as HANDLE);
				HAS_CONSOLE = true;
			}
			eprintln!($($arg)*);
		}
	}
}

unsafe fn s(bytes: &[u8]) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(bytes).as_ptr()
}

fn init() -> BOOL {
    let dinput = unsafe { LoadLibraryA(s(b"C:\\Windows\\System32\\dinput8.dll\0")) };
    if dinput.is_null() {
        error!("modloader error: could not load real dinput8");
        return FALSE;
    }
    unsafe {
        FUNC_1 = std::mem::transmute(GetProcAddress(dinput, s(b"DirectInput8Create\0")));
        FUNC_2 = std::mem::transmute(GetProcAddress(dinput, s(b"DllCanUnloadNow\0")));
        FUNC_3 = std::mem::transmute(GetProcAddress(dinput, s(b"DllGetClassObject\0")));
        FUNC_4 = std::mem::transmute(GetProcAddress(dinput, s(b"DllRegisterServer\0")));
        FUNC_5 = std::mem::transmute(GetProcAddress(dinput, s(b"DllUnregisterServer\0")));
    }

    match load_mods() {
        Ok(()) => TRUE,
        Err(e) => {
            error!("modloader error: {}", e);
            FALSE
        }
    }
}

fn load_mods() -> Res<()> {
    for entry in fs::read_dir("mods")? {
        let entry = entry.unwrap();
        if entry.file_type()?.is_dir() {
            let mut path = entry.path();
            path.push("mod.dll");
            let string = path.as_os_str().to_str().unwrap();
            let cstring = CString::new(string)?;
            let m = unsafe { LoadLibraryA(cstring.as_c_str().as_ptr()) };
            if m.is_null() {
                error!("modloader error: could not load mod: {string}");
            } else {
                println!("modloader: sucessfully loaded {string}");
            }
        }
    }

    Ok(())
}

#[unsafe(naked)]
#[no_mangle]
pub extern "system" fn DirectInput8Create() {
    naked_asm!("jmp [{}]", sym FUNC_1);
}

#[unsafe(naked)]
#[no_mangle]
pub extern "system" fn DllCanUnloadNow() {
    naked_asm!("jmp [{}]", sym FUNC_2);
}

#[unsafe(naked)]
#[no_mangle]
pub extern "system" fn DllGetClassObject() {
    naked_asm!("jmp [{}]", sym FUNC_3);
}

#[unsafe(naked)]
#[no_mangle]
pub extern "system" fn DllRegisterServer() {
    naked_asm!("jmp [{}]", sym FUNC_4);
}

#[unsafe(naked)]
#[no_mangle]
pub extern "system" fn DllUnregisterServer() {
    naked_asm!("jmp [{}]", sym FUNC_5);
}
