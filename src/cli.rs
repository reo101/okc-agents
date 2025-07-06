use clap::Parser;
use std::env;
use std::path::Path;

pub const AUTH_SOCK_ENV: &str = "SSH_AUTH_SOCK";
pub const AGENT_PID_ENV: &str = "SSH_AGENT_PID";

// A trait to identify structs that contain shell arguments.
pub trait HasShellArgs {
    fn shell_args(&self) -> &ShellArgs;
}

#[derive(Parser, Debug)]
pub struct ShellArgs {
    /// Generate C-shell commands on stdout.
    #[arg(short, long, group = "shell")]
    pub csh: bool,

    /// Generate Bourne shell (sh, bash, zsh) commands on stdout.
    #[arg(short = 's', long, group = "shell")]
    pub bash: bool,
}

#[derive(Parser, Debug)]
pub struct KillArgs {
    #[command(flatten)]
    pub shell: ShellArgs,
}

impl HasShellArgs for KillArgs {
    fn shell_args(&self) -> &ShellArgs {
        &self.shell
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Shell {
    Bourne,
    Csh,
}

impl<T: HasShellArgs> From<&T> for Shell {
    fn from(args: &T) -> Self {
        let shell_args = args.shell_args();
        if shell_args.csh {
            Shell::Csh
        } else if shell_args.bash {
            Shell::Bourne
        } else if let Ok(shell) = env::var("SHELL") {
            if shell.ends_with("csh") {
                Shell::Csh
            } else {
                Shell::Bourne
            }
        } else {
            Shell::Bourne
        }
    }
}

/// Prints the necessary environment variables for the user's shell to set.
pub fn print_shell_exports<T: HasShellArgs>(socket_path: &Path, pid: u32, args: &T) {
    let socket_str = socket_path.to_string_lossy();
    let shell_type: Shell = args.into();
    match shell_type {
        Shell::Csh => {
            println!("setenv {} '{}';", AUTH_SOCK_ENV, socket_str);
            println!("setenv {} {};", AGENT_PID_ENV, pid);
        }
        Shell::Bourne => {
            println!(
                "{}='{}'; export {};",
                AUTH_SOCK_ENV, socket_str, AUTH_SOCK_ENV
            );
            println!("{}={}; export {};", AGENT_PID_ENV, pid, AGENT_PID_ENV);
        }
    }
    println!("echo Agent pid {};", pid);
}

/// Prints the necessary commands for the user's shell to unset variables.
pub fn print_kill_vars(pid: i32, args: &KillArgs) {
    let shell_type: Shell = args.into();
    match shell_type {
        Shell::Csh => {
            println!("unsetenv {};", AUTH_SOCK_ENV);
            println!("unsetenv {};", AGENT_PID_ENV);
        }
        Shell::Bourne => {
            println!("unset {};", AUTH_SOCK_ENV);
            println!("unset {};", AGENT_PID_ENV);
        }
    }
    println!("echo Agent pid {} killed;", pid);
}
