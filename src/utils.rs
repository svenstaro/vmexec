use tokio::process::Command;

/// Get the full command that would be run
pub fn full_cmd(cmd: &Command) -> String {
    let program_str = cmd.as_std().get_program().to_string_lossy();
    let args_str = cmd
        .as_std()
        .get_args()
        .map(|x| x.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    format!("{program_str} {args_str}")
}
