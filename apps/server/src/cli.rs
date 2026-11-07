//! Command-line entry points besides serving HTTP.
//!
//! `create-owner` creates the first operator account. There is no default
//! account and no web sign-up: until an operator runs this command on the
//! server, nobody can sign in. The password is read from the terminal, or
//! from the first line of standard input when it is not a terminal, and
//! never from command-line arguments (which other local users can read).
//!
//! `reset-password` is the recovery path for a forgotten password. It needs
//! the same server and database access as `create-owner`, reads the new
//! password the same way, and signs the account out everywhere.

use std::io::{BufRead, IsTerminal, Read};

use secrecy::SecretString;

pub const USAGE: &str = "\
Usage:
  supabase-dashboard-server                 Start the HTTP server
  supabase-dashboard-server create-owner --email <email> --name <display name>
                                            Create the first operator account
  supabase-dashboard-server reset-password --email <email>
                                            Set a new password for an account
  supabase-dashboard-server help            Show this message

Both commands read the password from the terminal, or from the first line
of standard input when input is piped. create-owner refuses to run once
any account exists. reset-password signs the account out of every session;
it does not re-enable a disabled account.";

/// Longest password line accepted from standard input.
const MAX_PASSWORD_LINE: u64 = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Serve,
    CreateOwner { email: String, name: String },
    ResetPassword { email: String },
    Help,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        None => Ok(Command::Serve),
        Some("help" | "--help" | "-h") => Ok(Command::Help),
        Some("create-owner") => {
            let mut email = None;
            let mut name = None;
            while let Some(flag) = args.next() {
                let slot = match flag.as_str() {
                    "--email" => &mut email,
                    "--name" => &mut name,
                    other => return Err(format!("unknown option `{other}`")),
                };
                let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
                if slot.replace(value).is_some() {
                    return Err(format!("{flag} given twice"));
                }
            }
            Ok(Command::CreateOwner {
                email: email.ok_or("--email is required")?,
                name: name.ok_or("--name is required")?,
            })
        }
        Some("reset-password") => {
            let mut email = None;
            while let Some(flag) = args.next() {
                if flag != "--email" {
                    return Err(format!("unknown option `{flag}`"));
                }
                let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
                if email.replace(value).is_some() {
                    return Err(format!("{flag} given twice"));
                }
            }
            Ok(Command::ResetPassword {
                email: email.ok_or("--email is required")?,
            })
        }
        Some(other) => Err(format!("unknown command `{other}`")),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordInputError {
    #[error("could not read the password: {0}")]
    Io(#[from] std::io::Error),
    #[error("the passwords do not match")]
    Mismatch,
    #[error("no password was provided on standard input")]
    Empty,
}

/// Reads a new password without echoing it.
pub fn read_new_password() -> Result<SecretString, PasswordInputError> {
    if std::io::stdin().is_terminal() {
        let first = rpassword::prompt_password("Password: ")?;
        let second = rpassword::prompt_password("Repeat password: ")?;
        if first != second {
            return Err(PasswordInputError::Mismatch);
        }
        return Ok(SecretString::from(first));
    }
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .take(MAX_PASSWORD_LINE)
        .read_line(&mut line)?;
    let password = line.trim_end_matches(['\n', '\r']);
    if password.is_empty() {
        return Err(PasswordInputError::Empty);
    }
    Ok(SecretString::from(password.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn no_arguments_serves() {
        assert_eq!(parse(args(&[])), Ok(Command::Serve));
    }

    #[test]
    fn create_owner_needs_email_and_name() {
        assert_eq!(
            parse(args(&[
                "create-owner",
                "--name",
                "Ada",
                "--email",
                "a@b.test"
            ])),
            Ok(Command::CreateOwner {
                email: "a@b.test".into(),
                name: "Ada".into()
            })
        );
        assert!(parse(args(&["create-owner", "--email", "a@b.test"])).is_err());
        assert!(parse(args(&["create-owner", "--email"])).is_err());
        assert!(parse(args(&["create-owner", "--email", "a", "--email", "b"])).is_err());
    }

    #[test]
    fn passwords_are_not_accepted_as_arguments() {
        let err = parse(args(&["create-owner", "--password", "hunter2hunter2"])).unwrap_err();
        assert!(err.contains("unknown option"));
        assert!(!err.contains("hunter2"));
    }

    #[test]
    fn reset_password_takes_only_an_email() {
        assert_eq!(
            parse(args(&["reset-password", "--email", "a@b.test"])),
            Ok(Command::ResetPassword {
                email: "a@b.test".into()
            })
        );
        assert!(parse(args(&["reset-password"])).is_err());
        let err = parse(args(&[
            "reset-password",
            "--email",
            "a@b.test",
            "--password",
            "hunter2hunter2",
        ]))
        .unwrap_err();
        assert!(err.contains("unknown option") && !err.contains("hunter2"));
    }

    #[test]
    fn unknown_commands_are_rejected() {
        assert!(parse(args(&["frobnicate"])).is_err());
        assert_eq!(parse(args(&["--help"])), Ok(Command::Help));
    }
}
