use std::{fmt::Display, io};

use crate::{file::DisplayName, manifest::ManifestErr, Conflict};

#[derive(Debug)]
pub enum Error {
    Manifest(ManifestErr),
    Conflict(Vec<Conflict>),
    Io(io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Manifest(e) => e.fmt(f),
            Error::Conflict(conflicts) => {
                f.write_str("encountered file conflicts:\n\n")?;
                for conflict in conflicts {
                    writeln!(f, "  {}", conflict.target.display_name())?;
                }
                Ok(())
            }
            Error::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<ManifestErr> for Error {
    fn from(e: ManifestErr) -> Self {
        Error::Manifest(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
