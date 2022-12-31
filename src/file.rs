use std::path::{self, Path};

pub trait DisplayName {
    fn display_name(&self) -> path::Display;
}

impl<T> DisplayName for T
where
    T: AsRef<Path>,
{
    fn display_name(&self) -> path::Display {
        let path = self.as_ref();
        let name = path.file_name().unwrap_or(path.as_os_str());
        Path::display(name.as_ref())
    }
}
