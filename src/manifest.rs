use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    fs::File,
    io,
    path::{Path, PathBuf},
};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha1_smol::Sha1;

type Result<T, E = ManifestErr> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum ManifestErr {
    #[error("manifest exists: {0}")]
    ManifestExists(PathDisplay),

    #[error("not a file: {0}")]
    NotAFile(PathDisplay),

    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug)]
pub struct PathDisplay(PathBuf);

impl Display for PathDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

impl<T: Into<PathBuf>> From<T> for PathDisplay {
    fn from(path: T) -> Self {
        PathDisplay(path.into())
    }
}

#[derive(Clone, Debug)]
pub struct ManifestItem {
    pub path: PathBuf,
    pub name: String,
    pub hash: String,
}

impl ManifestItem {
    pub fn from_path(root: &Path, path: &Path) -> Result<Self, ManifestErr> {
        if !path.is_file() {
            return Err(ManifestErr::NotAFile(path.into()));
        }

        Ok(Self {
            path: path.strip_prefix(root).unwrap_or(path).into(),
            name: path.file_name().unwrap().to_str().unwrap().to_owned(),
            hash: crate::get_hash(path)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Action {
    Check,
    Cleanup,
}

pub struct ManifestBuilder {
    root: PathBuf,
    items: Vec<ManifestItem>,
}

impl ManifestBuilder {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            root: path.into(),
            items: Default::default(),
        }
    }

    pub fn build_item(&self, path: &Path) -> Result<ManifestItem> {
        ManifestItem::from_path(&self.root, path)
    }

    pub fn push(&mut self, item: ManifestItem) {
        self.items.push(item);
    }

    /// Gets the metahash for this digest
    ///
    /// The "metahash" is the sha1 hash of the blake3 hashes of all objects recorded in this
    /// manifest. The sole purpose of this is to ensure that manifests describing identical
    /// items have identical names and that unique manifests have unique names; it is not essential
    /// that this hash be secure.
    pub fn metahash(&self) -> String {
        let mut hash = Sha1::new();
        for item in &self.items {
            hash.update(item.hash.as_bytes());
        }
        hash.digest().to_string()
    }

    pub fn write(&self, path: impl AsRef<Path>, action: Action) -> Result<()> {
        let path = path.as_ref();

        // In the event that a manifest with this name has already been written, we should abort.
        if path.exists() {
            return Err(ManifestErr::ManifestExists(path.into()));
        }

        let mut items = IndexMap::with_capacity(self.items.len());

        // The sending side has some interesting filename constraints, because the relationship of
        // the file locations to the location of the manifest file is not fixed. For this reason,
        // we use different filenames for the check and cleanup operations.

        match action {
            Action::Check => {
                for item in &self.items {
                    items.insert(PathBuf::from(&item.name).into(), item.hash.clone());
                }
            }
            Action::Cleanup => {
                for item in &self.items {
                    items.insert(item.path.clone().into(), item.hash.clone());
                }
            }
        }

        let template = Manifest { action, items };
        serde_json::to_writer_pretty(&mut File::create(path)?, &template).unwrap();
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest<'a> {
    pub action: Action,
    #[serde(borrow)]
    pub items: IndexMap<Cow<'a, Path>, String>,
}
