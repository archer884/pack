use std::{
    borrow::Cow,
    fs::{self, File},
    io,
    path::{Path, PathBuf}, collections::HashSet,
};

use blake3::Hasher;
use clap::Parser;
use either::Either;
use indexmap::IndexMap;
use os_str_bytes::OsStrBytes;
use serde::Serialize;

#[derive(Clone, Debug, Parser)]
struct Args {
    /// path or paths to be copied
    ///
    /// If a directory is passed here, all files in that directory will be copied.
    #[clap(required = true)]
    paths: Vec<String>,
    ///
    target: String,
}

impl Args {
    fn try_get_dir(&self) -> Option<&'_ Path> {
        if self.paths.len() == 1 {
            let path = Path::new(&self.paths[0]);
            if path.is_dir() {
                return Some(path);
            }
        }

        None
    }

    fn paths(&self) -> impl Iterator<Item = PathBuf> + '_ {
        let candidates = self.paths.iter();

        candidates.filter_map(|x| {
            let candidate = Path::new(x);
            if candidate.is_file() {
                Some(candidate.into())
            } else {
                None
            }
        })
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(transparent)]
struct Manifest {
    items: IndexMap<PathBuf, String>,
}

impl Manifest {
    fn push(&mut self, path: &Path) -> io::Result<()> {
        let mut reader = File::open(path)?;
        let mut hasher = Hasher::new();
        io::copy(&mut reader, &mut hasher)?;
        self.items
            .insert(path.file_name().expect("argument must be a file").into(), hasher.finalize().to_string());
        Ok(())
    }
}

#[derive(Clone, Default)]
struct CaseInsensitiveFilter {
    set: HashSet<Vec<u8>>,
}

impl CaseInsensitiveFilter {
    /// Validate a path
    fn validate(&mut self, path: &Path) -> bool {
        let value: Vec<_> = path
            .as_os_str()
            .to_raw_bytes()
            .iter()
            .copied()
            .map(|u| u.to_ascii_uppercase())
            .collect();
        
        self.set.insert(value)
    }
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(&args) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run(args: &Args) -> anyhow::Result<()> {
    // See, this is where the fun starts...
    // Also, not using manifest_parent_path for now because I'm not saving
    // the manifest on the sending side.
    let (_manifest_parent_path, paths) = match args.try_get_dir() {
        Some(dir) => (Cow::from(dir), Either::Left(read_dir(dir)?)),
        None => (std::env::current_dir()?.into(), Either::Right(args.paths())),
    };

    let mut filter = CaseInsensitiveFilter::default();
    let mut manifest = Manifest::default();

    for path in paths {
        if !filter.validate(&path) {
            continue;
        }
        
        manifest.push(&path)?;

        let target = make_target_path(args.target.as_ref(), &path);
        let mut reader = File::open(&path)?;
        let mut writer = File::create(&target)?;
        // let mut writer = OpenOptions::new()
        //     .create_new(true)
        //     .write(true)
        //     .open(&target)?;

        io::copy(&mut reader, &mut writer)?;
        println!("{}", target.display());
    }

    let mut writer = File::create(Path::new(&args.target).join("manifest.json"))?;
    serde_json::to_writer_pretty(&mut writer, &manifest)?;

    Ok(())
}

fn read_dir(path: &Path) -> io::Result<impl Iterator<Item = PathBuf>> {
    Ok(fs::read_dir(path)?.filter_map(|entry| {
        let entry = entry.ok()?;
        if entry.file_type().ok()?.is_file() {
            Some(entry.path())
        } else {
            None
        }
    }))
}

fn make_target_path(target: &Path, path: &Path) -> PathBuf {
    target.join(path.file_name().expect("argument must be a file"))
}
