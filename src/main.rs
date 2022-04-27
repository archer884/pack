use std::{
    borrow::Cow,
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
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

    /// path to which files will be copied
    target: String,

    /// quiet mode
    #[clap(short, long)]
    quiet: bool,

    /// overwrite existing files
    #[clap(short, long)]
    force: bool,
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
        self.paths.iter().filter_map(|x| {
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
        let name = path
            .file_name()
            // Commented line uses unstable feature
            // see issue #86442 <https://github.com/rust-lang/rust/issues/86442> for more information
            // Note: these morons need to hurry up and stabilize this, because it's getting annoying.
            // .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidFilename, "path must be a file"))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "path must be a file"))?
            .into();

        let mut reader = File::open(path)?;
        let mut hasher = Hasher::new();
        io::copy(&mut reader, &mut hasher)?;
        self.items.insert(name, hasher.finalize().to_string());
        Ok(())
    }

    fn write(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut file = File::create(path)?;
        Ok(serde_json::to_writer_pretty(&mut file, self)?)
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
    let (manifest_parent_path, paths) = match args.try_get_dir() {
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
        let mut writer = create_target_file(&target, args)?;

        io::copy(&mut reader, &mut writer)?;

        if !args.quiet {
            // FIXME: We already did this once, but I guess we're doing it again.
            let name = target.strip_prefix(&args.target)?;
            println!("{}", name.display());
        }
    }

    manifest.write(manifest_parent_path.join("manifest.json"))?;
    manifest.write(Path::new(&args.target).join("manifest.json"))?;

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

fn create_target_file(path: &Path, args: &Args) -> io::Result<File> {
    if args.force {
        File::create(&path)
    } else {
        OpenOptions::new().create_new(true).write(true).open(&path)
    }
}
