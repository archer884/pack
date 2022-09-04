use std::{
    borrow::Cow,
    collections::HashSet,
    env,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use blake3::Hasher;
use bumpalo::Bump;
use clap::{Parser, Subcommand};
use either::Either;
use indexmap::IndexMap;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use sha1_smol::Sha1;
use unicase::UniCase;

#[derive(Clone, Debug, Parser)]
#[clap(version, subcommand_negates_reqs(true))]
struct Args {
    /// path or paths to be copied
    ///
    /// If a directory is passed here, all files in that directory will be copied.
    #[clap(required = true)]
    paths: Vec<String>,

    /// path to which files will be copied
    #[clap(required = true)]
    target: Option<String>,

    /// quiet mode
    #[clap(short, long)]
    quiet: bool,

    /// overwrite existing files
    #[clap(short, long)]
    force: bool,

    #[clap(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Debug, Subcommand)]
enum Command {
    /// check files (on the receiving side)
    Check { path: Option<String> },
    /// remove files
    ///
    /// This removes the files found in a manifest file before removing the manifest file itself.
    /// For obvious reasons, you'd only wanna do this on the sending side. I mean, that's obvious,
    /// right? ...right?
    Clean { path: Option<String> },
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

    fn target(&self) -> &str {
        // Don't ask.
        self.target.as_deref().unwrap()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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

        self.items.insert(name, get_hash(path)?);
        Ok(())
    }

    fn reconstruct_paths<'a>(
        &'a self,
        parent: impl AsRef<Path> + 'a,
    ) -> impl Iterator<Item = PathBuf> + 'a {
        self.items
            .keys()
            .map(move |path| parent.as_ref().join(path))
    }

    fn metahash(&self) -> String {
        let mut hasher = Sha1::new();
        for (_, hash) in &self.items {
            hasher.update(hash.as_bytes());
        }
        hasher.digest().to_string()
    }

    fn write(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut file = File::create(path)?;
        Ok(serde_json::to_writer_pretty(&mut file, self)?)
    }
}

fn get_hash(path: impl AsRef<Path>) -> io::Result<String> {
    let mut reader = File::open(path)?;
    let mut hasher = Hasher::new();
    io::copy(&mut reader, &mut hasher)?;
    Ok(hasher.finalize().to_string())
}

fn main() {
    if let Err(e) = run(&Args::parse()) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run(args: &Args) -> anyhow::Result<()> {
    if let Some(command) = &args.command {
        return execute_subcommand(command);
    }

    // See, this is where the fun starts...

    let (manifest_parent_path, paths) = match args.try_get_dir() {
        Some(dir) => (Cow::from(dir), Either::Left(read_dir(dir)?)),
        None => (std::env::current_dir()?.into(), Either::Right(args.paths())),
    };

    // Sorting paths is non fucking trivial, because the best way to sort paths has absolutely
    // nothing to do with the default cmp implementation on either String or PathBuf or *whatever.*
    // The reality is that no one in their right mind wants A and a to appear so far from one
    // another in any list of items, so fuck that. I'm trying to use unicase to perform a case
    // insensitive comparison, because I'm sick and tired of rewriting my own case insensitizer
    // every time I come to party (and I ALWAYS come to party), but I have no idea what its
    // constructor does and it's actually pretty expensive to make one out of a path because I need
    // to convert to a UTF8 string first (which is PROBABLY a noop, but whatever)...

    // This is a big problem because I can't just cache the damn things. They only borrow data and
    // I can't keep it around because of the semantics of sort_by_cached_key() unless it's stored
    // somewhere else--and the fact that it's stored on the vector itself is worthless because the
    // vector is being sorted, so all the references are about to be invalidated! Which means I
    // have only one solution left to fall back on.

    // Prepare yourself.

    let scratch = Bump::new();
    let mut paths: Vec<_> = paths.collect();

    // Fuck your lifetime.

    paths.sort_by_cached_key(|path| {
        let s = scratch.alloc_str(&*path.as_os_str().to_string_lossy());
        UniCase::new(s)
    });

    // Before we actually start this whole big long process, I actually want to check to see if
    // there are any path conflicts. We also need to see whether or not there's a manifest file on
    // the receiving end. Let's just do that now.

    let foreign_paths: Vec<_> = paths
        .iter()
        .map(|path| make_target_path(args.target().as_ref(), path))
        .collect();

    // So, if any of that stuff exists, we let the user know and bail. Unless, of course, we
    // force, of course....

    // FIXME: If the file conflict is in an existing manifest, the transfer can be safely skipped
    // FOR THAT FILE and we can continue with the others, so that's something to consider for a
    // future enhancement.

    if !args.force && foreign_paths.iter().any(|path| path.exists()) {
        return Err(anyhow::anyhow!("file conflict in target location"));
    }

    // Thankfully, it's a lot easier to pull this trick with the case insensitive filter now that
    // all these paths are owned by something stable.

    let mut filter = HashSet::new();
    let mut manifest = Manifest::default();

    let pairs = paths.iter().zip(foreign_paths.iter());

    for (path, target) in pairs {
        if !filter.insert(UniCase::new(path.as_os_str().to_string_lossy())) {
            continue;
        }

        manifest.push(path)?;

        let mut reader = File::open(&path)?;
        let mut writer = create_target_file(target, args)?;

        io::copy(&mut reader, &mut writer)?;

        if !args.quiet {
            // FIXME: We already did this once, but I guess we're doing it again.
            let name = target.strip_prefix(&args.target())?;
            println!("{}", name.display());
        }
    }

    let manifest_name = manifest.metahash() + ".manifest";
    let foreign_manifest = Path::new(args.target()).join(&manifest_name);

    manifest.write(manifest_parent_path.join(&manifest_name))?;
    manifest.write(foreign_manifest)?;

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

fn execute_subcommand(command: &Command) -> anyhow::Result<()> {
    match command {
        Command::Clean { path } => {
            let path = get_root_path(path);
            clean_files(&path, get_manifest_paths(&path)?)
        }

        Command::Check { path } => {
            let path = get_root_path(path);
            check_files(&path, get_manifest_paths(&path)?)
        }
    }
}

fn get_manifest_paths(path: &Path) -> io::Result<impl Iterator<Item = PathBuf>> {
    let expected_extension = OsStr::new("manifest");
    Ok(fs::read_dir(path)?.filter_map(move |entry| {
        let entry = entry.ok()?;
        let path = entry.path();
        let extension = path.extension()?;
        (path.is_file() && extension == expected_extension).then_some(path)
    }))
}

fn get_root_path(maybe: &Option<String>) -> Cow<Path> {
    maybe
        .as_deref()
        .map(|path| Cow::Borrowed(Path::new(path)))
        .unwrap_or_else(|| Cow::Owned(env::current_dir().unwrap()))
}

fn clean_files(
    root: &Path,
    manifest_paths: impl IntoIterator<Item = PathBuf>,
) -> anyhow::Result<()> {
    for manifest_path in manifest_paths {
        let manifest = load_manifest(&manifest_path)?;
        manifest
            .reconstruct_paths(&root)
            .try_for_each(remove_or_warn)?;
        fs::remove_file(&manifest_path)?;
    }

    Ok(())
}

fn remove_or_warn(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        eprintln!("{} {}", "file not found:".yellow(), path.display());
        return Ok(());
    }

    fs::remove_file(path)
}

fn check_files(
    root: &Path,
    manifest_paths: impl IntoIterator<Item = PathBuf>,
) -> anyhow::Result<()> {
    let mut has_files = false;
    
    for manifest_path in manifest_paths {
        let manifest = load_manifest(&manifest_path)?;
        has_files = true;

        let mut has_error = false;

        for (file_name, hash) in &manifest.items {
            let reconstructed_path = root.join(file_name);
            if !reconstructed_path.exists() {
                let missing = "missing".yellow();
                let file_name = file_name.display();
                eprintln!("{missing} {file_name}");
                has_error = true;
            }

            let reconstructed_hash = get_hash(&reconstructed_path)?;
            if &*reconstructed_hash != hash {
                let mismatch = "mismatch".red();
                let file_name = file_name.display();
                eprintln!("{mismatch} {file_name}");
                has_error = true;
            }
        }

        if has_error {
            std::process::exit(1);
        } else {
            println!("{}", "Ok".green());
            fs::remove_file(manifest_path)?;
        }
    }

    if !has_files {
        println!("manifest not found");
    }

    Ok(())
}

fn load_manifest(path: &Path) -> io::Result<Manifest> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}
