use std::{
    borrow::Cow,
    env,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
};

mod error;
mod file;
mod manifest;

use blake3::Hasher;
use bumpalo::Bump;
use clap::{Parser, Subcommand};
use either::Either;
use error::Error;
use hashbrown::HashSet;
use indexmap::IndexMap;
use manifest::{Action, Manifest, ManifestBuilder};
use serde::{Deserialize, Serialize};
use unicase::UniCase;

use crate::file::DisplayName;

type Result<T, E = error::Error> = std::result::Result<T, E>;

// FIXME: provide option to take paths from stdin for use with extensions(1)

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
    /// run manifest finalize action
    #[clap(alias = "f")]
    Finalize { path: Option<String> },

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
        let paths_from_args = self.paths.iter().filter_map(|x| {
            let candidate = Path::new(x);
            if candidate.is_file() {
                Some(candidate.into())
            } else {
                None
            }
        });

        if atty::is(atty::Stream::Stdin) {
            Either::Left(paths_from_args)
        } else {
            // todo!("This won't work yet");



            let paths_from_stdin = io::stdin().lines().filter_map(|line| {
                let candidate = line.ok()?;
                Path::is_file(candidate.as_ref()).then(|| candidate.into())
            });
            Either::Right(paths_from_args.chain(paths_from_stdin))
        }
    }

    fn target(&self) -> &str {
        // Don't ask.
        self.target.as_deref().unwrap()
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ActionManifest {
    action: Option<Action>,
    items: IndexMap<PathBuf, String>,
}

impl ActionManifest {
    fn reconstruct_paths<'a>(
        &'a self,
        parent: impl AsRef<Path> + 'a,
    ) -> impl Iterator<Item = PathBuf> + 'a {
        self.items
            .keys()
            .map(move |path| parent.as_ref().join(path))
    }
}

#[derive(Clone, Debug, Serialize)]
struct WriteActionManifest<'a> {
    action: Action,
    items: &'a IndexMap<PathBuf, String>,
}

fn get_hash(path: impl AsRef<Path>) -> io::Result<String> {
    /// 16 kib buffer (see hasher docs)
    const MIN_BUFFER_SIZE: usize = 0x4000;

    let mut hasher = Hasher::new();
    let mut buf = [0u8; MIN_BUFFER_SIZE];

    // Unclear whether or not a buffered reader is necessary
    let mut reader =
        File::open(path).map(|file| BufReader::with_capacity(MIN_BUFFER_SIZE * 20, file))?;

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => {
                hasher.update(&buf[..len]);
            }

            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(hasher.finalize().to_string())
}

/// Source and target paths for a file transfer
struct TransferPair<'a> {
    /// local source path
    source: &'a Path,

    /// projected foreign path
    target: PathBuf,
}

impl<'a> TransferPair<'a> {
    fn new(source: &'a Path, target: PathBuf) -> Self {
        Self { source, target }
    }
}

#[derive(Debug)]
pub struct Conflict {
    #[allow(unused)]
    source: PathBuf,
    target: PathBuf,
}

fn main() {
    if let Err(e) = run(&Args::parse()) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run(args: &Args) -> Result<()> {
    if let Some(command) = &args.command {
        return execute_subcommand(command, args.quiet);
    }

    let (manifest_parent_path, paths) = match args.try_get_dir() {
        Some(dir) => (Cow::from(dir), Either::Left(read_dir(dir)?)),
        None => (std::env::current_dir()?.into(), Either::Right(args.paths())),
    };

    let mut paths: Vec<_> = paths.collect();
    sort_paths(&mut paths);

    // Before we actually start this whole big long process, I actually want to check to see if
    // there are any path conflicts. We also need to see whether or not there's a manifest file on
    // the receiving end. Let's just do that now.

    let path_pairs: Vec<_> = paths
        .iter()
        .map(|path| TransferPair::new(path, make_target_path(args.target().as_ref(), path)))
        .collect();

    // If the user has NOT requested that we overwrite target files, we will check for all file
    // conflicts before initiating the transfer. Assuming the user didn't request that we overwrite
    // existing files, we'll bail if we encounter any.

    if !args.force {
        check_conflicts(&path_pairs)?;
    }

    // The next step is to construct the manifest for the transfer. We'll be using that to ensure
    // we don't bother transfering any files that already exist in the target location (which we
    // will determine on the basis of any existing manifests in the target location).

    let existing_hashes = read_target_manifests(args.target())?;
    let mut builder = ManifestBuilder::new(manifest_parent_path.as_ref());
    let mut filter = HashSet::new();

    for pair in &path_pairs {
        // We may have files which differ only in their casing. We don't actually want to perform
        // multiple transfers in this case, because the target file system (probably a Windows-like
        // file share) will not support this behavior. That's the purpose of this filter.
        if !filter.insert(UniCase::new(pair.source.as_os_str().to_string_lossy())) {
            continue;
        }

        // We're also going to skip transfering anything found in the existing hashes list above.
        let candidate = builder.build_item(pair.source)?;
        if !existing_hashes.contains(&candidate.hash) {
            builder.push(candidate);
            let mut reader = File::open(pair.source)?;
            let mut writer = create_target_file(&pair.target, args)?;
            io::copy(&mut reader, &mut writer)?;
        }

        if !args.quiet {
            println!("{}", pair.source.display());
        }
    }

    let manifest_name = builder.metahash() + ".manifest";
    let foreign_manifest = Path::new(args.target()).join(&manifest_name);

    builder.write(manifest_parent_path.join(&manifest_name), Action::Cleanup)?;
    builder.write(foreign_manifest, Action::Check)?;

    Ok(())
}

/// Performs a case insensitive sort paths.
///
/// Sorting paths is apparently non-fucking trivial, because the best way to sort paths has nothing
/// to do with the default cmp implementation on either String or PathBuf or anything else. The
/// reality is that no one cares about casing when they sort these; they want "a tale of two
/// cities" and "A Tale of Two Cities" to appear right next to one another, but the comparison
/// method doesn't *get* that. As such we're using `unicase` to perform the actual sort.
///
/// This is a problem because we need to cache these keys, so we're also using `bumpalo` to perform
/// the cacheing for us. (This is purely for performance reasons, meaning it's pointless.)
///
/// A big advantage of doing this in a separate function is we can immediately free up this arena.
fn sort_paths(paths: &mut [PathBuf]) {
    let arena = Bump::new();
    paths.sort_by_cached_key(|path| {
        let s = arena.alloc_str(&path.as_os_str().to_string_lossy());
        UniCase::new(s)
    });
}

fn check_conflicts(pairs: &[TransferPair]) -> Result<()> {
    let mut conflicts = Vec::new();

    for pair in pairs {
        if pair.target.exists() {
            conflicts.push(Conflict {
                source: pair.source.into(),
                target: pair.target.clone(),
            });
        }
    }

    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(Error::Conflict(conflicts))
    }
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
        File::create(path)
    } else {
        OpenOptions::new().create_new(true).write(true).open(path)
    }
}

fn execute_subcommand(command: &Command, quiet: bool) -> Result<()> {
    use owo_colors::OwoColorize;

    match command {
        Command::Finalize { path } => {
            let mut has_files = false;
            let path = get_root_path(path);

            for manifest_path in get_manifest_paths(&path)? {
                let manifest = load_manifest(&manifest_path)?;
                has_files = true;

                if let Some(action) = manifest.action {
                    match action {
                        Action::Check => {
                            if !check_manifest_files(&path, &manifest, quiet)? {
                                std::process::exit(1);
                            } else {
                                println!("{}", "Ok".green());
                                fs::remove_file(manifest_path)?;
                            }
                        }

                        Action::Cleanup => {
                            manifest
                                .reconstruct_paths(&path)
                                .try_for_each(remove_or_warn)?;
                            fs::remove_file(&manifest_path)?;
                        }
                    }
                }
            }

            if !has_files {
                println!("manifest not found");
            }

            Ok(())
        }

        Command::Clean { path } => {
            let path = get_root_path(path);
            clean_files(&path, get_manifest_paths(&path)?)
        }

        Command::Check { path } => {
            let path = get_root_path(path);
            check_files(&path, get_manifest_paths(&path)?, quiet)
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

fn clean_files(root: &Path, manifest_paths: impl IntoIterator<Item = PathBuf>) -> Result<()> {
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
    use owo_colors::OwoColorize;

    let path = path.as_ref();
    if !path.exists() {
        eprintln!("{} {}", "file not found:".yellow(), path.display_name());
        return Ok(());
    }

    fs::remove_file(path)?;
    println!("{}", path.display());
    Ok(())
}

fn check_files(
    root: &Path,
    manifest_paths: impl IntoIterator<Item = PathBuf>,
    quiet: bool,
) -> Result<()> {
    use owo_colors::OwoColorize;

    let mut has_files = false;

    for manifest_path in manifest_paths {
        let manifest = load_manifest(&manifest_path)?;
        has_files = true;

        if !check_manifest_files(root, &manifest, quiet)? {
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

/// Checks manifest files.
///
/// Boolean result indicates success for all files in manifest.
fn check_manifest_files(root: &Path, manifest: &ActionManifest, quiet: bool) -> io::Result<bool> {
    for (file_name, hash) in &manifest.items {
        let reconstructed_path = root.join(file_name);
        if !reconstructed_path.exists() {
            let missing = "missing";
            let file_name = file_name.display();
            eprintln!("{missing} {file_name}");
            return Ok(false);
        }

        let reconstructed_hash = get_hash(&reconstructed_path)?;
        if &*reconstructed_hash != hash {
            let mismatch = "mismatch";
            let file_name = file_name.display();
            eprintln!("{mismatch} {file_name}");
            return Ok(false);
        }

        if !quiet {
            println!("{}", file_name.display());
        }
    }

    Ok(true)
}

fn read_target_manifests(path: impl AsRef<Path>) -> Result<HashSet<String>> {
    let path = path.as_ref().join("*.manifest");
    let pattern = path.to_str().unwrap();

    // No-copy deserialization lifetime gets weird here. I'm not totally clear on the value of
    // allocating these strings this way, either. If nothing else, it means *fewer* allocations
    // overall, which is probably more important than allocating less memory.

    let arena = Bump::new();
    let candidate_files = globwalk::glob(pattern).unwrap();

    let hashes: HashSet<_> = candidate_files
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let text = &*arena.alloc(fs::read_to_string(entry.path()).ok()?);
            let manifest: Manifest = serde_json::from_str(text).ok()?;
            Some(manifest.items.into_iter().map(|(_path, hash)| hash))
        })
        .flatten()
        .collect();

    Ok(hashes)
}

fn load_manifest(path: &Path) -> io::Result<ActionManifest> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}
