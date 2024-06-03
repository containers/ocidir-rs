use std::io::{BufReader, Read};

use anyhow::{Context, Result};

use camino::{Utf8Path, Utf8PathBuf};
use cap_std::fs::Dir;
use cap_std_ext::{cap_std, dirext::CapStdExtDirExt};
use clap::{Parser, ValueEnum};
use fn_error_context::context;
use oci_spec::image::{ImageConfiguration, ImageManifest};
use ocidir::{cap_std::fs::DirBuilder, OciDir};

#[allow(dead_code)]
mod ustar;

#[derive(Debug, Default, Clone, PartialEq, ValueEnum)]
enum LayerType {
    Tar,
    #[default]
    TarGzip
}

#[derive(Debug, Parser)]
enum Opt {
    Generate {
        /// The path to the target OCI directory
        path: Utf8PathBuf,
    },
    FromTar {
        /// The path to the target OCI directory
        ocidir: Utf8PathBuf,
        /// The tag for the image
        name: String,
        /// The path to the raw tarball (will not be inspected)
        tarball: Utf8PathBuf,

        #[clap(long)]
        layer_type: LayerType 
    },
}

type GeneratorFn = fn(
    &ocidir::OciDir,
    manifest: &mut ImageManifest,
    config: &mut ImageConfiguration,
) -> Result<()>;

struct Fixture {
    name: &'static str,
    gen: GeneratorFn,
}

const FIXTURES: &[Fixture] = &[Fixture {
    name: "selabeled",
    gen: gen_selabeled,
}];

#[context("Generating")]
fn generate(d: &ocidir::OciDir) -> Result<()> {
    for fixture in FIXTURES {
        let mut manifest = ocidir::new_empty_manifest().build().unwrap();
        let mut config = oci_spec::image::ImageConfigurationBuilder::default()
            .build()
            .unwrap();
        (fixture.gen)(d, &mut manifest, &mut config)
            .with_context(|| format!("Generating {}", fixture.name))?;
        let config = d.write_config(config)?;
        manifest.set_config(config);

        d.insert_manifest(manifest, Some(fixture.name), Default::default())?;
    }
    Ok(())
}

fn gen_selabeled(
    d: &OciDir,
    manifest: &mut ImageManifest,
    config: &mut ImageConfiguration,
) -> Result<()> {
    let mut layerw = d.create_layer(None)?;
    let mut header = tar::Header::new_ustar();
    header.set_size(11);
    layerw.append_data(&mut header, "foo", std::io::Cursor::new("hello world"))?;
    let layerw = layerw.into_inner()?;
    let layer = layerw.complete()?;
    d.push_layer(manifest, config, layer, "initial layer", None);
    Ok(())
}

#[context("Generating from tar")]
fn from_tar(d: &ocidir::OciDir, name: &str, mut tarf: impl Read) -> Result<()> {
    let mut manifest = ocidir::new_empty_manifest().build().unwrap();
    let mut config = oci_spec::image::ImageConfigurationBuilder::default()
        .build()
        .unwrap();
    let mut layerw = d.create_raw_layer(None)?;
    std::io::copy(&mut tarf, &mut layerw)?;
    let layer = layerw.complete()?;
    d.push_layer(&mut manifest, &mut config, layer, "initial layer", None);
    let config = d.write_config(config)?;
    manifest.set_config(config);

    d.insert_manifest(manifest, Some(name), Default::default())?;
    println!("Generated: {name}");
    Ok(())
}

fn ensure_ocidir(path: &Utf8Path) -> Result<ocidir::OciDir> {
    let db = DirBuilder::new();
    let parent = path.parent().unwrap_or(".".into());
    let parent = &Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
    let path = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Not a filename"))?;
    parent.ensure_dir_with(path, &db)?;
    let d = parent.open_dir(path)?;
    ocidir::OciDir::ensure(&d)
}

fn run() -> Result<()> {
    let opt = Opt::parse();
    match opt {
        Opt::Generate { path } => {
            let d = &ensure_ocidir(&path)?;
            generate(&d)
        }
        Opt::FromTar {
            ocidir,
            name,
            tarball,
        } => {
            let d = &ensure_ocidir(&ocidir)?;
            let tarf = std::fs::File::open(&tarball)
                .map(BufReader::new)
                .with_context(|| tarball.clone())?;
            from_tar(d, &name, tarf)
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
