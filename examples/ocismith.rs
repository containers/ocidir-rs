use anyhow::{Context, Result};

use camino::Utf8PathBuf;
use cap_std::fs::Dir;
use cap_std_ext::{cap_std, dirext::CapStdExtDirExt};
use clap::Parser;
use fn_error_context::context;
use oci_spec::image::{ImageConfiguration, ImageManifest};
use ocidir::{cap_std::fs::DirBuilder, OciDir};

#[derive(Debug, Parser)]
enum Opt {
    Generate {
        /// The path to the target OCI directory
        path: Utf8PathBuf,
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
fn generate(d: &Dir) -> Result<()> {
    let d = &ocidir::OciDir::ensure(d)?;
    for fixture in FIXTURES {
        let mut manifest = ocidir::new_empty_manifest().build().unwrap();
        let mut config = oci_spec::image::ImageConfigurationBuilder::default()
            .build()
            .unwrap();
        (fixture.gen)(d, &mut manifest, &mut config)?;
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

fn run() -> Result<()> {
    let opt = Opt::parse();
    match opt {
        Opt::Generate { path } => {
            let db = DirBuilder::new();
            let parent = path.parent().unwrap_or(".".into());
            let parent = &Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
            let path = path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Not a filename"))?;
            parent.ensure_dir_with(path, &db)?;
            let d = parent.open_dir(path)?;
            generate(&d)
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
