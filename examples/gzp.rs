/// Example that shows how to use a custom compression and media type for image layers.
/// The example below uses gzp to compress the layer.
use std::{env, io, path::PathBuf};

use gzp::{deflate::Gzip, par::compress::ParCompress, Compression, ZWriter};
use oci_spec::image::Platform;
use ocidir::{cap_std::fs::Dir, new_empty_manifest, BlobWriter, OciDir, WriteComplete};

struct ParCompressWrapper<'a>(ParCompress<'a, Gzip, BlobWriter<'a>>);

impl<'a> io::Write for ParCompressWrapper<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a> WriteComplete<BlobWriter<'a>> for ParCompressWrapper<'a> {
    fn complete(mut self) -> io::Result<BlobWriter<'a>> {
        self.0
            .finish()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

fn main() {
    let dir = Dir::open_ambient_dir(env::temp_dir(), ocidir::cap_std::ambient_authority()).unwrap();
    let oci_dir = OciDir::ensure(dir).unwrap();

    let mut manifest = new_empty_manifest().build().unwrap();
    let mut config = ocidir::oci_spec::image::ImageConfigurationBuilder::default()
        .build()
        .unwrap();

    let layer = std::thread::scope(|s| {
        // Add the src as a layer
        let writer = oci_dir
            .create_custom_layer(
                |bw| {
                    Ok(ParCompressWrapper(
                        ParCompress::<Gzip, BlobWriter>::builder()
                            .compression_level(Compression::new(3))
                            .from_borrowed_writer(bw, s),
                    ))
                },
                oci_spec::image::MediaType::ImageLayerGzip,
            )
            .unwrap();
        let mut builder = tar::Builder::new(writer);
        builder.follow_symlinks(false);
        builder
            .append_dir_all(".", PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"))
            .unwrap();
        builder.into_inner().unwrap().complete().unwrap()
    });

    oci_dir.push_layer(&mut manifest, &mut config, layer, "src", None);

    println!(
        "Created image with manifest: {}",
        manifest.to_string_pretty().unwrap()
    );

    // Add the image manifest
    let _descriptor = oci_dir
        .insert_manifest_and_config(manifest.clone(), config, None, Platform::default())
        .unwrap();
}
