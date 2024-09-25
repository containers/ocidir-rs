#[cfg(feature = "zstdmt")]
fn main() {
    use std::{env, path::PathBuf};

    use oci_spec::image::Platform;
    use ocidir::{cap_std::fs::Dir, new_empty_manifest, OciDir};
    let dir = Dir::open_ambient_dir(env::temp_dir(), ocidir::cap_std::ambient_authority()).unwrap();
    let oci_dir = OciDir::ensure(&dir).unwrap();

    let mut manifest = new_empty_manifest().build().unwrap();
    let mut config = ocidir::oci_spec::image::ImageConfigurationBuilder::default()
        .build()
        .unwrap();

    // Add the src as a layer
    let mut writer = oci_dir.create_layer_zstd(Some(0)).unwrap();
    writer
        .append_dir_all(".", PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"))
        .unwrap();

    let layer = writer.into_inner().unwrap().complete().unwrap();
    oci_dir.push_layer(&mut manifest, &mut config, layer, "src", None);

    // Add the examples as a layer, using multithreaded compression
    let mut writer = oci_dir.create_layer_zstd_multithread(Some(0), 4).unwrap();
    writer
        .append_dir_all(
            ".",
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples"),
        )
        .unwrap();
    let layer = writer.into_inner().unwrap().complete().unwrap();
    oci_dir.push_layer(&mut manifest, &mut config, layer, "examples", None);

    println!(
        "Created image with manifest: {}",
        manifest.to_string_pretty().unwrap()
    );

    // Add the image manifest
    let _descriptor = oci_dir
        .insert_manifest_and_config(manifest.clone(), config, None, Platform::default())
        .unwrap();
}

#[cfg(not(feature = "zstdmt"))]
fn main() {
    println!("Run this example with `cargo run --example zstd --features zstdmt`");
}
