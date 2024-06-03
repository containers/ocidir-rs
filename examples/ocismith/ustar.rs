use std::io::Write;

use anyhow::Result;

const END_OF_ARCHIVE: [u8; 1024] = [0; 1024];

/// Write a PAX extended header
fn write_pax_ext_header(mut w: impl Write, key: &str, value: &[u8]) -> Result<()> {
    let mut buf = Vec::new();
    write!(&mut buf, "{}=", key)?;
    buf.write_all(value)?;
    buf.write_all(b"\n")?;
    write!(w, "{} ", buf.len())?;
    w.write_all(&buf)?;
    Ok(())
}

fn octal_into<T: std::fmt::Octal>(dst: &mut [u8], val: T) {
    let o = format!("{:o}", val);
    let value = o.bytes().rev().chain(std::iter::repeat(b'0'));
    for (slot, value) in dst.iter_mut().rev().skip(1).zip(value) {
        *slot = value;
    }
}

pub struct XattrRef<'k, 'v> {
    pub key: &'k str,
    pub value: &'v [u8],
}

impl<'k, 'v> XattrRef<'k, 'v> {
    const PREFIX: &'static str = "SCHILY.xattr.";

    fn write_to(&self, w: impl Write) -> Result<()> {
        let paxkey = format!("{}{}", Self::PREFIX, self.key);
        write_pax_ext_header(w, &paxkey, self.value)
    }
}

pub fn write_entry<'k, 'v, W: Write>(
    mut out: W,
    xattrs: impl IntoIterator<Item = XattrRef<'k, 'v>>,
) -> Result<()> {
    let mut exthdr = tar::Header::new_ustar();
    let ustarexthdr = exthdr.as_ustar_mut().unwrap();
    ustarexthdr.typeflag[0] = b'x';
    let mut extbuf = Vec::new();
    for xattr in xattrs {
        xattr.write_to(&mut extbuf)?;
    }
    octal_into(&mut ustarexthdr.size, extbuf.len());
    out.write_all(exthdr.as_bytes())?;
    out.write_all(&extbuf)?;
    Ok(())
}

struct UstarWriter<W: Write> {
    out: W,
}

impl<W: Write> UstarWriter<W> {
    pub fn new(out: W) -> Self {
        Self { out }
    }

    pub fn into_inner_without_eof(self) -> W {
        self.out
    }

    pub fn into_inner(mut self) -> Result<W> {
        self.out.write_all(&END_OF_ARCHIVE)?;
        Ok(self.out)
    }

    pub fn write_xattrs<'k, 'v>(
        &mut self,
        xattrs: impl IntoIterator<Item = XattrRef<'k, 'v>>,
    ) -> Result<()> {
        write_entry(&mut self.out, xattrs)
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufWriter;

    use super::*;
    use cap_std_ext::cap_std;
    #[test]
    fn test_write_to_read() -> Result<()> {
        let td = &cap_std_ext::cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
        let tarw = td.create("foo.tar").map(BufWriter::new)?;

        let mut header = tar::Header::new_ustar();
        header.set_size(11);
        layerw.append_data(&mut header, "foo", std::io::Cursor::new("hello world"))?;
        Ok(())
    }
}
