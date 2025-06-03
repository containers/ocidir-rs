use anyhow::Result;
use ocidir_cjson::CanonicalFormatter;
use serde::Serialize;
use std::io;

pub trait JsonCanonicalSerialize {
    fn to_json_canonical_string(&self) -> Result<String>;
    fn to_json_canonical_writer<W>(&self, writer: W) -> Result<()>
    where
        W: io::Write;
}

impl<S> JsonCanonicalSerialize for S
where
    S: Serialize,
{
    fn to_json_canonical_string(&self) -> Result<String> {
        let mut ser = serde_json::Serializer::with_formatter(Vec::new(), CanonicalFormatter::new());
        self.serialize(&mut ser)?;
        let str = String::from_utf8(ser.into_inner())?;
        Ok(str)
    }

    fn to_json_canonical_writer<W>(&self, writer: W) -> Result<()>
    where
        W: io::Write,
    {
        let mut ser = serde_json::Serializer::with_formatter(writer, CanonicalFormatter::new());
        self.serialize(&mut ser)?;
        ser.into_inner().flush()?;
        Ok(())
    }
}
