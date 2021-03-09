use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use wasm_bindgen::__rt::std::io::{Cursor, Seek, Read, Write};
use std::io::SeekFrom;
use block_modes::{Ecb, BlockMode};
use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use log::warn;

const CORE_KEY: [u8; 16] = [0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57];

const MODIFY_KEY: [u8; 16] = [0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28];

const MAGIC_HEADER: [u8; 8] = *b"CTENFDAM";

type DumpResult<T> = Result<T, String>;

#[wasm_bindgen]
pub struct NcmDump {
    inner: NcmDecoder,
}

#[wasm_bindgen]
impl NcmDump {
    pub fn new_from_memory(data: Vec<u8>) -> Self {
        Self {
            inner: NcmDecoder::new(data),
        }
    }

    pub fn dump(&mut self) -> DumpOutput {
        match self.inner.dump() {
            Ok((data, metadata, extension)) => DumpOutput::new(data, metadata,"ok".to_string(), extension),
            Err(err) => DumpOutput::new(vec![], "".to_string(), err, "".to_string()),
        }
    }
}

struct NcmDecoder {
    data: Cursor<Vec<u8>>,
}

impl NcmDecoder {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data: Cursor::new(data),
        }
    }

    fn dump(&mut self) -> DumpResult<(Vec<u8>, String, String)> {
        self.check_format()?;
        self.skip(2)?;

        let key_box = build_key_box(&self.read_aes_key()?[17..]);
        let metadata = self.read_metadata()?;

        self.skip(9)?;

        let image = self.read_image()?;
        let mut audio = self.read_audio(&key_box)?;

        let extension: String;

        match audio.format {
            AudioFileType::Flac => {
                add_flac_metadata(&mut audio, &image, &metadata)?;
                extension = "flac".to_string();
            },
            AudioFileType::Mp3 => {
                add_mp3_metadata(&mut audio, &image, &metadata)?;
                extension = "mp3".to_string();
            },
        }

        Ok((audio.data, serde_json::to_string(&metadata).map_err(err_to_string)?, extension))
    }

    /// check magic header
    fn check_format(&mut self) -> DumpResult<()> {
        let mut buf = [0; 8];
        let read_size = self.data.read(&mut buf).map_err(err_to_string)?;
        if read_size != 8 || buf != MAGIC_HEADER {
            Err("This file is not in ncm format".to_string())
        } else {
            Ok(())
        }
    }

    fn read_aes_key(&mut self) -> DumpResult<Vec<u8>> {
        let key_len = self.data.read_le_u32().map_err(err_to_string)?;
        let mut key_data = vec![0; key_len as usize];
        self.data.read_exact(&mut key_data).map_err(err_to_string)?;

        key_data.iter_mut().for_each(|b| *b ^= 0x64);

        aes_decrypt(&mut key_data, &CORE_KEY)
    }

    fn read_metadata(&mut self) -> DumpResult<Option<Metadata>> {
        let meta_len = self.data.read_le_u32().map_err(err_to_string)?;
        if meta_len == 0 {
            warn!("No metadata information found in file");
            return Ok(None);
        }
        let mut meta_data = vec![0; meta_len as usize];
        self.data.read_exact(&mut meta_data).map_err(err_to_string)?;

        meta_data.iter_mut().for_each(|b| *b ^= 0x63);

        // skip `163 key` ...
        let mut modify_data = base64::decode(&meta_data[22..]).map_err(err_to_string)?;
        let decrypt_data = aes_decrypt(&mut modify_data, &MODIFY_KEY)?;

        // skip `music:`
        let metadata_str = String::from_utf8_lossy(&decrypt_data[6..]);
        let metadata = serde_json::from_str::<Metadata>(&metadata_str).map_err(err_to_string)?;
        Ok(Some(metadata))
    }

    fn read_image(&mut self) -> DumpResult<Option<Image>> {
        let image_len = self.data.read_le_u32().map_err(err_to_string)?;
        if image_len == 0 {
            warn!("No image found in file");
            return Ok(None);
        }
        let mut image_data = vec![0; image_len as usize];
        self.data.read_exact(&mut image_data).map_err(err_to_string)?;
        let filetype = ImageFileType::from_header_data(&image_data[0..8]);
        Ok(Some(Image {
            format: filetype,
            data: image_data,
        }))
    }

    fn read_audio(&mut self, key_box: &[u8]) -> DumpResult<Audio> {
        let mut buf = [0u8; 0x8000];

        let cur_offset = self.skip(0)?;
        let eof_offset = self.data.seek(SeekFrom::End(0)).map_err(err_to_string)?;

        let audio_len = eof_offset - cur_offset;
        let mut audio_data: Vec<u8> = Vec::with_capacity(audio_len as usize);

        self.data.seek(SeekFrom::Start(cur_offset)).map_err(err_to_string)?;
        // identify file type
        self.data.read_exact(&mut buf[..4]).map_err(err_to_string)?;
        self.skip(-4)?;
        decode_audio(&mut buf, 4, key_box);
        let filetype = AudioFileType::from_header_data(&buf[0..4]);

        loop {
            let read_size = self.data.read(&mut buf).map_err(err_to_string)?;
            if read_size == 0 {
                break;
            }
            decode_audio(&mut buf, read_size, key_box);
            audio_data.write_all(&buf[0..read_size]).map_err(err_to_string)?;
        }

        Ok(Audio {
            format: filetype,
            data: audio_data,
        })
    }

    #[inline]
    fn skip(&mut self, byte_num: i64) -> DumpResult<u64> {
        self.data.seek(SeekFrom::Current(byte_num)).map_err(err_to_string)
    }
}

struct Audio {
    format: AudioFileType,
    data: Vec<u8>,
}

struct Image {
    format: ImageFileType,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    format: String,
    music_id: u64,
    music_name: String,
    artist: Vec<(String, u64)>,
    album: String,
    album_id: u64,
    album_pic_doc_id: u128,
    album_pic: String,
    mv_id: u64,
    flag: u64,
    bitrate: u64,
    duration: u64,
    trans_names: Vec<String>,
}

fn aes_decrypt(data: &mut [u8], key: &[u8]) -> DumpResult<Vec<u8>> {
    let cipher = Ecb::<Aes128, Pkcs7>::new_var(key, Default::default()).map_err(err_to_string)?;
    Ok(cipher.decrypt(data).map_err(err_to_string)?.to_owned())
}

fn decode_audio(data: &mut [u8], read_size: usize, key_box: &[u8]) {
    for i in 0..read_size {
        let j = (i + 1) & 0xff;
        data[i] ^= key_box[(key_box[j] as usize + key_box[(key_box[j] as usize + j) & 0xff] as usize) & 0xff];
    }
}

const fn init_key_box() -> [u8; 256] {
    let mut data = [0u8; 256];
    let mut i = 0;
    while i < data.len() {
        data[i] = i as u8;
        i += 1;
    }
    data
}

fn build_key_box(key_data: &[u8]) -> [u8; 256] {
    let key_len = key_data.len();
    let mut key_box = init_key_box();
    let mut last_byte = 0u8;
    let mut key_offset = 0;
    for i in 0..key_box.len() {
        let c = (key_box[i] + last_byte + key_data[key_offset]) & 0xff;
        key_offset += 1;
        if key_offset >= key_len {
            key_offset = 0;
        }
        key_box.swap(i, c as usize);
        last_byte = c;
    }
    key_box
}

enum AudioFileType {
    Mp3,
    Flac,
}

enum ImageFileType {
    Jpeg,
    Png,
    Gif,
}

impl AudioFileType {
    fn from_header_data(header_data: &[u8]) -> Self {
        match header_data[0..4] {
            [0x66, 0x4c, 0x61, 0x43] => {
                Self::Flac
            },
            [0x49, 0x44, 0x33, _] => {
                Self::Mp3
            },
            _ => Self::Mp3
        }
    }
}

impl ImageFileType {
    fn from_header_data(header_data: &[u8]) -> Self {
        match header_data[0..8] {
            [137, 80, 78, 71, 13, 10, 26, 10] => Self::Png,
            [0xFF, 0xD8, 0xFF, 0xE0, _, _, _, _] => Self::Jpeg,
            [71, 73, 70, _, _, _, _, _] => Self::Gif,
            _ => panic!("unknown image mime type")
        }
    }
}

impl ToString for ImageFileType {
    fn to_string(&self) -> String {
        match self {
            Self::Png => "image/png".to_string(),
            Self::Jpeg => "image/jpeg".to_string(),
            Self::Gif => "image/gif".to_string(),
        }
    }
}

fn add_flac_metadata(audio: &mut Audio, image: &Option<Image>, metadata: &Option<Metadata>) -> DumpResult<()> {
    if image.is_none() && metadata.is_none() {
        return Ok(());
    }
    let audio_data = &audio.data;
    let mut new_audio_data = Vec::new();
    let mut cursor = Cursor::new(audio_data);
    let mut tag = metaflac::Tag::read_from(&mut cursor).map_err(err_to_string)?;
    let raw_data = metaflac::Tag::skip_metadata(&mut cursor);
    let comment = tag.vorbis_comments_mut();
    if let Some(metadata) = metadata {
        comment.set_title(vec![metadata.music_name.clone()]);
        comment.set_album(vec![metadata.album.clone()]);
        comment.set_artist(metadata.artist.iter().map(|a| a.0.clone()).collect::<Vec<_>>());

    }
    if let Some(image) = image {
        tag.add_picture(
            image.format.to_string(),
            metaflac::block::PictureType::CoverFront,
            image.data.clone(),
        );
    }
    tag.write_to(&mut new_audio_data).map_err(err_to_string)?;
    new_audio_data.write_all(&raw_data).map_err(err_to_string)?;
    audio.data = new_audio_data;
    Ok(())
}

fn add_mp3_metadata(audio: &mut Audio, image: &Option<Image>, metadata: &Option<Metadata>) -> DumpResult<()> {
    if image.is_none() && metadata.is_none() {
        return Ok(())
    }
    let audio_data = &mut audio.data;
    let mut new_audio_data = audio_data.clone();
    let cursor = Cursor::new(audio_data);
    let mut tag = id3::Tag::read_from(cursor).map_err(err_to_string)?;
    if let Some(metadata) = metadata {
        tag.set_title(metadata.music_name.clone());
        tag.set_album(metadata.album.to_string());
        tag.set_artist(metadata.artist.iter().map(|a| a.0.clone()).collect::<Vec<_>>().join("/"));
    }
    if let Some(image) = image {
        tag.add_picture(
            id3::frame::Picture {
                mime_type: image.format.to_string(),
                picture_type: id3::frame::PictureType::CoverFront,
                data: image.data.clone(),
                description: Default::default(),
            }
        );
    }
    tag.write_to(&mut new_audio_data, id3::Version::Id3v24).map_err(err_to_string)?;
    audio.data = new_audio_data;
    Ok(())
}

#[wasm_bindgen]
pub struct DumpOutput {
    data: Vec<u8>,
    metadata: String,
    extension: String,
    result: String,
}

#[wasm_bindgen]
impl DumpOutput {
    pub fn new(data: Vec<u8>, metadata: String, result: String, extension: String) -> Self {
        Self {
            data,
            metadata,
            extension,
            result,
        }
    }

    pub fn data(self) -> Vec<u8> {
        self.data
    }

    pub fn metadata(&self) -> String {
        self.metadata.clone()
    }

    pub fn extension(&self) -> String {
        self.extension.to_string()
    }

    pub fn result(&self) -> String {
        self.result.clone()
    }
}

fn err_to_string(err: impl std::error::Error) -> String {
    err.to_string()
}

trait ReaderExt {
    fn read_le_u32(&mut self) -> std::io::Result<u32>;
}

impl<T: AsRef<[u8]>> ReaderExt for Cursor<T> {
    fn read_le_u32(&mut self) -> std::io::Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }
}
