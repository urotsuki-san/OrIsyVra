use std::fmt::Write as _;
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use font8x8::{UnicodeFonts, BASIC_FONTS};
use image::{DynamicImage, ImageFormat, Luma, Rgb, RgbImage};
use qrcode::{Color, EcLevel, QrCode};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::keyfile::{
    create_keyfile, encode_keyfile_bytes, unlock_keyfile_bytes, validate_keyfile_bytes,
    write_keyfile_bytes, KeyfileParams, MasterKey,
};

const CARD_PREFIX: &str = "ORISYVRA-CARD1:";
const CARD_WIDTH: u32 = 1200;
const CARD_HEIGHT: u32 = 720;
const CARD_PADDING: u32 = 56;
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const KEY_CHUNK_TYPE: &[u8; 4] = b"orKY";
const KEY_CHUNK_MAGIC: &[u8; 8] = b"OYVPKY1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyCardInfo {
    pub card_id: String,
}

fn card_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(16);
    for byte in &digest[..8] {
        write!(&mut output, "{byte:02X}").expect("writing to String cannot fail");
    }
    output
}

fn grouped_card_id(value: &str) -> String {
    value
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

fn validate_output(path: &Path, overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        return Err(Error::OutputExists(path.display().to_string()));
    }
    Ok(())
}

fn card_payload(keyfile: &[u8]) -> Result<(QrCode, KeyCardInfo)> {
    validate_keyfile_bytes(keyfile)?;
    let payload = format!("{CARD_PREFIX}{}", URL_SAFE_NO_PAD.encode(keyfile));
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::Q)
        .map_err(|error| Error::Image(error.to_string()))?;
    Ok((
        code,
        KeyCardInfo {
            card_id: card_id(keyfile),
        },
    ))
}

fn draw_text(image: &mut RgbImage, text: &str, x: u32, y: u32, scale: u32, color: Rgb<u8>) {
    let mut cursor = x;
    for character in text.chars() {
        if let Some(glyph) = BASIC_FONTS.get(character) {
            for (row, bits) in glyph.iter().enumerate() {
                for column in 0..8_u32 {
                    if bits & (1_u8 << column) == 0 {
                        continue;
                    }
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let px = cursor + column * scale + dx;
                            let py = y + row as u32 * scale + dy;
                            if px < image.width() && py < image.height() {
                                image.put_pixel(px, py, color);
                            }
                        }
                    }
                }
            }
        }
        cursor = cursor.saturating_add(9 * scale);
    }
}

fn fill_rect(image: &mut RgbImage, x: u32, y: u32, width: u32, height: u32, color: Rgb<u8>) {
    let end_x = (x + width).min(image.width());
    let end_y = (y + height).min(image.height());
    for py in y..end_y {
        for px in x..end_x {
            image.put_pixel(px, py, color);
        }
    }
}

fn render_png_card(keyfile: &[u8]) -> Result<(RgbImage, KeyCardInfo)> {
    let (code, info) = card_payload(keyfile)?;
    let qr = code
        .render::<Luma<u8>>()
        .quiet_zone(true)
        .module_dimensions(4, 4)
        .build();

    let mut card = RgbImage::from_pixel(CARD_WIDTH, CARD_HEIGHT, Rgb([8, 18, 34]));
    fill_rect(&mut card, 0, 0, CARD_WIDTH, 10, Rgb([82, 213, 255]));
    fill_rect(&mut card, 62, 205, 470, 2, Rgb([53, 76, 105]));
    fill_rect(&mut card, 62, 550, 470, 2, Rgb([53, 76, 105]));

    draw_text(&mut card, "ORISYVRA", 64, 62, 6, Rgb([238, 247, 255]));
    draw_text(&mut card, "VISUAL KEY", 68, 138, 3, Rgb([82, 213, 255]));
    draw_text(
        &mut card,
        "ENCRYPTION KEY",
        68,
        242,
        2,
        Rgb([145, 165, 195]),
    );
    draw_text(
        &mut card,
        "KEEP PRIVATE - REQUIRED FOR RECOVERY",
        68,
        288,
        2,
        Rgb([190, 205, 225]),
    );
    draw_text(
        &mut card,
        "KEY FINGERPRINT",
        68,
        404,
        2,
        Rgb([145, 165, 195]),
    );
    draw_text(
        &mut card,
        &grouped_card_id(&info.card_id),
        68,
        450,
        3,
        Rgb([238, 247, 255]),
    );
    draw_text(
        &mut card,
        "OPEN THIS PNG DIRECTLY IN ORISYVRA",
        68,
        592,
        2,
        Rgb([145, 165, 195]),
    );
    draw_text(
        &mut card,
        "QR = PRINT / CAMERA RECOVERY ONLY",
        68,
        626,
        2,
        Rgb([145, 165, 195]),
    );

    let qr_x = CARD_WIDTH
        .checked_sub(qr.width() + CARD_PADDING)
        .ok_or_else(|| Error::InvalidInput("key card QR image is too large".into()))?;
    let qr_y = (CARD_HEIGHT - qr.height()) / 2;
    fill_rect(
        &mut card,
        qr_x.saturating_sub(14),
        qr_y.saturating_sub(14),
        qr.width() + 28,
        qr.height() + 28,
        Rgb([245, 248, 252]),
    );
    for (x, y, pixel) in qr.enumerate_pixels() {
        let value = pixel.0[0];
        card.put_pixel(qr_x + x, qr_y + y, Rgb([value, value, value]));
    }
    draw_text(
        &mut card,
        "OPTICAL BACKUP",
        qr_x,
        (qr_y + qr.height() + 18).min(CARD_HEIGHT - 28),
        2,
        Rgb([145, 165, 195]),
    );

    Ok((card, info))
}

fn render_pdf_card(keyfile: &[u8]) -> Result<(Vec<u8>, KeyCardInfo)> {
    let (code, info) = card_payload(keyfile)?;
    let quiet = 4_usize;
    let modules = code.width() + quiet * 2;
    let scale = (360.0_f32 / modules as f32).floor().max(1.0);
    let size = modules as f32 * scale;
    let origin_x = 595.0_f32 - size - 54.0;
    let origin_y = 224.0_f32;
    let mut stream = String::new();
    writeln!(stream, "1 1 1 rg 0 0 595 842 re f").expect("String write");
    writeln!(stream, "0.03 0.07 0.13 rg 30 70 535 702 re f").expect("String write");
    writeln!(stream, "0.32 0.84 1 rg 30 762 535 10 re f").expect("String write");
    writeln!(stream, "1 1 1 rg BT /F1 28 Tf 56 718 Td (ORISYVRA) Tj ET").expect("String write");
    writeln!(
        stream,
        "0.32 0.84 1 rg BT /F1 15 Tf 56 688 Td (VISUAL KEY) Tj ET"
    )
    .expect("String write");
    writeln!(
        stream,
        "0.75 0.82 0.9 rg BT /F1 11 Tf 56 610 Td (KEY FINGERPRINT) Tj ET"
    )
    .expect("String write");
    writeln!(
        stream,
        "1 1 1 rg BT /F1 15 Tf 56 580 Td ({} ) Tj ET",
        grouped_card_id(&info.card_id)
    )
    .expect("String write");
    writeln!(stream, "0.75 0.82 0.9 rg BT /F1 10 Tf 56 530 Td (Keep private. Use OrIsyVra to unlock this key.) Tj ET").expect("String write");
    writeln!(stream, "0.75 0.82 0.9 rg BT /F1 10 Tf 56 510 Td (QR is provided for optical recovery from print or camera.) Tj ET").expect("String write");
    writeln!(
        stream,
        "1 1 1 rg {:.2} {:.2} {:.2} {:.2} re f",
        origin_x, origin_y, size, size
    )
    .expect("String write");
    stream.push_str("0 0 0 rg\n");
    for y in 0..code.width() {
        for x in 0..code.width() {
            if code[(x, y)] != Color::Dark {
                continue;
            }
            let px = origin_x + (x + quiet) as f32 * scale;
            let py = origin_y + (code.width() + quiet - y - 1) as f32 * scale;
            writeln!(stream, "{:.2} {:.2} {:.2} {:.2} re f", px, py, scale, scale)
                .expect("String write");
        }
    }
    let stream_object = format!(
        "<< /Length {} >>\nstream\n{}endstream",
        stream.len(),
        stream
    );
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>".to_owned(),
        stream_object,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>".to_owned(),
    ];
    let mut pdf = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        write!(&mut pdf, "{} 0 obj\n{}\nendobj\n", index + 1, object).map_err(Error::Io)?;
    }
    let xref = pdf.len();
    write!(&mut pdf, "xref\n0 {}\n", objects.len() + 1).map_err(Error::Io)?;
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets {
        writeln!(&mut pdf, "{offset:010} 00000 n ").map_err(Error::Io)?;
    }
    write!(
        &mut pdf,
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
        objects.len() + 1,
        xref
    )
    .map_err(Error::Io)?;
    Ok((pdf, info))
}

fn write_atomic(bytes: &[u8], output: &Path, overwrite: bool) -> Result<()> {
    validate_output(output, overwrite)?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    if output.exists() && overwrite {
        fs::remove_file(output)?;
    }
    temporary
        .persist(output)
        .map_err(|error| Error::Io(error.error))?;
    Ok(())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320_u32 & mask);
        }
    }
    !crc
}

fn build_key_chunk(keyfile: &[u8]) -> Result<Vec<u8>> {
    validate_keyfile_bytes(keyfile)?;
    let length = u16::try_from(keyfile.len())
        .map_err(|_| Error::InvalidInput("protected key capsule is too large".into()))?;
    let digest = Sha256::digest(keyfile);
    let mut data = Vec::with_capacity(KEY_CHUNK_MAGIC.len() + 2 + keyfile.len() + digest.len());
    data.extend_from_slice(KEY_CHUNK_MAGIC);
    data.extend_from_slice(&length.to_le_bytes());
    data.extend_from_slice(keyfile);
    data.extend_from_slice(&digest);
    Ok(data)
}

fn inject_key_chunk(png: &[u8], keyfile: &[u8]) -> Result<Vec<u8>> {
    if !png.starts_with(PNG_SIGNATURE) {
        return Err(Error::Image("encoder did not produce a PNG image".into()));
    }
    let data = build_key_chunk(keyfile)?;
    let mut chunk_crc_input = Vec::with_capacity(4 + data.len());
    chunk_crc_input.extend_from_slice(KEY_CHUNK_TYPE);
    chunk_crc_input.extend_from_slice(&data);

    let mut output = Vec::with_capacity(png.len() + 12 + data.len());
    output.extend_from_slice(PNG_SIGNATURE);
    let mut cursor = PNG_SIGNATURE.len();
    let mut inserted = false;
    while cursor + 12 <= png.len() {
        let length = u32::from_be_bytes(
            png[cursor..cursor + 4]
                .try_into()
                .map_err(|_| Error::KeyCardDecode)?,
        ) as usize;
        let end = cursor
            .checked_add(12)
            .and_then(|value| value.checked_add(length))
            .ok_or(Error::KeyCardDecode)?;
        if end > png.len() {
            return Err(Error::KeyCardDecode);
        }
        let chunk_type = &png[cursor + 4..cursor + 8];
        if chunk_type == b"IEND" && !inserted {
            output.extend_from_slice(&(data.len() as u32).to_be_bytes());
            output.extend_from_slice(KEY_CHUNK_TYPE);
            output.extend_from_slice(&data);
            output.extend_from_slice(&crc32(&chunk_crc_input).to_be_bytes());
            inserted = true;
        }
        output.extend_from_slice(&png[cursor..end]);
        cursor = end;
        if chunk_type == b"IEND" {
            break;
        }
    }
    if !inserted {
        return Err(Error::Image("PNG IEND chunk was not found".into()));
    }
    Ok(output)
}

fn extract_key_chunk(png: &[u8]) -> Result<Option<Vec<u8>>> {
    if !png.starts_with(PNG_SIGNATURE) {
        return Ok(None);
    }
    let mut cursor = PNG_SIGNATURE.len();
    while cursor + 12 <= png.len() {
        let length = u32::from_be_bytes(
            png[cursor..cursor + 4]
                .try_into()
                .map_err(|_| Error::KeyCardDecode)?,
        ) as usize;
        let data_start = cursor + 8;
        let data_end = data_start.checked_add(length).ok_or(Error::KeyCardDecode)?;
        let end = data_end.checked_add(4).ok_or(Error::KeyCardDecode)?;
        if end > png.len() {
            return Err(Error::KeyCardDecode);
        }
        let chunk_type = &png[cursor + 4..cursor + 8];
        if chunk_type == KEY_CHUNK_TYPE {
            let data = &png[data_start..data_end];
            if data.len() < KEY_CHUNK_MAGIC.len() + 2 + 32
                || &data[..KEY_CHUNK_MAGIC.len()] != KEY_CHUNK_MAGIC
            {
                return Err(Error::KeyCardDecode);
            }
            let length_offset = KEY_CHUNK_MAGIC.len();
            let key_length = u16::from_le_bytes(
                data[length_offset..length_offset + 2]
                    .try_into()
                    .map_err(|_| Error::KeyCardDecode)?,
            ) as usize;
            let key_start = length_offset + 2;
            let key_end = key_start
                .checked_add(key_length)
                .ok_or(Error::KeyCardDecode)?;
            if key_end + 32 != data.len() {
                return Err(Error::KeyCardDecode);
            }
            let keyfile = data[key_start..key_end].to_vec();
            let expected = Sha256::digest(&keyfile);
            if expected.as_slice() != &data[key_end..] {
                return Err(Error::KeyCardDecode);
            }
            validate_keyfile_bytes(&keyfile)?;
            return Ok(Some(keyfile));
        }
        cursor = end;
        if chunk_type == b"IEND" {
            break;
        }
    }
    Ok(None)
}

fn save_png_card(card: &RgbImage, keyfile: &[u8], output: &Path, overwrite: bool) -> Result<()> {
    let mut encoded = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(card.clone())
        .write_to(&mut encoded, ImageFormat::Png)
        .map_err(|error| Error::Image(error.to_string()))?;
    let png = inject_key_chunk(&encoded.into_inner(), keyfile)?;
    write_atomic(&png, output, overwrite)
}

fn export_bytes(keyfile: &[u8], output: &Path, overwrite: bool) -> Result<KeyCardInfo> {
    if output
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("pdf"))
    {
        let (pdf, info) = render_pdf_card(keyfile)?;
        write_atomic(&pdf, output, overwrite)?;
        Ok(info)
    } else {
        let (card, info) = render_png_card(keyfile)?;
        save_png_card(&card, keyfile, output, overwrite)?;
        Ok(info)
    }
}

fn decode_qr_keycard(image_bytes: &[u8]) -> Result<Vec<u8>> {
    let image = image::load_from_memory(image_bytes)
        .map_err(|error| Error::Image(error.to_string()))?
        .to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(image);
    for grid in prepared.detect_grids() {
        let Ok((_, content)) = grid.decode() else {
            continue;
        };
        let Some(encoded) = content.strip_prefix(CARD_PREFIX) else {
            continue;
        };
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::KeyCardDecode)?;
        validate_keyfile_bytes(&decoded)?;
        return Ok(decoded);
    }
    Err(Error::KeyCardDecode)
}

pub fn decode_keycard_image(image_bytes: &[u8]) -> Result<Vec<u8>> {
    if let Some(keyfile) = extract_key_chunk(image_bytes)? {
        return Ok(keyfile);
    }
    decode_qr_keycard(image_bytes)
}

fn source_bytes(source: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(source)?;
    if bytes.starts_with(PNG_SIGNATURE) {
        decode_keycard_image(&bytes)
    } else {
        validate_keyfile_bytes(&bytes)?;
        Ok(bytes)
    }
}

pub fn key_source_info(source: &Path) -> Result<KeyCardInfo> {
    let bytes = source_bytes(source)?;
    Ok(KeyCardInfo {
        card_id: card_id(&bytes),
    })
}

pub fn create_keycard(
    output: &Path,
    password: &[u8],
    params: KeyfileParams,
    overwrite: bool,
) -> Result<KeyCardInfo> {
    let directory = tempfile::tempdir()?;
    let key = directory.path().join("visual-key.orisyvra-key");
    create_keyfile(&key, password, params, false)?;
    export_keycard(&key, output, overwrite)
}

pub fn unlock_key_source(source: &Path, password: &[u8]) -> Result<MasterKey> {
    unlock_keyfile_bytes(&source_bytes(source)?, password)
}

pub fn export_keycard(source: &Path, output: &Path, overwrite: bool) -> Result<KeyCardInfo> {
    export_bytes(&source_bytes(source)?, output, overwrite)
}

pub fn export_recovery_keycard_from_master(
    master: &MasterKey,
    recovery_password: &[u8],
    params: KeyfileParams,
    output: &Path,
    overwrite: bool,
) -> Result<KeyCardInfo> {
    let bytes = encode_keyfile_bytes(master, recovery_password, params)?;
    export_bytes(&bytes, output, overwrite)
}

pub fn export_recovery_keycard(
    source: &Path,
    current_password: &[u8],
    recovery_password: &[u8],
    params: KeyfileParams,
    output: &Path,
    overwrite: bool,
) -> Result<KeyCardInfo> {
    let master = unlock_keyfile_bytes(&source_bytes(source)?, current_password)?;
    export_recovery_keycard_from_master(&master, recovery_password, params, output, overwrite)
}

pub fn import_keycard(input: &Path, output_keyfile: &Path, overwrite: bool) -> Result<KeyCardInfo> {
    let keyfile = decode_keycard_image(&fs::read(input)?)?;
    let info = KeyCardInfo {
        card_id: card_id(&keyfile),
    };
    write_keyfile_bytes(output_keyfile, &keyfile, overwrite)?;
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::{
        create_keycard, export_keycard, import_keycard, key_source_info, unlock_key_source,
    };
    use crate::{create_keyfile, unlock_keyfile, KeyfileParams};

    #[test]
    fn keycard_round_trip() {
        let directory = tempfile::tempdir().expect("temp directory");
        let key = directory.path().join("source.orisyvra-key");
        let card = directory.path().join("card.png");
        let restored = directory.path().join("restored.orisyvra-key");
        let password = b"correct horse battery staple";
        let params = KeyfileParams {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        };
        create_keyfile(&key, password, params, false).expect("create key");
        let exported = export_keycard(&key, &card, false).expect("export card");
        let imported = import_keycard(&card, &restored, false).expect("import card");
        assert_eq!(exported, imported);
        assert_eq!(
            unlock_keyfile(&key, password).unwrap().as_bytes(),
            unlock_keyfile(&restored, password).unwrap().as_bytes()
        );
    }

    #[test]
    fn visual_key_can_be_used_directly() {
        let directory = tempfile::tempdir().expect("temp directory");
        let card = directory.path().join("visual-key.png");
        let password = b"correct horse battery staple";
        let params = KeyfileParams {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        };
        let created = create_keycard(&card, password, params, false).expect("create visual key");
        let info = key_source_info(&card).expect("read visual key info");
        assert_eq!(created, info);
        let first = unlock_key_source(&card, password).expect("unlock visual key");
        let second = unlock_key_source(&card, password).expect("unlock visual key again");
        assert_eq!(first.as_bytes(), second.as_bytes());
    }
}
