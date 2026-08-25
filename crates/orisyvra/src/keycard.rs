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
const LEFT_TEXT_X: u32 = 68;
const LEFT_TEXT_RIGHT: u32 = 562;
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

fn text_width(text: &str, scale: u32) -> u32 {
    let count = text.chars().count() as u32;
    if count == 0 {
        0
    } else {
        count
            .saturating_mul(9_u32.saturating_mul(scale))
            .saturating_sub(scale)
    }
}

fn fitted_scale(text: &str, max_width: u32, preferred_scale: u32) -> u32 {
    let mut scale = preferred_scale.max(1);
    while scale > 1 && text_width(text, scale) > max_width {
        scale -= 1;
    }
    scale
}

fn wrap_text(text: &str, max_width: u32, scale: u32) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        let candidate = if current.is_empty() {
            word.to_owned()
        } else {
            format!("{current} {word}")
        };
        if text_width(&candidate, scale) <= max_width {
            current = candidate;
            continue;
        }

        if !current.is_empty() {
            lines.push(std::mem::take(&mut current));
        }

        if text_width(word, scale) <= max_width {
            current.push_str(word);
            continue;
        }

        let mut fragment = String::new();
        for character in word.chars() {
            let mut candidate = fragment.clone();
            candidate.push(character);
            if !fragment.is_empty() && text_width(&candidate, scale) > max_width {
                lines.push(std::mem::take(&mut fragment));
            }
            fragment.push(character);
        }
        current = fragment;
    }

    if !current.is_empty() {
        lines.push(current);
    }
    lines
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

fn draw_wrapped_text(
    image: &mut RgbImage,
    text: &str,
    x: u32,
    y: u32,
    max_width: u32,
    scale: u32,
    color: Rgb<u8>,
) {
    const LINE_SPACING: u32 = 10;
    let line_advance = 8_u32
        .saturating_mul(scale)
        .saturating_add(LINE_SPACING);
    for (index, line) in wrap_text(text, max_width, scale).iter().enumerate() {
        draw_text(
            image,
            line,
            x,
            y.saturating_add(index as u32 * line_advance),
            scale,
            color,
        );
    }
}

fn draw_centered_text(
    image: &mut RgbImage,
    text: &str,
    center_x: u32,
    y: u32,
    scale: u32,
    color: Rgb<u8>,
) {
    let width = text_width(text, scale);
    let x = center_x.saturating_sub(width / 2);
    draw_text(image, text, x, y, scale, color);
}

fn draw_centered_wrapped_text(
    image: &mut RgbImage,
    text: &str,
    center_x: u32,
    y: u32,
    max_width: u32,
    scale: u32,
    color: Rgb<u8>,
) {
    const LINE_SPACING: u32 = 10;
    let line_advance = 8_u32
        .saturating_mul(scale)
        .saturating_add(LINE_SPACING);
    for (index, line) in wrap_text(text, max_width, scale).iter().enumerate() {
        draw_centered_text(
            image,
            line,
            center_x,
            y.saturating_add(index as u32 * line_advance),
            scale,
            color,
        );
    }
}

fn fill_rect(image: &mut RgbImage, x: u32, y: u32, width: u32, height: u32, color: Rgb<u8>) {
    let end_x = x.saturating_add(width).min(image.width());
    let end_y = y.saturating_add(height).min(image.height());
    for py in y..end_y {
        for px in x..end_x {
            image.put_pixel(px, py, color);
        }
    }
}

fn draw_key_sigil(card: &mut RgbImage, keyfile: &[u8]) {
    let digest = Sha256::digest(keyfile);
    let panel_x = 665_u32;
    let panel_y = 92_u32;
    let panel_w = 465_u32;
    let panel_h = 530_u32;
    let panel_center_x = panel_x + panel_w / 2;
    fill_rect(card, panel_x, panel_y, panel_w, panel_h, Rgb([12, 28, 49]));
    fill_rect(card, panel_x, panel_y, panel_w, 3, Rgb([74, 196, 235]));
    fill_rect(card, panel_x, panel_y + panel_h - 3, panel_w, 3, Rgb([74, 196, 235]));

    let primary = Rgb([
        90_u8.saturating_add(digest[0] % 90),
        120_u8.saturating_add(digest[1] % 90),
        145_u8.saturating_add(digest[2] % 90),
    ]);
    let secondary = Rgb([
        80_u8.saturating_add(digest[3] % 100),
        90_u8.saturating_add(digest[4] % 110),
        125_u8.saturating_add(digest[5] % 110),
    ]);

    let cell = 43_u32;
    let grid_w = 7 * cell;
    let grid_x = panel_x + (panel_w - grid_w) / 2;
    let grid_y = panel_y + 84;
    let rows = 7_usize;
    let half_cols = 4_usize;
    for row in 0..rows {
        for col in 0..half_cols {
            let index = row * half_cols + col;
            let byte = digest[6 + index / 8];
            let on = ((byte >> (index % 8)) & 1) == 1;
            if !on {
                continue;
            }
            let inset = 5 + (digest[(index + 13) % digest.len()] as u32 % 7);
            let size = cell.saturating_sub(inset * 2);
            let y = grid_y + row as u32 * cell + inset;
            let left_x = grid_x + col as u32 * cell + inset;
            let mirror_col = 6_usize.saturating_sub(col);
            let right_x = grid_x + mirror_col as u32 * cell + inset;
            let color = if (row + col) % 2 == 0 { primary } else { secondary };
            fill_rect(card, left_x, y, size, size, color);
            if right_x != left_x {
                fill_rect(card, right_x, y, size, size, color);
            }
        }
    }

    let center_x = grid_x + 3 * cell + (cell - 26) / 2;
    let center_y = grid_y + 3 * cell + (cell - 26) / 2;
    fill_rect(card, center_x, center_y, 26, 26, Rgb([230, 245, 252]));
    fill_rect(card, center_x + 6, center_y + 6, 14, 14, primary);

    draw_centered_text(
        card,
        "KEY SIGIL",
        panel_center_x,
        panel_y + 28,
        3,
        Rgb([82, 213, 255]),
    );
    draw_centered_text(
        card,
        "VISUAL FINGERPRINT",
        panel_center_x,
        panel_y + 420,
        2,
        Rgb([145, 165, 195]),
    );
    let note_width = panel_w - 132;
    draw_centered_wrapped_text(
        card,
        "NOT A SECRET - VERIFY BY SIGHT",
        panel_center_x,
        panel_y + 462,
        note_width,
        2,
        Rgb([190, 205, 225]),
    );
}

fn render_png_card(keyfile: &[u8]) -> Result<(RgbImage, KeyCardInfo)> {
    validate_keyfile_bytes(keyfile)?;
    let info = KeyCardInfo {
        card_id: card_id(keyfile),
    };
    let mut card = RgbImage::from_pixel(CARD_WIDTH, CARD_HEIGHT, Rgb([8, 18, 34]));
    fill_rect(&mut card, 0, 0, CARD_WIDTH, 10, Rgb([82, 213, 255]));
    fill_rect(&mut card, 62, 205, 500, 2, Rgb([53, 76, 105]));
    fill_rect(&mut card, 62, 550, 500, 2, Rgb([53, 76, 105]));

    let left_width = LEFT_TEXT_RIGHT - LEFT_TEXT_X;
    draw_text(&mut card, "ORISYVRA", 64, 62, 6, Rgb([238, 247, 255]));
    draw_text(&mut card, "VISUAL KEY", LEFT_TEXT_X, 138, 3, Rgb([82, 213, 255]));
    draw_text(
        &mut card,
        "DIGITAL KEY CARD",
        LEFT_TEXT_X,
        242,
        2,
        Rgb([145, 165, 195]),
    );
    draw_wrapped_text(
        &mut card,
        "KEEP PRIVATE - COPYING THIS FILE COPIES THE KEY CARD",
        LEFT_TEXT_X,
        288,
        left_width,
        2,
        Rgb([190, 205, 225]),
    );
    draw_text(
        &mut card,
        "KEY FINGERPRINT",
        LEFT_TEXT_X,
        404,
        2,
        Rgb([145, 165, 195]),
    );
    let fingerprint = grouped_card_id(&info.card_id);
    let fingerprint_scale = fitted_scale(&fingerprint, left_width, 3);
    draw_text(
        &mut card,
        &fingerprint,
        LEFT_TEXT_X,
        450,
        fingerprint_scale,
        Rgb([238, 247, 255]),
    );
    draw_wrapped_text(
        &mut card,
        "OPEN THIS PNG IN ORISYVRA",
        LEFT_TEXT_X,
        592,
        left_width,
        2,
        Rgb([145, 165, 195]),
    );
    draw_wrapped_text(
        &mut card,
        "KEY DATA IS EMBEDDED IN A PRIVATE PNG CHUNK",
        LEFT_TEXT_X,
        626,
        left_width,
        2,
        Rgb([145, 165, 195]),
    );
    draw_key_sigil(&mut card, keyfile);
    Ok((card, info))
}

fn legacy_card_payload(keyfile: &[u8]) -> Result<(QrCode, KeyCardInfo)> {
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

fn render_pdf_card(keyfile: &[u8]) -> Result<(Vec<u8>, KeyCardInfo)> {
    let (code, info) = legacy_card_payload(keyfile)?;
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
        "0.32 0.84 1 rg BT /F1 15 Tf 56 688 Td (LEGACY OPTICAL RECOVERY) Tj ET"
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
    writeln!(stream, "0.75 0.82 0.9 rg BT /F1 10 Tf 56 530 Td (Optional optical recovery export.) Tj ET").expect("String write");
    writeln!(stream, "0.75 0.82 0.9 rg BT /F1 10 Tf 56 510 Td (Normal PNG cards use an embedded private key chunk and Key Sigil.) Tj ET").expect("String write");
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
    // Backward compatibility for old QR-bearing visual keys and photographed cards.
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
        create_keycard, fitted_scale, key_source_info, text_width, unlock_key_source, wrap_text,
    };
    use crate::KeyfileParams;

    #[test]
    fn new_png_card_round_trip_uses_embedded_key_chunk() {
        let directory = tempfile::tempdir().expect("temp directory");
        let card = directory.path().join("card.png");
        let password = b"correct horse battery staple";
        let params = KeyfileParams {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        };
        let created = create_keycard(&card, password, params, false).expect("create card");
        let loaded = key_source_info(&card).expect("read card");
        assert_eq!(created, loaded);
        unlock_key_source(&card, password).expect("unlock card");
    }

    #[test]
    fn fingerprint_scale_is_reduced_when_needed() {
        let fingerprint = "3B5A-D975-F4D4-10E3";
        let scale = fitted_scale(fingerprint, 494, 3);
        assert_eq!(scale, 2);
        assert!(text_width(fingerprint, scale) <= 494);
    }

    #[test]
    fn card_copy_wraps_stay_inside_their_columns() {
        for (text, max_width) in [
            ("KEEP PRIVATE - COPYING THIS FILE COPIES THE KEY CARD", 494_u32),
            ("OPEN THIS PNG IN ORISYVRA", 494_u32),
            ("KEY DATA IS EMBEDDED IN A PRIVATE PNG CHUNK", 494_u32),
            ("NOT A SECRET - VERIFY BY SIGHT", 333_u32),
        ] {
            let lines = wrap_text(text, max_width, 2);
            assert!(!lines.is_empty());
            assert!(lines
                .iter()
                .all(|line| text_width(line, 2) <= max_width));
        }
    }
}
