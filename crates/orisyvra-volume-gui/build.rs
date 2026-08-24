use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn icon_rgba(size: u32) -> Vec<u8> {
    let mut rgba = vec![0_u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 / size as f32;
            let fy = y as f32 / size as f32;
            let index = ((y * size + x) * 4) as usize;
            let body = fx > 0.20 && fx < 0.80 && fy > 0.34 && fy < 0.84;
            let shackle = ((fx - 0.50).powi(2) / 0.20_f32.powi(2)
                + (fy - 0.34).powi(2) / 0.22_f32.powi(2))
                <= 1.0
                && fy < 0.52;
            if body || shackle {
                rgba[index..index + 4].copy_from_slice(&[116, 88, 170, 255]);
            }
            let keyhole = ((fx - 0.50).powi(2) + (fy - 0.58).powi(2)).sqrt() < 0.055
                || ((fx - 0.50).abs() < 0.028 && (0.58..0.72).contains(&fy));
            if keyhole {
                rgba[index..index + 4].copy_from_slice(&[10, 17, 35, 255]);
            }
        }
    }
    rgba
}

fn write_ico(path: &Path, size: u32) -> std::io::Result<()> {
    let rgba = icon_rgba(size);
    let mask_row_bytes = size.div_ceil(32) * 4;
    let mask_size = mask_row_bytes * size;
    let pixel_size = size * size * 4;
    let image_size = 40 + pixel_size + mask_size;
    let image_offset = 6 + 16;

    let mut file = fs::File::create(path)?;
    file.write_all(&0_u16.to_le_bytes())?;
    file.write_all(&1_u16.to_le_bytes())?;
    file.write_all(&1_u16.to_le_bytes())?;
    file.write_all(&[size as u8, size as u8, 0, 0])?;
    file.write_all(&1_u16.to_le_bytes())?;
    file.write_all(&32_u16.to_le_bytes())?;
    file.write_all(&image_size.to_le_bytes())?;
    file.write_all(&(image_offset as u32).to_le_bytes())?;

    file.write_all(&40_u32.to_le_bytes())?;
    file.write_all(&(size as i32).to_le_bytes())?;
    file.write_all(&((size * 2) as i32).to_le_bytes())?;
    file.write_all(&1_u16.to_le_bytes())?;
    file.write_all(&32_u16.to_le_bytes())?;
    file.write_all(&0_u32.to_le_bytes())?;
    file.write_all(&pixel_size.to_le_bytes())?;
    file.write_all(&0_i32.to_le_bytes())?;
    file.write_all(&0_i32.to_le_bytes())?;
    file.write_all(&0_u32.to_le_bytes())?;
    file.write_all(&0_u32.to_le_bytes())?;

    for y in (0..size).rev() {
        for x in 0..size {
            let index = ((y * size + x) * 4) as usize;
            let r = rgba[index];
            let g = rgba[index + 1];
            let b = rgba[index + 2];
            let a = rgba[index + 3];
            file.write_all(&[b, g, r, a])?;
        }
    }
    file.write_all(&vec![0_u8; mask_size as usize])?;
    Ok(())
}

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let icon = out_dir.join("orisyvra-volume.ico");
    write_ico(&icon, 64).expect("write Windows icon");

    let mut resource = winresource::WindowsResource::new();
    resource.set_icon(icon.to_str().expect("UTF-8 icon path"));
    resource.set_version_info(winresource::VersionInfo::FILEVERSION, 0x0000_0002_0000_0001);
    resource.set_version_info(
        winresource::VersionInfo::PRODUCTVERSION,
        0x0000_0002_0000_0001,
    );
    resource.compile().expect("compile Windows resources");
}
