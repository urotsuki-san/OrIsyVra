use eframe::egui;

const MASCOT_TEXTURE_ID: &str = "orisyvra-mascot-v2";
const MASCOT_DATA_ID: &str = "orisyvra-mascot-v2-texture";
const MASCOT_PNG: &[u8] =
    include_bytes!("../../../docs/assets/readme/orisyvra-standee-v2.png");

fn texture(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let id = egui::Id::new(MASCOT_DATA_ID);
    if let Some(texture) = ctx.data(|data| data.get_temp::<egui::TextureHandle>(id)) {
        return Some(texture);
    }

    let image = image::load_from_memory(MASCOT_PNG).ok()?.to_rgba8();
    let size = [image.width() as usize, image.height() as usize];
    let rgba = image.into_raw();
    let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &rgba);
    let texture = ctx.load_texture(MASCOT_TEXTURE_ID, color_image, egui::TextureOptions::LINEAR);
    ctx.data_mut(|data| data.insert_temp(id, texture.clone()));
    Some(texture)
}

pub fn paint_background(ui: &egui::Ui, alpha: u8) {
    if alpha == 0 {
        return;
    }
    let panel = ui.max_rect();
    if panel.width() < 720.0 || panel.height() < 480.0 {
        return;
    }
    let Some(texture) = texture(ui.ctx()) else {
        return;
    };

    let texture_size = texture.size();
    if texture_size[0] == 0 || texture_size[1] == 0 {
        return;
    }

    let target_height = (panel.height() * 0.82).clamp(360.0, 620.0);
    let target_width = target_height * texture_size[0] as f32 / texture_size[1] as f32;
    let size = egui::vec2(target_width, target_height);
    let position = egui::pos2(
        panel.right() - size.x - 18.0,
        panel.bottom() - size.y + 28.0,
    );
    let image_rect = egui::Rect::from_min_size(position, size);

    ui.painter().image(
        texture.id(),
        image_rect,
        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
        egui::Color32::from_white_alpha(alpha),
    );
}
