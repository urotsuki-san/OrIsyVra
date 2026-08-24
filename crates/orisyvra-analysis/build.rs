fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource.set_version_info(winresource::VersionInfo::FILEVERSION, 0x0000_0002_0000_0001);
        resource.set_version_info(
            winresource::VersionInfo::PRODUCTVERSION,
            0x0000_0002_0000_0001,
        );
        resource.compile().expect("compile Windows resources");
    }
}
