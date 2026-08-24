# Windows release checklist

- Build on `windows-latest` with Rust stable.
- Verify ProductName, FileDescription, ProductVersion, and CompanyName on every EXE.
- Sign every EXE and the installer with the same trusted publisher identity when signing credentials are configured.
- Timestamp signatures.
- Do not modify files after signing.
- Generate SHA-256 checksums after signing.
- If Microsoft Defender Antivirus reports a false positive, submit the exact detected file as a Software developer to Microsoft Security Intelligence.
