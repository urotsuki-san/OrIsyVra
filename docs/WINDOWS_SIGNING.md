# Windows code signing

The build workflow supports optional Authenticode signing through two GitHub Actions secrets:

- `WINDOWS_SIGNING_PFX_BASE64`
- `WINDOWS_SIGNING_PFX_PASSWORD`

Use a certificate issued by a trusted code-signing provider. The workflow signs all Windows executables before packaging, then signs the installer and timestamps each signature.

Microsoft recommends consistent signing identity for Windows applications distributed outside the Microsoft Store.
