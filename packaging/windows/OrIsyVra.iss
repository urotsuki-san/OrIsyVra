#define MyAppName "OrIsyVra"
#define MyAppVersion "0.2.0-alpha.1"
#define MyBinaryVersion "0.2.0.1"
#define SourceDir GetEnv("ORISYVRA_SOURCE")
#define OutputDir GetEnv("ORISYVRA_OUTPUT")
#define IconFile GetEnv("ORISYVRA_ICON")

[Setup]
AppId={{8F905D52-09BC-4B9B-B0D9-45D612972F05}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=OrIsyVra Project
AppPublisherURL=https://github.com/urotsuki-san/OrIsyVra
AppSupportURL=https://github.com/urotsuki-san/OrIsyVra/security
DefaultDirName={localappdata}\Programs\OrIsyVra
DefaultGroupName=OrIsyVra
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename=OrIsyVra-Setup-x86_64
SetupIconFile={#IconFile}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\orisyvra-gui.exe
VersionInfoVersion={#MyBinaryVersion}
VersionInfoCompany=OrIsyVra Project
VersionInfoDescription=OrIsyVra file and encrypted-volume application installer
VersionInfoProductName=OrIsyVra

[Files]
Source: "{#SourceDir}\target\release\orisyvra-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\target\release\orisyvra-volume-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\target\release\orisyvra.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#SourceDir}\target\release\orisyvra-analysis.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#SourceDir}\target\release\orisyvra-volume-mount.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#SourceDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\OrIsyVra"; Filename: "{app}\orisyvra-gui.exe"
Name: "{group}\OrIsyVra Encrypted Volumes"; Filename: "{app}\orisyvra-volume-gui.exe"
Name: "{autodesktop}\OrIsyVra"; Filename: "{app}\orisyvra-gui.exe"

[Run]
Filename: "{app}\orisyvra-gui.exe"; Description: "Launch OrIsyVra"; Flags: nowait postinstall skipifsilent
