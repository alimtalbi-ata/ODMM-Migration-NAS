#define MyAppName "ODMM Compact"
#define MyAppVersion "7.8.6"
[Setup]
AppId={{93CF01C3-4C76-4E34-A61F-920B67D18D6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Abdelhalim Talbi
DefaultDirName={autopf}\ODMM Compact
DefaultGroupName=ODMM Compact
OutputDir=dist
OutputBaseFilename=ODMM-Compact-Setup-V7.8.6
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
WizardStyle=modern
[Files]
Source: "dist\ODMM-Compact.exe"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{group}\ODMM Compact"; Filename: "{app}\ODMM-Compact.exe"
Name: "{autodesktop}\ODMM Compact"; Filename: "{app}\ODMM-Compact.exe"; Tasks: desktopicon
[Tasks]
Name: "desktopicon"; Description: "Créer un raccourci Bureau"; Flags: unchecked
[Run]
Filename: "{app}\ODMM-Compact.exe"; Description: "Démarrer ODMM Compact"; Flags: nowait postinstall skipifsilent
