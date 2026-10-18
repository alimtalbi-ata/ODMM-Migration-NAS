#define MyAppName "Open Data Migration Manager Compact"
#ifndef ODMM_VERSION
  #error "ODMM_VERSION must be supplied by build script"
#endif
#define MyAppVersion ODMM_VERSION
#ifndef ODMM_EXE
  #error "ODMM_EXE must point to the compiled portable executable"
#endif
#ifndef ODMM_OUTPUT
  #error "ODMM_OUTPUT must point to the installer output directory"
#endif
[Setup]
AppId={{93CF01C3-4C76-4E34-A61F-920B67D18D6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Abdelhalim Talbi
DefaultDirName={localappdata}\Programs\ODMM Compact
DefaultGroupName=ODMM Compact
OutputDir={#ODMM_OUTPUT}
OutputBaseFilename=ODMM-Compact-Setup-V{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
WizardStyle=modern
UninstallDisplayIcon={app}\ODMM-Compact.exe
[Files]
Source: "{#ODMM_EXE}"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{group}\ODMM Compact"; Filename: "{app}\ODMM-Compact.exe"
Name: "{autodesktop}\ODMM Compact"; Filename: "{app}\ODMM-Compact.exe"; Tasks: desktopicon
[Tasks]
Name: "desktopicon"; Description: "Creer un raccourci Bureau"; Flags: unchecked
[Run]
Filename: "{app}\ODMM-Compact.exe"; Description: "Demarrer ODMM Compact"; Flags: nowait postinstall skipifsilent
