#define MyAppName "Open Data Migration Manager Compact"
#define MyAppVersion "7.9.12"
#ifndef ODMM_EXE
 #error "Pass /DODMM_EXE=<absolute path to compiled exe>"
#endif
#ifndef ODMM_OUTPUT
 #error "Pass /DODMM_OUTPUT=<output directory>"
#endif
[Setup]
AppId={{93CF01C3-4C76-4E34-A61F-920B67D18D6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Abdelhalim Talbi
DefaultDirName={localappdata}\Programs\ODMM Compact
DefaultGroupName=ODMM Compact
OutputDir={#ODMM_OUTPUT}
OutputBaseFilename=ODMM-Compact-Setup-V7.9.12
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
