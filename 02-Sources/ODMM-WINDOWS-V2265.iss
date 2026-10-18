#define MyAppName "ODMM Desktop"
#define MyAppVersion "226.5"
[Setup]
AppId={{B2CFDC45-553C-481F-85B6-4B7598B2B174}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Abdelhalim Talbi
DefaultDirName={autopf}\ODMM Desktop
DefaultGroupName=ODMM Desktop
OutputDir=dist
OutputBaseFilename=ODMM-Setup-V226.5
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
WizardStyle=modern
[Files]
Source: "dist\ODMM-Desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{group}\ODMM Desktop"; Filename: "{app}\ODMM-Desktop.exe"
Name: "{autodesktop}\ODMM Desktop"; Filename: "{app}\ODMM-Desktop.exe"; Tasks: desktopicon
[Tasks]
Name: "desktopicon"; Description: "Créer un raccourci Bureau"; Flags: unchecked
[Run]
Filename: "{app}\ODMM-Desktop.exe"; Description: "Démarrer ODMM Desktop"; Flags: nowait postinstall skipifsilent
