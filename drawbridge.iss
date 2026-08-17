#if Ver < EncodeVer(6, 4, 0, 0)
  #error Inno Setup 6.4 or newer is required.
#endif

#define MyAppName "Drawbridge"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "Drawbridge"
#define MyAppExeName "Drawbridge.App.exe"
#define MyServiceExeName "Drawbridge.Service.exe"

[Setup]
AppId={{D6CEAC0B-9721-4485-A35F-D57BE4CF11AE}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Drawbridge
DefaultGroupName=Drawbridge
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
AppMutex=Global\DrawbridgeSingleInstance
OutputDir=artifacts\installer
OutputBaseFilename=Drawbridge-{#MyAppVersion}-win-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=Drawbridge.App\Assets\Drawbridge.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=no
RestartIfNeededByRun=no

[Files]
Source: "artifacts\publish\service\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "artifacts\publish\app\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Drawbridge"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; IconIndex: 0
Name: "{autodesktop}\Drawbridge"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; IconIndex: 0; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{sys}\sc.exe"; Parameters: "start DrawbridgeService"; Flags: runhidden waituntilterminated; BeforeInstall: ConfigureDrawbridgeService; AfterInstall: VerifyServiceRunning
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Drawbridge"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
var
  SetupServiceWasActive: Boolean;
  SetupServiceWasStopped: Boolean;
  SetupCreatedService: Boolean;
  SetupCompleted: Boolean;
  UninstallServiceWasActive: Boolean;

function ServiceExists: Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'),
    'query DrawbridgeService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode = 0);
end;

function ServiceHasState(const StateCode: String): Boolean;
var
  ResultCode: Integer;
  Output: TExecOutput;
  I: Integer;
begin
  Result := False;
  if not ExecAndCaptureOutput(ExpandConstant('{sys}\sc.exe'),
    'query DrawbridgeService', '', SW_SHOWNORMAL, ewWaitUntilTerminated,
    ResultCode, Output) or (ResultCode <> 0) then
  begin
    Exit;
  end;

  for I := 0 to GetArrayLength(Output.StdOut) - 1 do
  begin
    if Pos(': ' + StateCode + '  ', Output.StdOut[I]) > 0 then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function WaitForServiceState(const StateCode: String): Boolean;
var
  Attempt: Integer;
begin
  Result := False;
  for Attempt := 1 to 480 do
  begin
    if ServiceHasState(StateCode) then
    begin
      Result := True;
      Exit;
    end;

    Sleep(250);
  end;
end;

function StopDrawbridgeService: Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if not ServiceExists or ServiceHasState('1') then
  begin
    Exit;
  end;

  if not Exec(ExpandConstant('{sys}\sc.exe'), 'stop DrawbridgeService', '',
    SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := False;
    Exit;
  end;

  Result := WaitForServiceState('1');
end;

function StartDrawbridgeService: Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  if not ServiceExists then
  begin
    Exit;
  end;

  if ServiceHasState('4') then
  begin
    Result := True;
    Exit;
  end;

  if not Exec(ExpandConstant('{sys}\sc.exe'), 'start DrawbridgeService', '',
    SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Exit;
  end;

  Result := WaitForServiceState('4');
end;

procedure RunRequired(const FileName, Parameters, Description: String);
var
  ResultCode: Integer;
begin
  if not Exec(FileName, Parameters, '', SW_HIDE, ewWaitUntilTerminated,
    ResultCode) then
  begin
    RaiseException(Description + ' could not be started (Windows error ' +
      IntToStr(ResultCode) + ').');
  end;

  if ResultCode <> 0 then
  begin
    RaiseException(Description + ' failed with exit code ' +
      IntToStr(ResultCode) + '.');
  end;
end;

procedure RemoveLegacyTaskForInstall;
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{sys}\schtasks.exe'),
    '/Query /TN "Drawbridge"', '', SW_HIDE, ewWaitUntilTerminated,
    ResultCode) then
  begin
    RaiseException('The legacy Drawbridge scheduled task could not be queried.');
  end;

  if ResultCode = 0 then
  begin
    RunRequired(ExpandConstant('{sys}\schtasks.exe'),
      '/Delete /F /TN "Drawbridge"',
      'Removing the legacy Drawbridge scheduled task');
  end
  else if ResultCode <> 1 then
  begin
    RaiseException('The legacy Drawbridge scheduled-task query failed with ' +
      'exit code ' + IntToStr(ResultCode) + '.');
  end;
end;

procedure ConfigureDrawbridgeService;
var
  ServicePath: String;
  QuotedServicePath: String;
begin
  ServicePath := ExpandConstant('{app}\{#MyServiceExeName}');
  { Backslash-escaped inner quotes become part of SCM's stored binary path. }
  QuotedServicePath := '\"' + ServicePath + '\"';
  if not ServiceExists then
  begin
    RunRequired(ExpandConstant('{sys}\sc.exe'),
      'create DrawbridgeService binPath= "' + QuotedServicePath +
      '" start= delayed-auto DisplayName= "Drawbridge Filtering Service"',
      'Creating DrawbridgeService');
    SetupCreatedService := True;
  end;

  RunRequired(ExpandConstant('{sys}\sc.exe'),
    'config DrawbridgeService binPath= "' + QuotedServicePath +
    '" start= delayed-auto obj= LocalSystem ' +
    'DisplayName= "Drawbridge Filtering Service"',
    'Configuring DrawbridgeService');
  RunRequired(ExpandConstant('{sys}\sc.exe'),
    'description DrawbridgeService ' +
    '"Drawbridge parental-control DNS filtering service"',
    'Setting the DrawbridgeService description');
  RunRequired(ExpandConstant('{sys}\sc.exe'),
    'failure DrawbridgeService reset= 86400 ' +
    'actions= restart/5000/restart/15000/restart/60000',
    'Setting DrawbridgeService recovery actions');
  RunRequired(ExpandConstant('{sys}\sc.exe'),
    'failureflag DrawbridgeService 1',
    'Enabling DrawbridgeService recovery for non-crash failures');
  RemoveLegacyTaskForInstall;
end;

procedure VerifyServiceRunning;
begin
  if not WaitForServiceState('4') then
  begin
    RaiseException('DrawbridgeService did not reach the running state.');
  end;
end;

function RunCleanup: Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  if not Exec(ExpandConstant('{app}\{#MyServiceExeName}'), '--cleanup', '',
    SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Exit;
  end;

  Result := ResultCode = 0;
end;

function DeleteService: Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if not ServiceExists then
  begin
    Exit;
  end;

  Result := False;
  if not Exec(ExpandConstant('{sys}\sc.exe'), 'delete DrawbridgeService', '',
    SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Exit;
  end;

  Result := ResultCode = 0;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  SetupServiceWasActive := ServiceExists and not ServiceHasState('1');
  SetupServiceWasStopped := SetupServiceWasActive;
  if ServiceExists and not StopDrawbridgeService then
  begin
    Result := 'DrawbridgeService could not be stopped. The installer will ' +
      'attempt to restore its previous running state. Verify the service ' +
      'state and try the upgrade again.';
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssDone then
  begin
    SetupCompleted := True;
  end;
end;

procedure RollBackFailedFreshInstall;
var
  Stopped: Boolean;
  Cleaned: Boolean;
  Deleted: Boolean;
begin
  Stopped := StopDrawbridgeService;
  Cleaned := False;
  Deleted := False;
  if Stopped then
  begin
    Cleaned := RunCleanup;
  end;

  if Cleaned then
  begin
    Deleted := DeleteService;
  end;
  if not Deleted then
  begin
    if StartDrawbridgeService then
    begin
      MsgBox('Setup did not complete and could not fully roll back the new ' +
        'service. The registered service was retained and restarted to keep ' +
        'DNS available. Run setup again or use the installed service --cleanup ' +
        'command.', mbCriticalError, MB_OK);
    end
    else
    begin
      MsgBox('Setup did not complete, cleanup failed, and the retained service ' +
        'could not be restarted. WARNING: restore automatic DNS in Windows ' +
        'network settings or run Drawbridge.Service.exe --cleanup from an ' +
        'elevated terminal before removing files.', mbCriticalError, MB_OK);
    end;
  end;
end;

procedure DeinitializeSetup;
begin
  if SetupCompleted then
  begin
    Exit;
  end;

  if SetupCreatedService then
  begin
    RollBackFailedFreshInstall;
  end
  else if SetupServiceWasActive and SetupServiceWasStopped and
    not StartDrawbridgeService then
  begin
    MsgBox('Setup did not complete and the previous DrawbridgeService could ' +
      'not be restarted. Restore automatic DNS from Windows network settings ' +
      'or rerun the installed service with --cleanup.', mbCriticalError, MB_OK);
  end;
end;

procedure AbortUninstallWithRollback(const Detail: String);
var
  Recovery: String;
begin
  Recovery := '';
  if UninstallServiceWasActive then
  begin
    if StartDrawbridgeService then
    begin
      Recovery := ' The retained filtering service was restarted.';
    end
    else
    begin
      Recovery := ' WARNING: the retained service could not be restarted. ' +
        'Restore automatic DNS in Windows network settings or run ' +
        'Drawbridge.Service.exe --cleanup from an elevated terminal.';
    end;
  end;

  MsgBox(Detail + ' No application files were removed.' + Recovery,
    mbCriticalError, MB_OK);
  Abort;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep <> usUninstall then
  begin
    Exit;
  end;

  UninstallServiceWasActive := ServiceExists and not ServiceHasState('1');
  if not StopDrawbridgeService then
  begin
    AbortUninstallWithRollback(
      'DrawbridgeService could not be stopped. Verify its state and retry.');
  end;

  if not RunCleanup then
  begin
    AbortUninstallWithRollback(
      'Drawbridge could not verify automatic DNS, firewall, and legacy-task cleanup.');
  end;

  if not DeleteService then
  begin
    AbortUninstallWithRollback(
      'DrawbridgeService could not be deleted. Check Service Control Manager and retry.');
  end;
end;
