unit uDataInput;
interface
Uses
  SysUtils, Classes, HabeetatIP, FoundationTypes, uDeviceCache, uPacketCache,
  uEndpointCache, uCommon, NetCoreServices, Util, DateUtils,
  DPSSockets, AnsiStrings, IniFiles, UtilProc, FoundationProcs, SyncObjs,
  uPacketListeners, uMaintenanceTasks, uEncryption, EventLog,
  Generics.Collections, Dialogs, System.StrUtils, System.Types;
procedure StartDataProcessing;
procedure StopDataProcessing;
function DeviceStats_GetDeviceCacheMiss: Integer;
function EndpointStats_GetEndpointCacheMiss: Integer;
function EndpointStats_GetStatusCacheMiss: Integer;
function EndpointStats_GetDuplicateStatus: Integer;
implementation
Var
  _CritSect: TCriticalSection;
  _Threads: Array [1 .. 50] of TThread;
  _DuplicateStatusCount: Integer = 0;
  _DeviceCacheMissCount: Integer = 0;
  _EndpointCacheMissCount: Integer = 0;
  _StatusCacheMissCount: Integer = 0;
Type
  TDataProcessingThread = class(TThread)
  strict private
    FLogBoot: Boolean;
    FLogTimeSync: Boolean;
    FLogSecurity: Boolean;
    FLogDebug: Boolean;
    FLogAccessControl: Boolean;
    FHomeCloudPrivateService: NetCoreServicesIns;
  protected
    procedure Execute; override;
    //
    procedure LogActivity(const FileSuffix: String; const MAC: TMACAddress;
      EncryptionType: Byte; const Data: String);
    function HomeCloudPrivateService: NetCoreServicesIns;
    function MakeResponsePacket(const Request: THACommand): THACommand;
    procedure RespondACK(EncryptionType: Byte; const Request: THACommand;
      const Device: TDeviceCacheEntry; Socket: TUDPChildSocket);
    procedure RespondNAK(EncryptionType: Byte; const Request: THACommand;
      const Device: TDeviceCacheEntry; Socket: TUDPChildSocket);
    procedure ProcessPacket(Packet: THACommand; Len: Integer;
      const IPAddress: String; Port: Word; Socket: TUDPChildSocket);
    function GetDeviceData(const MAC: TMACAddress;
      out Device: TDeviceCacheEntry): Boolean;
    function GetEndpointData(DeviceID, EndpointAddress: Integer;
      out Endpoint: TEndpointCacheEntry): Boolean;
    procedure UpdateDeviceData(var Device: TDeviceCacheEntry;
      const IPAddress: String; Port: Word; SequenceNumber: Byte;
      EncryptionType: Byte; Socket: TUDPChildSocket);
    procedure CreateDeviceData(var Device: TDeviceCacheEntry;
      const IPAddress: String; Port: Word; SequenceNumber: Byte;
      EncryptionType: Byte; Socket: TUDPChildSocket);
    procedure SendPacket(EncryptionType: Byte; var Packet: THACommand;
      DataLen: Integer; const Device: TDeviceCacheEntry;
      Socket: TUDPChildSocket);
   procedure UpdateEndpointValues(var E: TEndpointCacheEntry;
  const Values: ArrayOfEndpointValue; const Status: t_HACommand_StatusDoorlock);
    function AreDuplicateValues(const E: TEndpointCacheEntry;
      const Values: ArrayOfEndpointValue): Boolean;
    function ToDateTimeDT(Datetime: TDateTime): DatetimeDT; overload;
    function ToDateTimeDT(UnixDateTime: Cardinal): DatetimeDT; overload;
    function ToDateTimeDT(const UnixDateTime: Portable32_t)
      : DatetimeDT; overload;
    function MACAddressToString(MAC: TMACAddress): string;
  protected
    // Commands
    procedure ProcessStatus(EncryptionType: Byte; const Packet: THACommand;
      const Device: TDeviceCacheEntry; Socket: TUDPChildSocket);
    procedure ProcessDebug(EncryptionType: Byte; const Packet: THACommand;
      const Device: TDeviceCacheEntry; Socket: TUDPChildSocket);
    procedure ProcessTime(EncryptionType: Byte; const Packet: THACommand;
      const Device: TDeviceCacheEntry; Socket: TUDPChildSocket);
    procedure ProcessBootNotification(EncryptionType: Byte;
      const Packet: THACommand; const Device: TDeviceCacheEntry;
      Socket: TUDPChildSocket);
    procedure ProcessAlarm(EncryptionType: Byte; const Packet: THACommand;
      const Device: TDeviceCacheEntry; Socket: TUDPChildSocket);
    procedure ProcessJoin(EncryptionType: Byte; const Packet: THACommand;
      const Device: TDeviceCacheEntry; Socket: TUDPChildSocket);
    procedure ProcessKeyRequest(EncryptionType: Byte; const Packet: THACommand;
      const Device: TDeviceCacheEntry; Socket: TUDPChildSocket);
    procedure ProcessValuePairReport(EncryptionType: Byte;
      const Packet: THACommand; const Device: TDeviceCacheEntry;
      Socket: TUDPChildSocket);
    procedure ProcessElectricityMeteringReport(EncryptionType: Byte;
      const Packet: THACommand; const Device: TDeviceCacheEntry;
      Socket: TUDPChildSocket);
    procedure ProcessEndpointManagerCommand(EncryptionType: Byte;
      const Packet: THACommand; const Device: TDeviceCacheEntry;
      Socket: TUDPChildSocket);
    procedure ProcessDoorLockCommand(EncryptionType: Byte;
      const Packet: THACommand; const Device: TDeviceCacheEntry;
      Socket: TUDPChildSocket);
    // Status
    procedure ProcessCurtainStatus(const Device: TDeviceCacheEntry;
      EndpointAddress: Integer; const Status: t_HACommand_StatusCurtain);
    procedure ProcessHVACStatus(const Device: TDeviceCacheEntry;
      EndpointAddress: Integer; const Status: t_HACommand_StatusHVAC);
    procedure ProcessLightStatus(const Device: TDeviceCacheEntry;
      EndpointAddress: Integer; const Status: t_HACommand_StatusLight);
    procedure ProcessIASStatus(const Device: TDeviceCacheEntry;
      EndpointAddress: Integer; const Status: t_HACommand_StatusIAS);
    procedure ProcessDoorlockStatus(const Device: TDeviceCacheEntry;
      EndpointAddress: Integer; const Status: t_HACommand_StatusDoorlock);
    // Others
    procedure SetDevicePropertiesOnMemory(const Device: TDeviceCacheEntry;
      StringModelFirmware: string);
    function BytesToString(const Bytes: array of Byte): string;
  public
    constructor Create;
    destructor Destroy; override;
  end;
procedure StartDataProcessing;
Var
  i: Integer;
begin
  for i := Low(_Threads) to High(_Threads) do
    _Threads[i] := TDataProcessingThread.Create;
end;
procedure StopDataProcessing;
Var
  i: Integer;
begin
  // Es mejor hacer el terminate de todos juntos para que comiencen a parar
  // simult�neamente. De esta forma, el WaitFor() que est� m�s abajo
  // demorar� tanto como el thread que m�s tarde en terminar.
  for i := Low(_Threads) to High(_Threads) do
    _Threads[i].Terminate;
  // Anteriormente, en este for estaba tambi�n el Terminate() de cada thread.
  // Como consecuencia, si cada thread tardaba 10 segundos en parar, el
  // proceso completo demorar� n * 10 segundos, donde n es la cantidad de
  // threads. Con la mejora de arriba, ahora el proceso completo tardar�a
  // 10 segundos.
  for i := Low(_Threads) to High(_Threads) do
  begin
    _Threads[i].WaitFor;
    FreeAndNil(_Threads[i]);
  end;
end;
procedure AddDuplicateStatus;
begin
  _CritSect.Enter;
  try
    Inc(_DuplicateStatusCount);
  finally
    _CritSect.Leave;
  end;
end;
function EndpointStats_GetDuplicateStatus: Integer;
begin
  _CritSect.Enter;
  try
    Result := _DuplicateStatusCount;
    _DuplicateStatusCount := 0;
  finally
    _CritSect.Leave;
  end;
end;
procedure AddDeviceCacheMiss();
begin
  _CritSect.Enter;
  try
    Inc(_DeviceCacheMissCount);
  finally
    _CritSect.Leave;
  end;
end;
function DeviceStats_GetDeviceCacheMiss: Integer;
begin
  _CritSect.Enter;
  try
    Result := _DeviceCacheMissCount;
    _DeviceCacheMissCount := 0;
  finally
    _CritSect.Leave;
  end;
end;
procedure AddEndpointCacheMiss();
begin
  _CritSect.Enter;
  try
    Inc(_EndpointCacheMissCount);
  finally
    _CritSect.Leave;
  end;
end;
function EndpointStats_GetEndpointCacheMiss: Integer;
begin
  _CritSect.Enter;
  try
    Result := _EndpointCacheMissCount;
    _EndpointCacheMissCount := 0;
  finally
    _CritSect.Leave;
  end;
end;
procedure AddStatusCacheMiss();
begin
  _CritSect.Enter;
  try
    Inc(_StatusCacheMissCount);
  finally
    _CritSect.Leave;
  end;
end;
function EndpointStats_GetStatusCacheMiss: Integer;
begin
  _CritSect.Enter;
  try
    Result := _StatusCacheMissCount;
    _StatusCacheMissCount := 0;
  finally
    _CritSect.Leave;
  end;
end;
{ TDataProcessingThread }
function TDataProcessingThread.AreDuplicateValues(const E: TEndpointCacheEntry;
  const Values: ArrayOfEndpointValue): Boolean;
Var
  i: Integer;
begin
  for i := Low(Values) to High(Values) do
  begin
    if GetEndpointValue(Values[i].ValueType, E.EndpointValues) <> Values[i].Value
    then
      Exit(False);
  end;
  Result := True;
end;
constructor TDataProcessingThread.Create;
begin
  inherited;
  FLogBoot := InstallIni.ReadInteger('Logging', 'Boot', 0) > 0;
  FLogTimeSync := InstallIni.ReadInteger('Logging', 'TimeSync', 0) > 0;
  FLogSecurity := InstallIni.ReadInteger('Logging', 'Security', 0) > 0;
  FLogDebug := InstallIni.ReadInteger('Logging', 'Debug', 0) > 0;
  FLogAccessControl := InstallIni.ReadInteger('Logging',
    'AccessControl', 0) > 0;
  FreeOnTerminate := False;
end;
destructor TDataProcessingThread.Destroy;
begin
  FreeAndNil(FHomeCloudPrivateService);
  inherited;
end;
procedure TDataProcessingThread.Execute;
Var
  Port: Word;
  Len: Integer;
  Packet: THACommand;
  Socket: TUDPChildSocket;
  IPAddress, SourceMAC: String;
begin
  Repeat
    SourceMAC := 'Unknown';
    try
      Len := GetInputPacket(Packet, IPAddress, Port, Socket);
      if Len > 0 then
      begin
        SourceMAC := MACToStr(Packet.Header.SourceMAC);
        ProcessPacket(Packet, Len, IPAddress, Port, Socket)
      end
      else
      begin
        Sleep(10);
      end;
    except
      on E: exception do
      begin
        EventLogReportEvent(elError,
          Format('An unexpected exception was raised in TDataProcessingThread.Execute(), while processing a packet for MAC address %s: %s',
          [SourceMAC, E.Message]));
      end;
    end;
  Until Terminated;
end;
function TDataProcessingThread.MACAddressToString(MAC: TMACAddress): string;
var
  i: Integer;
begin
  for i := 0 to 5 do
  begin
    if (MAC[i] < 0) or (MAC[i] > 255) then
    begin
      Result := 'Invalid MAC';
      Exit;
    end;
  end;
  Result := '';
  for i := 0 to 5 do
  begin
    if i > 0 then
      Result := Result + ':';
    Result := Result + IntToHex(MAC[i], 2);
  end;
end;
function TDataProcessingThread.GetDeviceData(const MAC: TMACAddress;
  out Device: TDeviceCacheEntry): Boolean;
var
  B: TBytes;
  Response: DeviceResponse;
begin
  // Maybe we have it cached?
  if GetDeviceCacheEntry(MAC, Device) and (Device.DeviceID > 0) then
    Exit(True);
  // No, it's not cached. We need to retrieve device information by resorting
  // to the upper-layer services.
  try
    AddDeviceCacheMiss();
    Response := HomeCloudPrivateService.GetDeviceByAddress(MACToStr(MAC));
    Result := Response.ResponseStatus.Status = ResponseStatus.Success;
    if Result then
    begin
      Device := Default (TDeviceCacheEntry);
      Device.MAC := MAC;
      Device.DeviceID := Response.Device.DeviceID;
      Device.HomeID := Response.Device.HomeID;
      Device.EncryptionType := PROTOCOL_VERSION_PLAIN;
      B := HexToBytes(Response.Device.PrivateKey);
      ZeroMem(@Device.PrivateKey, SizeOf(Device.PrivateKey));
      if Length(B) = SizeOf(Device.PrivateKey) then
        Move(B[0], Device.PrivateKey[0], Length(B));
    end;
  except
    on E: exception do
    begin
      EventLogReportEvent(elError,
        'Error executing HomeCloudPrivateService.GetDeviceByAddress(): ' +
        E.Message);
      Result := False;
    end;
  end;
end;
function TDataProcessingThread.GetEndpointData(DeviceID, EndpointAddress
  : Integer; out Endpoint: TEndpointCacheEntry): Boolean;
var
  Response: EndpointResponse;
begin
  // Maybe we have it cached?
  if GetEndpointCacheEntry(DeviceID, EndpointAddress, Endpoint) then
    Exit(True);
  // No, it's not cached. We need to retrieve device information by resorting
  // to the upper-layer services.
  try
    AddEndpointCacheMiss();
    Response := HomeCloudPrivateService.GetEndpointByAddress(DeviceID,
      IntToStr(EndpointAddress));
    Result := Response.ResponseStatus.Status = ResponseStatus.Success;
    if Result then
    begin
      Endpoint := Default (TEndpointCacheEntry);
      Endpoint.EndpointID := Response.Endpoint.EndpointID;
      Endpoint.DeviceID := Response.Endpoint.DeviceID;
      Endpoint.MAC_HUB := Response.Endpoint.HUB_MAC;
      Endpoint.EndpointAddress := EndpointAddress;
    end;
    StoreEndpointCacheEntry(Endpoint);
  except
    on E: exception do
    begin
      // Hola: loggear el error en alg�n lado
      Result := False;
    end;
  end;
end;
function TDataProcessingThread.HomeCloudPrivateService: NetCoreServicesIns;
begin
  if not Assigned(FHomeCloudPrivateService) then
    FHomeCloudPrivateService := InstantiateHomeCloudPrivateService();
  Result := FHomeCloudPrivateService;
end;
procedure TDataProcessingThread.LogActivity(const FileSuffix: String;
  const MAC: TMACAddress; EncryptionType: Byte; const Data: String);
Var
  i: Integer;
  AFile: TextFile;
  AFileName: String;
begin
  if not DirectoryExists('.\Activity') then
    ExtMkDir('.\Activity');
  AFileName := '.\Activity\' + MACToStr(MAC) + FileSuffix + '.log';
  try
    i := 20;
    while i > 0 do
    begin
      try
        AssignFile(AFile, AFileName);
        if FileExists(AFileName) then
          Append(AFile)
        else
          ReWrite(AFile);
        break;
      except
        Dec(i);
        Sleep(50);
      end;
    end;
    if i = 0 then
      raise exception.Create('Could not write to log file.');
    try
      WriteLn(AFile, FormatDateTime('yyyy"-"mm"-"dd hh":"nn":"ss', UTCNow),
        Format(' EncType=%d; ', [EncryptionType]) + Data);
    finally
      CloseFile(AFile);
    end;
  except
    on E: exception do
      EventLogReportEvent(elWarning, 'Could not write activity log: ' +
        E.Message);
  end;
end;
function TDataProcessingThread.MakeResponsePacket(const Request: THACommand)
  : THACommand;
begin
  ZeroMem(@Result, SizeOf(Result));
  Result.Header.SourceMAC := MAC_NONE;
  Result.Header.DestinationMAC := Request.Header.SourceMAC;
  Result.Header.SequenceNumber := 0;
  Result.Header.SourceEndpoint := 0;
  Result.Header.DestinationEndpoint := Request.Header.SourceEndpoint;
  Result.Header.CommandID := 0;
end;
procedure TDataProcessingThread.ProcessStatus(EncryptionType: Byte;
  const Packet: THACommand; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
begin
  case Packet.Status.StatusType of
    STATUS_TYPE_CURTAIN:
      ProcessCurtainStatus(Device, Packet.Header.SourceEndpoint,
        Packet.Status.Curtain);
    STATUS_TYPE_HVAC:
      ProcessHVACStatus(Device, Packet.Header.SourceEndpoint,
        Packet.Status.HVAC);
    STATUS_TYPE_LIGHT:
      ProcessLightStatus(Device, Packet.Header.SourceEndpoint,
        Packet.Status.Light);
    STATUS_TYPE_IAS:
      ProcessIASStatus(Device, Packet.Header.SourceEndpoint, Packet.Status.IAS);
    STATUS_TYPE_DOORLOCK:
      ProcessDoorlockStatus(Device, Packet.Header.SourceEndpoint,
        Packet.Status.Doorlock);
    // STATUS_TYPE_SAFELOCK:
    // ProcessSafelockStatus(Device, Packet.Header.SourceEndpoint, Packet.Status.Safelock);
  end;
  RespondACK(EncryptionType, Packet, Device, Socket);
end;
procedure TDataProcessingThread.ProcessTime(EncryptionType: Byte;
  const Packet: THACommand; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
Var
  D: TDateTime;
  Response: THACommand;
  Rsp: DateTimeResponse;
begin
  case Packet.Time.SubCommand of
    TIME_REQUEST_LOCAL_FULL:
      begin
        try
          Rsp := HomeCloudPrivateService.GetDeviceCurrentDateTime
            (Device.DeviceID);
          if Rsp.ResponseStatus.Status <> ResponseStatus.Success then
            raise exception.CreateFmt('Invalid response status: %d',
              [Integer(Rsp.ResponseStatus.Status)]);
          Response := MakeResponsePacket(Packet);
          Response.Header.CommandID := HA_TIME;
          Response.Time.SubCommand := TIME_REPORT_LOCAL_FULL;
          D := EncodeDateTime(
            Rsp.Datetime.Date.Year, Rsp.Datetime.Date.Month,
            Rsp.Datetime.Date.Day,
            Rsp.Datetime.Time.Hour, Rsp.Datetime.Time.Minute,
            Rsp.Datetime.Time.Second, 0
            );
          Response.Time.LocalFull.UnixTime :=
            DWORDToPortable32(Trunc((D - EncodeDate(1970, 1, 1)) * SecsPerDay));
          Response.Time.LocalFull.Year := WORDToPortable16(Year(D));
          Response.Time.LocalFull.Month := Month(D);
          Response.Time.LocalFull.Day := Day(D);
          Response.Time.LocalFull.DOW := DayOfTheWeek(D);
          Response.Time.LocalFull.Hour := Hour(D);
          Response.Time.LocalFull.Minute := Minute(D);
          Response.Time.LocalFull.Second := Second(D);
          //
          if FLogTimeSync then
            LogActivity('', Packet.Header.SourceMAC, EncryptionType,
              Format('TIME_REQUEST_LOCAL_FULL: DeviceDateTime=%s; ReturnedDateTime=%s',
              [
              FormatDateTime('yyyy"-"mm"-"dd hh":"nn":"ss', EncodeDate(1970, 1,
              1) + Portable32ToDWORD(Packet.Time.LocalFullRequest.UnixTime) /
              SecsPerDay),
              FormatDateTime('yyyy"-"mm"-"dd hh":"nn":"ss', D)
              ]));
          // Hola: missing sunrise / sunset
          SendPacket(EncryptionType, Response,
            1 + SizeOf(Response.Time.LocalFull), Device, Socket);
        except
          on E: exception do
          begin
            LogActivity('', Packet.Header.SourceMAC, EncryptionType,
              Format('TIME_REQUEST_LOCAL_FULL: (Exception!); DeviceDateTime=%s; Exception=%s',
              [
              FormatDateTime('yyyy"-"mm"-"dd hh":"nn":"ss', EncodeDate(1970, 1,
              1) + Portable32ToDWORD(Packet.Time.LocalFullRequest.UnixTime) /
              SecsPerDay),
              E.Message
              ]));
          end;
        end;
      end;
  end;
end;
procedure TDataProcessingThread.ProcessValuePairReport(EncryptionType: Byte;
  const Packet: THACommand; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
type
  P_HAValuePairCollection = ^t_HAValuePairCollection;
Var
  Value: String;
  E: TEndpointCacheEntry;
  P: P_HAValuePairCollection;
  Key, EndpointNumber: Integer;
  Values: ArrayOfEndpointValue;
begin
  EndpointNumber := Packet.Header.SourceEndpoint;
  if EndpointNumber = 0 then
    EndpointNumber := 1;
  // Los value pairs del device por ahora se mapean al primer endpoint.
  if not GetEndpointData(Device.DeviceID, EndpointNumber, E) then
    Exit;
  SetLength(Values, 0);
  P := @Packet.ValuePairReport;
  while (P.ValueLength > 0) do
  begin
    Key := Portable32ToDWORD(P.Key);
    if Key <= 20 then
    begin // Only value pairs with keys from 1 to 20 can be stored
      Value := Copy(String(AnsiStrings.StrPas(@P.Data)), 1, P.ValueLength);
      SetEndpointValue(EndpointValueType(Integer(EndpointValueType.ValuePair1) +
        Key - 1), Value, Values);
      P := P_HAValuePairCollection(Integer(P) + P.ValueLength + 5);
    end;
  end;
  //UpdateEndpointValues(E, Values, 0);
  RespondACK(EncryptionType, Packet, Device, Socket);
end;
procedure TDataProcessingThread.RespondACK(EncryptionType: Byte;
  const Request: THACommand; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
Var
  Pkt: THACommand;
begin
  Pkt := MakeResponsePacket(Request);
  Pkt.Header.CommandID := HA_ACK;
  SendPacket(EncryptionType, Pkt, 0, Device, Socket);
end;
procedure TDataProcessingThread.RespondNAK(EncryptionType: Byte;
  const Request: THACommand; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
Var
  Pkt: THACommand;
begin
  Pkt := MakeResponsePacket(Request);
  Pkt.Header.CommandID := HA_NAK;
  SendPacket(EncryptionType, Pkt, 0, Device, Socket);
end;
procedure TDataProcessingThread.SendPacket(EncryptionType: Byte;
  var Packet: THACommand; DataLen: Integer; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
Var
  TotalLength: Integer;
  EncryptedPacket: THACommand;
begin
  Packet.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber
    (Device.MAC);
  if EncryptionType = 0 then
  begin
    Packet.Header.ProtocolVersion := 0;
    SetOutputPacket(Packet, DataLen, Device.RemoteIP, Device.RemotePort, Socket)
  end
  else
  begin
    EncryptedPacket := Packet;
    TotalLength := DataLen + SizeOf(THACommandHeader);
    if EncryptPacket(EncryptedPacket, TotalLength, EncryptionType,
      Device.PrivateKey) then
      SetOutputPacket(EncryptedPacket, TotalLength - SizeOf(THACommandHeader),
        Device.RemoteIP, Device.RemotePort, Socket);
  end;
end;
function TDataProcessingThread.ToDateTimeDT(Datetime: TDateTime): DatetimeDT;
Var
  Y, Mo, D, H, Mi, S, Ms: Word;
begin
  DecodeDateTime(Datetime, Y, Mo, D, H, Mi, S, Ms);
  with Result.Date do
  begin
    Year := Y;
    Month := Mo;
    Day := D;
  end;
  with Result.Time do
  begin
    Hour := H;
    Minute := Mi;
    Second := S;
    Millisecond := Ms;
  end;
end;
function TDataProcessingThread.ToDateTimeDT(UnixDateTime: Cardinal): DatetimeDT;
begin
  Result := ToDateTimeDT(UnixToDateTime(UnixDateTime));
end;
function TDataProcessingThread.ToDateTimeDT(const UnixDateTime: Portable32_t)
  : DatetimeDT;
begin
  Result := ToDateTimeDT(Portable32ToDWORD(UnixDateTime));
end;
procedure TDataProcessingThread.ProcessAlarm(EncryptionType: Byte;
  const Packet: THACommand; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
Var
  A: InputAlarm;
  EndpointID: Integer;
  E: TEndpointCacheEntry;
begin
  EndpointID := Packet.Header.SourceEndpoint;
  if EndpointID = 0 then
    EndpointID := Packet.Alarm.Endpoint_Do_Not_Use;
  if EndpointID > 0 then
  begin
    if not GetEndpointData(Device.DeviceID, EndpointID, E) then
      Exit;
    EndpointID := E.EndpointID;
  end;
  A.AlarmNumber := Packet.Alarm.AlarmID;
  A.DeviceID := Device.DeviceID;
  A.EndpointID := EndpointID;;
  A.Comments := UTF8ToString(PAnsiChar(@Packet.Alarm.Text));
  HomeCloudPrivateService.StoreAlarm(A);
  RespondACK(EncryptionType, Packet, Device, Socket);
end;
procedure TDataProcessingThread.ProcessBootNotification(EncryptionType: Byte;
  const Packet: THACommand; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
Var
  Version: String;
begin
  Version := String(PAnsiChar(@Packet.RebootNotification.Version));
  if FLogBoot then
    LogActivity('', Packet.Header.SourceMAC, EncryptionType,
      Format('BOOT: Reason: %d; Version: %s',
      [Packet.RebootNotification.ResetReason, Version]));
  RespondACK(EncryptionType, Packet, Device, Socket);
  HomeCloudPrivateService.UpdateDeviceFirmwareVersion(Device.DeviceID,
    ParseParamByNumber(Version, 2, ','));
end;
procedure TDataProcessingThread.ProcessCurtainStatus(const Device
  : TDeviceCacheEntry; EndpointAddress: Integer;
  const Status: t_HACommand_StatusCurtain);
Var
  VP: ArrayOfEndpointValue;
  Endpoint: TEndpointCacheEntry;
begin
  if not GetEndpointData(Device.DeviceID, EndpointAddress, Endpoint) then
    Exit; // Unregistered endpoint
  SetLength(VP, 2);
  VP[0] := MakeValueType(EndpointValueType.IsOn, Status.MotorStatus and
    (CURTAIN_STATUS_MOVING_UP or CURTAIN_STATUS_MOVING_DOWN) > 0);
  VP[1] := MakeValueType(EndpointValueType.Position, Status.Position);
  //UpdateEndpointValues(Endpoint, VP, Status.MotorStatus);
end;
procedure TDataProcessingThread.ProcessDebug(EncryptionType: Byte;
  const Packet: THACommand; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
begin
  try
    if FLogDebug then
      LogActivity('_Debug', Packet.Header.SourceMAC, EncryptionType,
        Format('DEBUG: Data=%s', [String(PAnsiChar(@Packet.Debug.Data))]));
  except
  end;
end;
procedure TDataProcessingThread.ProcessDoorLockCommand(EncryptionType: Byte;
  const Packet: THACommand; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
var
  Rsp: THACommand;
  i, SampleSerial: Integer;
  Endpoint: TEndpointCacheEntry;
  Values: ArrayOfAccessControlEntry;
  Response: EndpointAccessControlEntryResponse;
begin
  if not GetEndpointData(Device.DeviceID, Packet.Header.SourceEndpoint, Endpoint)
  then
    Exit;
  case Packet.Doorlock.SubCommand of
    DOORLOCK_OPERATION_REPORT:
      case Packet.Doorlock.OperationReport.ReportFormat of
        DOORLOCK_OPERATION_REPORT_FORMAT_NOTIFICATION:
          with Packet.Doorlock.OperationReport.Notification do
          begin
            if FLogAccessControl then
              LogActivity('', Packet.Header.SourceMAC, EncryptionType, Format(
                'DOORLOCK_OPERATION_REPORT_FORMAT_NOTIFICATION: SampleEntryCount=%d',
                [Packet.Doorlock.OperationReport.Notification.
                SampleEntryCount]));
            // Create an array with all entries reported by the endpoint.
            SetLength(Values, 0);
            for i := 0 to SampleEntryCount - 1 do
            begin
              SampleSerial := Portable32ToDWORD(Entries[i].SampleSerialNumber);
              SetLength(Values, Length(Values) + 1);
              //
              Values[High(Values)].SampleSerialNumber := SampleSerial;
              Values[High(Values)].Status :=
                AccessControlStatusType(Entries[i].Status);
              Values[High(Values)].Reason :=
                AccessControlReasonType(Entries[i].Reason);
              Values[High(Values)].Source :=
                AccessControlSourceType(Entries[i].Source);
              Values[High(Values)].UserID := Entries[i].UserID;
              Values[High(Values)].Timestamp :=
                ToDateTimeDT(Entries[i].Timestamp);
            end;
            // Store in the database
            Response := HomeCloudPrivateService.
              StoreEndpointAccessControlEntries(Endpoint.EndpointID, Values);
            // Respond to the endpoint
            if Length(Response.SampleSerialNumberIDSucceeded) > 0 then
            begin
              Rsp := MakeResponsePacket(Packet);
              Rsp.Header.CommandID := HA_DOORLOCK_COMMAND;
              Rsp.Doorlock.SubCommand := DOORLOCK_OPERATION_REPORT;
              Rsp.Doorlock.OperationReport.ReportFormat :=
                DOORLOCK_OPERATION_REPORT_FORMAT_NOTIFICATION_ACK;
              for i := Low(Response.SampleSerialNumberIDSucceeded)
                to High(Response.SampleSerialNumberIDSucceeded) do
              begin
                Rsp.Doorlock.OperationReport.NotificationACK.RecordID[i] :=
                  DWORDToPortable32(Response.SampleSerialNumberIDSucceeded[i]);
                Inc(Rsp.Doorlock.OperationReport.NotificationACK.RecordIDCount);
              end;
              SendPacket(
                EncryptionType,
                Rsp,
                SizeOf(Rsp.Doorlock.SubCommand) +
                SizeOf(Rsp.Doorlock.OperationReport.ReportFormat) +
                SizeOf(Rsp.Doorlock.OperationReport.NotificationACK.
                RecordIDCount) +
                SizeOf(Rsp.Doorlock.OperationReport.NotificationACK.RecordID[0])
                * Rsp.Doorlock.OperationReport.NotificationACK.RecordIDCount,
                Device,
                Socket);
              if FLogAccessControl then
                LogActivity('', Packet.Header.SourceMAC, EncryptionType, Format(
                  'DOORLOCK_OPERATION_REPORT_FORMAT_NOTIFICATION_ACK: SampleEntryCount=%d',
                  [Rsp.Doorlock.OperationReport.NotificationACK.
                  RecordIDCount]));
            end;
          end;
      else
        LogActivity('', Packet.Header.SourceMAC, EncryptionType,
          Format('Cannot process DOORLOCK_OPERATION_REPORT report with ReportFormat=%d',
          [Packet.Doorlock.OperationReport.ReportFormat]));
      end;
  else
    LogActivity('', Packet.Header.SourceMAC, EncryptionType,
      Format('Cannot process HA_DOORLOCK_COMMAND with SubCommand=%d',
      [Packet.Doorlock.SubCommand]));
  end;
end;
procedure TDataProcessingThread.ProcessDoorlockStatus
  (const Device: TDeviceCacheEntry; EndpointAddress: Integer;
  const Status: t_HACommand_StatusDoorlock);
Var
  VP: ArrayOfEndpointValue;
  Endpoint: TEndpointCacheEntry;
begin
if EndpointAddress <> 0 then
        Endpoint.EndpointAddress := EndpointAddress;
      if (Device.DeviceID <> -1) and (Device.DeviceID <> 0) then
        Endpoint.DeviceID := Device.DeviceID;
  if not GetEndpointData(Device.DeviceID, EndpointAddress, Endpoint) then
    Exit; // Unregistered endpoint
  HomeCloudPrivateService.UpdateEndpointLastActivityStatus(Endpoint.DeviceID, Endpoint.EndpointAddress, Status.Status);
end;
procedure TDataProcessingThread.ProcessElectricityMeteringReport
  (EncryptionType: Byte; const Packet: THACommand;
  const Device: TDeviceCacheEntry; Socket: TUDPChildSocket);
var
  Rsp: THACommand;
  i, SampleSerial: Integer;
  Endpoint: TEndpointCacheEntry;
  Response: EndpointMeteringResponse;
  Values: ArrayOfEndpointMeteringValue;
begin
  if not GetEndpointData(Device.DeviceID, Packet.Header.SourceEndpoint, Endpoint) then Exit;
  Endpoint.DeviceID := Device.DeviceID;
  Endpoint.EndpointAddress := Packet.Header.SourceEndpoint;
  case Packet.ElectricityMetering.ReportFormat of
    METERING_ELECTRICITY_FORMAT_ACCUMULATED_1:
      with Packet.ElectricityMetering.Summation_1 do
      begin
        // Create an array with all metering values reported by the endpoint.
        SetLength(Values, 0);
        for i := 0 to SampleEntryCount - 1 do
        begin
          SampleSerial := Portable32ToDWORD(Entries[i].SampleSerialNumber);
          SetLength(Values, Length(Values) + 1);
          //
          Values[High(Values)].MeteringDateTime :=
            ToDateTimeDT(Entries[i].Datetime);
          Values[High(Values)].MeteringSampleID := SampleSerial;
          Values[High(Values)].Sumation :=
            Portable32ToDWORD(Entries[i].ActiveConsumptionmWh) / 1000000;
          // From mWh to kWh
          Values[High(Values)].ApparentSumation :=
            Portable32ToDWORD(Entries[i].ApparentConsumptiomVAh) / 1000000;
          // From mVAh to kVAh
          Values[High(Values)].DurationSeconds :=
            Portable32ToDWORD(Entries[i].DurationSeconds);
          Values[High(Values)].AverageVoltage :=
            Portable32ToDWORD(Entries[i].VRMSmV) / 1000; // From mV to V
          Values[High(Values)].AverageCurrent :=
            Portable32ToDWORD(Entries[i].IRMSmA) / 1000; // From mA to A
          Values[High(Values)].PowerFactor := Entries[i].PowerFactor;
        end;
        // Store in the database
        // Response := HomeCloudPrivateService.StoreEndpointMeteringValues(Endpoint.EndpointID, Values);
        // Respond to the endpoint
        if Length(Response.MeteringSampleIDSucceeded) > 0 then
        begin
          Rsp := MakeResponsePacket(Packet);
          Rsp.Header.CommandID := HA_METERING_ELECTRICITY;
          Rsp.ElectricityMetering.ReportFormat :=
            METERING_ELECTRICITY_FORMAT_ACK;
          for i := Low(Response.MeteringSampleIDSucceeded)
            to High(Response.MeteringSampleIDSucceeded) do
          begin
            Rsp.ElectricityMetering.ReportACK.RecordID[i] :=
              DWORDToPortable32(Response.MeteringSampleIDSucceeded[i]);
            Inc(Rsp.ElectricityMetering.ReportACK.RecordIDCount);
          end;
          SendPacket(
            EncryptionType,
            Rsp,
            SizeOf(Rsp.ElectricityMetering.ReportFormat) +
            SizeOf(Rsp.ElectricityMetering.ReportACK.RecordIDCount) +
            SizeOf(Rsp.ElectricityMetering.ReportACK.RecordID[0]) *
            Rsp.ElectricityMetering.ReportACK.RecordIDCount,
            Device,
            Socket);
        end;
      end;
  else
    LogActivity('', Packet.Header.SourceMAC, EncryptionType,
      Format('Cannot process METERING_ELECTRICITY report with ReportFormat=%d',
      [Packet.ElectricityMetering.ReportFormat]));
  end;
end;
procedure TDataProcessingThread.ProcessEndpointManagerCommand
  (EncryptionType: Byte; const Packet: THACommand;
  const Device: TDeviceCacheEntry; Socket: TUDPChildSocket);
begin
  if Packet.EndpointManager.SubCommand <> ENDPOINT_MANAGER_ENROLLED then
    Exit;
  SetEndpointCacheEnrollmentResult(Device.DeviceID,
    Packet.Header.SourceEndpoint, Packet.EndpointManager.EnrollmentResult);
end;
procedure TDataProcessingThread.ProcessHVACStatus(const Device
  : TDeviceCacheEntry; EndpointAddress: Integer;
  const Status: t_HACommand_StatusHVAC);
Var
  VP: ArrayOfEndpointValue;
  Endpoint: TEndpointCacheEntry;
begin
  if not GetEndpointData(Device.DeviceID, EndpointAddress, Endpoint) then
    Exit;
  SetLength(VP, 7);
  VP[0] := MakeValueType(EndpointValueType.ThermostatMode, Status.Mode);
  VP[1] := MakeValueType(EndpointValueType.ThermostatFanMode, Status.FanMode);
  VP[2] := MakeValueType(EndpointValueType.MeasuredTemperatureC,
    SmallInt(Portable16ToWORD(Status.MeasuredTemp)) / 100);
  VP[3] := MakeValueType(EndpointValueType.ThermostatDesiredTempC,
    SmallInt(Portable16ToWORD(Status.DesiredTemp)) / 100);
  VP[4] := MakeValueType(EndpointValueType.HVACTimerOnMinutes,
    Portable16ToWORD(Status.TimerOnMinutes));
  VP[5] := MakeValueType(EndpointValueType.HVACTimerOffMinutes,
    Portable16ToWORD(Status.TimerOffMinutes));
  VP[6] := MakeValueType(EndpointValueType.HVACFlags, Status.Flags);
  //UpdateEndpointValues(Endpoint, VP);
end;
procedure TDataProcessingThread.ProcessIASStatus(const Device
  : TDeviceCacheEntry; EndpointAddress: Integer;
  const Status: t_HACommand_StatusIAS);
Var
  VP: ArrayOfEndpointValue;
  Endpoint: TEndpointCacheEntry;
begin
  if not GetEndpointData(Device.DeviceID, EndpointAddress, Endpoint) then
    Exit; // Unregistered endpoint
  SetLength(VP, 1);
  VP[0] := MakeValueType(EndpointValueType.IASSensorState, Status.State);
  //UpdateEndpointValues(Endpoint, VP);
end;
procedure TDataProcessingThread.ProcessJoin(EncryptionType: Byte;
  const Packet: THACommand; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
begin
  case Packet.Join.SubCommand of
    JOIN_COMMAND_KEY_REQUEST:
      ProcessKeyRequest(EncryptionType, Packet, Device, Socket);
  end;
end;
//procedure TDataProcessingThread.SetDevicePropertiesOnMemory
//  (const Device: TDeviceCacheEntry; StringModelFirmware: string);
//var
//  UpdatedDevice: TDeviceCacheEntry;
//  parts, modelAndFirmware: TStringDynArray;
//  dashPos: Integer;
//begin
//  if GetDeviceCacheEntryByMAC(Device.MAC, UpdatedDevice) then
//  begin
//    // Divide la cadena en partes utilizando las comillas simples como delimitador
//    parts := SplitString(StringModelFirmware, '''');
//    // Divide la �ltima parte utilizando la coma como delimitador
//    modelAndFirmware := SplitString(parts[High(parts)], ',');
//    // Encuentra la posici�n del gui�n en el modelo
//    dashPos := Pos('-', modelAndFirmware[0]);
//    // Asignar los datos extra�dos a las propiedades del dispositivo
//    if dashPos > 0 then
//      UpdatedDevice.Model := Copy(modelAndFirmware[0], dashPos + 1, MaxInt)
//      // Copia desde la posici�n del gui�n hasta el final
//   else
//      UpdatedDevice.Model := modelAndFirmware[0];
//   UpdatedDevice.Firmware := modelAndFirmware[1];
//   UpdatedDevice.LastTimeStamp := TTimeZone.Local.ToUniversalTime(Now);
//    // Asignar la copia actualizada al dispositivo correspondiente en la lista
//    UpdateDeviceCacheEntry(UpdatedDevice);
//  end;
//end;
procedure TDataProcessingThread.SetDevicePropertiesOnMemory
  (const Device: TDeviceCacheEntry; StringModelFirmware: string);
var
  UpdatedDevice: TDeviceCacheEntry;
  parts, modelAndFirmware: TStringDynArray;
begin
  if GetDeviceCacheEntryByMAC(Device.MAC, UpdatedDevice) then
  begin
    // Divide la cadena en partes utilizando las comillas simples como delimitador
    parts := SplitString(StringModelFirmware, '''');
    // Divide la �ltima parte utilizando la coma como delimitador
    modelAndFirmware := SplitString(parts[High(parts)], ',');
    // Asignar los datos extra�dos a las propiedades del dispositivo
    UpdatedDevice.Model := modelAndFirmware[0];
    UpdatedDevice.Firmware := modelAndFirmware[1];
    UpdatedDevice.LastTimeStamp := TTimeZone.Local.ToUniversalTime(Now);
    // Asignar la copia actualizada al dispositivo correspondiente en la lista
    UpdateDeviceCacheEntry(UpdatedDevice);
  end;
end;
function TDataProcessingThread.BytesToString(const Bytes
  : array of Byte): string;
var
  i: Integer;
begin
  SetLength(Result, Length(Bytes));
  for i := Low(Bytes) to High(Bytes) do
    Result[i - Low(Bytes) + 1] := Chr(Bytes[i]);
end;
procedure TDataProcessingThread.ProcessLightStatus(const Device
  : TDeviceCacheEntry; EndpointAddress: Integer;
  const Status: t_HACommand_StatusLight);
Var
  VP: ArrayOfEndpointValue;
  Endpoint: TEndpointCacheEntry;
begin
  if not GetEndpointData(Device.DeviceID, EndpointAddress, Endpoint) then
    Exit; // Unregistered endpoint
  SetLength(VP, 2);
  VP[0] := MakeValueType(EndpointValueType.IsOn,
    iif(Status.LoadStatus = 0, 0, 1));
  VP[1] := MakeValueType(EndpointValueType.Dim, Status.DimValue);
  //UpdateEndpointValues(Endpoint, VP);
end;
procedure TDataProcessingThread.ProcessKeyRequest(EncryptionType: Byte;
  const Packet: THACommand; const Device: TDeviceCacheEntry;
  Socket: TUDPChildSocket);
Var
  Response: THACommand;
begin
  // Verificar si Device.PrivateKey es nulo
  if Device.Secured = False then
    Exit; // Salir de la funci�n si Device.PrivateKey es nulo
  if FLogSecurity then
    LogActivity('', Packet.Header.SourceMAC, EncryptionType, 'KEY_REQUEST');
  Response := MakeResponsePacket(Packet);
  Response.Header.CommandID := HA_JOIN;
  Response.Join.SubCommand := JOIN_COMMAND_SET_KEY_NEW;
  Response.Join.SetKey.Key := Device.PrivateKey;
  if FLogSecurity then
    LogActivity('', Packet.Header.SourceMAC, EncryptionType,
      'KEY_SET; Key=' + BytesToHex(Device.PrivateKey,
      SizeOf(Device.PrivateKey)));
  SendPacket(EncryptionType, Response, 1 + SizeOf(Response.Join.SetKey),
    Device, Socket);
end;
procedure TDataProcessingThread.ProcessPacket(Packet: THACommand; Len: Integer;
  const IPAddress: String; Port: Word; Socket: TUDPChildSocket);
Var
  EncryptionType: Byte;
  Device: TDeviceCacheEntry;
  Endpoint: TEndpointCacheEntry;
  onlineDevice: TDeviceCacheEntry;
  macTemp: TMACAddress;
  DeviceIndex: Integer;
  StringModelFirmware: String;
  tmp_deviceID: Int64;
begin
  // AGREGAR ESTAS LINEAS
  // Check if messages from this device are to be ignored
  if IsIgnoredDevice(Packet.Header.SourceMAC) then
    Exit;
  // PORQUE IP ADDRESSS VENDR�A VACIO?? DETECTANMOS ALGUN CASO? SI NO BORRAR
  // Agrega una validaci�n para asegurarte de que IPAddress no est� vac�o
  if IPAddress = '' then
  begin
    // Puedes manejar el error aqu�, por ejemplo, registrando un mensaje de error o lanzando una excepci�n
    LogActivity('', Packet.Header.SourceMAC, 99,
      'IPAddress is empty for DEVICE.');
    EventLogReportEvent(elWarning,
      Format('IPAddress is empty for DEVICE. MAC Address: %s',
      [MACToStr(Packet.Header.SourceMAC)]));
    Exit;
  end;
  // PORQUE ESTAMOS VERIFICANDO SI ESTA EN LA LISTA INDEPENDIENTEMENTE DE SI EL DISPOSITIVO ESTA ENVIANDO UN MENSAJE VALIDO
  // SOLO DEBER�A HACER ESTE CHEQUEO ANTE KEEP ALIVE, SERVER TIME Y GET PRIVATE KEY? TODO ESTE CODIGO SE EJECUTA
  // INDEPENDIENTEMENTE DE SI EL MENSAJE ES VALIDO, EST� CORRECTAMENTE ENCRIPTADO O SI HAY QUE RESPONDERLO
  // Verifica si el dispositivo ya existe en la lista
  Device.MAC := Packet.Header.SourceMAC;
  EncryptionType := Packet.Header.ProtocolVersion;
  if GetDeviceCacheEntryByMAC(Device.MAC, Device) then
  begin
    UpdateDeviceData(Device, IPAddress, Port, Packet.Header.SequenceNumber,
      EncryptionType, Socket);
  end
  else
  begin
    CreateDeviceData(Device, IPAddress, Port, Packet.Header.SequenceNumber,
      EncryptionType, Socket);
    LogActivity('', Packet.Header.SourceMAC, 99,
      'Device reported (not linked): ' + Device.RemoteIP);
  end;
  if not DecryptPacket(Packet, Len, Device.PrivateKey) then
  begin
    EventLogReportEvent(elWarning,
      Format('Could not decrypt data packet for MAC address %s',
      [MACToStr(Packet.Header.SourceMAC)]));
    Exit;
  end;
  // Si la clave esta seteada fuerzo rapido el envio de clave.
  if Device.Secured then ProcessJoin(EncryptionType, Packet, Device, Socket);
  // Muevo a cola los paquetes
  QueuePacketForListeners(Packet, Len);
  // Process the contents of the packet
  case Packet.Header.CommandID of
    HA_STATUS:
      ProcessStatus(EncryptionType, Packet, Device, Socket);
    HA_ALARM:
      ProcessAlarm(EncryptionType, Packet, Device, Socket);
    HA_BOOT_NOTIFICATION:
      ProcessBootNotification(EncryptionType, Packet, Device, Socket);
    HA_TIME:
      ProcessTime(EncryptionType, Packet, Device, Socket);
    HA_KEEP_ALIVE:
      begin
        try
          RespondACK(EncryptionType, Packet, Device, Socket);
          StringModelFirmware := BytesToString(Packet.Join.JoinRequest.SSID);
          // Capturo modelo y firmware del keep_alive.
          SetDevicePropertiesOnMemory(Device, StringModelFirmware);
          if Device.Linked then
          begin
            HomeCloudPrivateService.UpdateLastDeviceActivity(Device.DeviceID,
              MACToStr(Device.MAC));
            // Notifico estado online del dispositivo al BE.
          end;
        except
          On E: exception do
          begin
            LogActivity('EXCEPTION', Device.MAC, 99, 'Ex Calss: ' + E.ClassName
              + ' || Exception message: ' + E.Message);
          end;
        end;
      end;
    HA_JOIN:
      ProcessJoin(EncryptionType, Packet, Device, Socket);
      // TODO: AGREGAR DISPARO DIRECTO PARA SETEAR LA CLAVE.
    HA_VALUE_PAIR_REPORT:
      ProcessValuePairReport(EncryptionType, Packet, Device, Socket);
    HA_METERING_ELECTRICITY:
      ProcessElectricityMeteringReport(EncryptionType, Packet, Device, Socket);
    HA_DEBUG:
      ProcessDebug(EncryptionType, Packet, Device, Socket);
    HA_EP_MANAGER_COMMAND:
        ProcessEndpointManagerCommand(EncryptionType, Packet, Device, Socket);
    HA_DOORLOCK_COMMAND:
    begin
      if Packet.Header.SourceEndpoint <> 0 then
        Endpoint.EndpointAddress := Packet.Header.SourceEndpoint;
      if (Device.DeviceID <> -1) and (Device.DeviceID <> 0) then
        Endpoint.DeviceID := Device.DeviceID;
      if not GetEndpointData(Device.DeviceID, Packet.Header.SourceEndpoint, Endpoint) then Exit;
      HomeCloudPrivateService.UpdateEndpointLastActivityStatus(Endpoint.DeviceID, Endpoint.EndpointAddress, Packet.Status.Doorlock.Status);
      ProcessDoorLockCommand(EncryptionType, Packet, Device, Socket);
    end;
    HA_ACK:
      ;
    HA_NAK:
      ;
  else
    LogActivity('', Packet.Header.SourceMAC, Device.EncryptionType, Format(
      'Unknown command type: %d (%s). Possible key mismatch?',
      [Packet.Header.CommandID, IntToHex(Packet.Header.CommandID, 2)]));
  end;
end;
procedure TDataProcessingThread.CreateDeviceData(var Device: TDeviceCacheEntry;
  const IPAddress: String; Port: Word; SequenceNumber: Byte;
  EncryptionType: Byte; Socket: TUDPChildSocket);
begin
  if (Device.RemoteIP = IPAddress) and (Device.RemotePort = Port) and
    (Device.Socket = Socket) and (EncryptionType = Device.EncryptionType) then
    Exit;
  Device.RemoteIP := IPAddress;
  Device.RemotePort := Port;
  Device.Socket := Socket;
  Device.EncryptionType := EncryptionType;
  Device.LastInboundSequenceNumber := SequenceNumber;
  Device.Linked := False;
  Device.Secured := False;
  Device.HomeID := -1;
  Device.DeviceID := -1;
  FillChar(Device.PrivateKey, SizeOf(Device.PrivateKey), 0);
  StoreDeviceCacheEntry(Device);
end;
procedure TDataProcessingThread.UpdateDeviceData(var Device: TDeviceCacheEntry;
  const IPAddress: String; Port: Word; SequenceNumber: Byte;
  EncryptionType: Byte; Socket: TUDPChildSocket);
begin
  if (Device.RemoteIP = IPAddress) and (Device.RemotePort = Port) and
    (Device.Socket = Socket) and (EncryptionType = Device.EncryptionType) then
    Exit;
  Device.RemoteIP := IPAddress;
  Device.RemotePort := Port;
  Device.Socket := Socket;
  Device.EncryptionType := EncryptionType;
  Device.LastInboundSequenceNumber := SequenceNumber;
  UpdateDeviceCacheEntry(Device);
end;
procedure TDataProcessingThread.UpdateEndpointValues(var E: TEndpointCacheEntry;
  const Values: ArrayOfEndpointValue; const Status: t_HACommand_StatusDoorlock);
Var
  i: Integer;
begin
 // HomeCloudPrivateService.UpdateEndpointLastActivity(E.DeviceID, E.EndpointAddress, Status.Status);
  if AreDuplicateValues(E, Values) then
  begin
    AddDuplicateStatus();
  end
  else
  begin
    AddStatusCacheMiss();
    for i := Low(Values) to High(Values) do
      SetEndpointValue(Values[i].ValueType, Values[i].Value, E.EndpointValues);
    HomeCloudPrivateService.UpdateEndpointValue(E.DeviceID, E.EndpointAddress, Values);
    StoreEndpointCacheEntry(E);
  end;
end;
initialization
_CritSect := TCriticalSection.Create;
finalization
FreeAndNil(_CritSect);
end.
