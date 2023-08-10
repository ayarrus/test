unit uWebServer;


interface

Uses
    SysUtils, WebSrv, DMIWServices, FoundationTypes, FoundationProcs, System.Generics.Collections, NetCoreServices, uDeviceCache, uCommon, Classes, HabeetatIP, Dialogs, uDataInput;

Type
  TCommandContext = record
    Chain: String;
  end;
  PCommandContext = ^TCommandContext;

  {WSNamespace$ 'http://HomeCloudService.Solidmation.com' }
  {WSUrl$ 'http://localhost:8089/HomeCloudCommandService.asmx' }
  HomeCloudCommandService = class(TWebServiceImplementation)
  strict private
    FHomeCloudPrivateService: NetCoreServicesIns;
    function  HomeCloudPrivateService: NetCoreServicesIns;
  private
    function SimpleCommand(deviceID: Int64; Command: Byte; CommandContext: PCommandContext = nil): Boolean;
    function SimpleCommandMAC(macAddress: String; Command: Byte; CommandContext: PCommandContext = nil): Boolean;
    function MakeCommandResponse(ResponseContract: ResponseContract; ResultOk: Boolean): CommandResponse;
    function MakeResponseContract(ResponseStatus: ResponseStatus; ErrorCode: Integer; const ErrorDescription: String): ResponseContract;
  public
    //Public global list for all devices.
    GlobalDeviceList: TList<Device>;
    // Network
    function UnjoinDevice(macAddress: String): Boolean;
    // On-Off
    function OnOffSwitch(deviceID: Int64; const endpointAddress: String; isOn: Boolean): Boolean;
      function SetAutoOff(deviceID: Int64; const endpointAddress: String; offTimeout: Word): Boolean;
    // Dimmer
    function Dim(deviceID: Int64; const endpointAddress: String; dimValue: Integer): Boolean;
    function SetFadeRate(deviceID: Int64; const endpointAddress: String; fadeRate: Single): Boolean;
    // Curtain
    function CurtainStop(deviceID: Int64; const endpointAddress: String): Boolean;
    function CurtainUp(deviceID: Int64; const endpointAddress: String; stopIfMoving: Boolean): Boolean;
    function CurtainDown(deviceID: Int64; const endpointAddress: String; stopIfMoving: Boolean): Boolean;
    function CurtainSetPosition(deviceID: Int64; const endpointAddress: String; position: Byte): Boolean;
    // HVAC
    function HVACSetModes(deviceID: Int64; const endpointAddress: String; desiredTempC: Double; mode: Byte; fanMode: Byte; flags: Byte): Boolean;
    function HVACSendCommand(deviceID: Int64; const endpointAddress: String; subCommand: Byte): Boolean;
    // Scenes
    function ActivateScene(sceneID: Int64): Boolean;
    function ProgramEndpointScenes(deviceID: Int64; const endpointAddress: String): Boolean;
    // Endpoint enrollment
    function EndpointEnrollmentStart(deviceID: Int64; const endpointAddress, Name: String; const timeOut: Integer): CommandResponse;
    FUNCTION EndpointEnrollmentCancel(deviceID: Int64; const endpointAddress: String): CommandResponse;
    function EndpointEnrollmentGetStatus(deviceID: Int64; const endpointAddress: String): CommandEndpointEnrollmentResponse;
    function EndpointEnrollmentGetAllStatus(): CommandEndpointEnrollmentResponseList;
    function EndpointEnrollmentDelete(deviceID: Int64; const endpointAddress, childEndpointAddress: String): CommandResponse;
    // Door locks
    function DoorlockLockUnlock(deviceID: Int64; const endpointAddress: String; isLocked: Boolean; const entryCode: String): CommandResponse;
    function DoorlockSynchronizeUser(deviceID: Int64; const endpointAddress: String; userID: Integer; enabled: Boolean; const entryCode: String; operationType: SynchronizationOperationType): CommandResponse;
    function DoorlockSynchronizeSlot(deviceID: Int64; const endpointAddress: String; userID: Integer; const slot: AccessControlSlotSyncInfo; operationType: SynchronizationOperationType): CommandResponse;
    // Comandos customizados en cada dispositivo
    function SendCustomCommand(deviceID: Int64; const endpointAddress: String; customCommandID: Byte; const dataBytesBase64: String): Boolean;
    function SendCustomCommandWithResponse(deviceID: Int64; const endpointAddress: String; customCommandID: Byte; const dataBytesBase64: String; out responseCommandID: Byte; out responseBytesBase64: String): Boolean;
    // Mantenimiento
    function UpdateDeviceFirmware(deviceID: Int64; const updateURL: String): Boolean;
    function RebootDevice(deviceID: Int64): Boolean;
    function GetDeviceVersion(deviceID: Int64): CommandDeviceVersionResponse;
    function GetDeviceVersionByAddress(macAddress: string): CommandDeviceVersionResponse;
    function SetCloudNotificationIP(deviceID: Int64; const IPAddress: string): Boolean;
    function GetDeviceByTempAddress(macAddress: string): Device;
    function StoreDeviceByTempAddress(macAddress: string): Boolean;
    function GetDeviceByAddress(const MAC: string): TDeviceCacheEntry;
    function DeleteDeviceByAddress(const MAC: string): Boolean;
    class function StringToMACAddress(MAC: string): TMACAddress;
    class function MACAddressToString(MAC: TMACAddress): string;
    function SetDevicePrivateKeyByAddress(const MAC: string; PrivateKey: string; const DeviceID: Int64; const HomeID: Int64): Boolean;
  end;

procedure StartWebServer(const IPAddresses: String);
procedure StopWebServer;

implementation

Uses
  Util, DMIWSSoap, DMIWSJson, HomeCloudCommand_ServerProxy, AnsiStrings, uPacketCache,
  uEndpointCache, uPacketListeners, EncdDecd, DPSSockets, uEncryption;

const
  TIMEOUT_5_SECONDS  =  5000;
  TIMEOUT_10_SECONDS = 10000;
  TIMEOUT_20_SECONDS = 20000;

Var
  WebServer: TWebServer = nil;
  WSJson: HomeCloudCommand_ServerProxy.HomeCloudCommandService_ServerProxy = nil;

procedure StartWebServer(const IPAddresses: String);
Var
    i: Integer;
    IP: String;
    Bindings: Array of TWebserverBinding;
begin
  try
    // Armamos los bindings
    SetLength(Bindings, 0);
    for i := 1 to MaxInt do begin
        IP := ParseParamByNumber(IPAddresses, i, ',');
        if IP = '' then
          break;
        SetLength(Bindings, Length(Bindings) + 1);
        Bindings[High(Bindings)].Port := 8089;
        Bindings[High(Bindings)].IPAddress := IP;
    end;
    // Creamos el web server
    WebServer := TWebServer.Create(nil);
    // Creamos el Web Service, en versión Soap y Json
    WSJson := HomeCloudCommand_ServerProxy.HomeCloudCommandService_ServerProxy.Create(WebServer, '/command/*', True);
    // Iniciamos el web server
    WebServer.Start(Bindings, '.\', '/');
  except
    WebServer.Free;
    WSJson.Free;
    raise;
  end;
end;

procedure StopWebServer;
begin
  if Assigned(WebServer) then FreeAndNil(WebServer);
  if Assigned(WSJson) then FreeAndNil(WSJson);
end;

procedure EncryptAndSend(Packet: THACommand; DataLen: Integer; EncryptionType: Byte; const Key: TEncryptionKey; const IPAddress: String; Port: Word; Socket: TUDPChildSocket);
Var
    Len: Integer;
begin
    Len := DataLen + SizeOf(THACommandHeader);
    EncryptPacket(Packet, Len, EncryptionType, Key);
    SetOutputPacket(Packet, Len - SizeOf(THACommandHeader), IPAddress, Port, Socket);
end;

function GetResponse(Listener: Pointer; SequenceNumber: Byte; out Pkt: THACommand; TmOutMs: Integer = TIMEOUT_5_SECONDS; CommandContext: PCommandContext = nil): Integer;
Var
  Len: Integer;
  Timeout: Int64;
begin
  Timeout := GetMSCounter + TmOutMs;
  while GetMSCounter < Timeout do begin
    Len := ReadListenerData(Listener, Pkt);
    if (Len > 0) then begin
      if Assigned(CommandContext) then begin
          CommandContext^.Chain := CommandContext^.Chain + ' ' +
            Format('Response={Cmd=%s; Seq=%d}', [IntToHex(Pkt.Header.CommandID, 2), Pkt.Header.SequenceNumber]);
      end;
      if Pkt.Header.SequenceNumber = SequenceNumber then begin
        Result := Len;
        Exit;
      end;
    end else begin
      Sleep(10);
    end;
  end;
  Result := 0;
end;

function CurtainUpDownStop(deviceID: Integer; endpointAddress: String; Command: Byte): Boolean;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  Result := False;
  EndpointNumber := StrToIntDef(endpointAddress, 0);
  if not GetDeviceCacheEntry(deviceID, Device) then Exit;
  if not Assigned(Device.Socket) then Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := Command;

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(Pkt.CurtainPosition), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function CreateCurtainScenePacket(const SceneData: ArrayOfEndpointValuesOfScene): THACommand;
Var
    i: Integer;
begin
    Result := Default(THACommand);
    Result.Scenes.SceneType := SCENE_TYPE_CURTAIN;
    Result.Scenes.SceneCount := Length(SceneData);
    for i := Low(SceneData) to High(SceneData) do begin
        Result.Scenes.CurtainScenes[i].SceneID := DWORDToPortable32(SceneData[i].SceneID);
        Result.Scenes.CurtainScenes[i].Position := GetEndpointValueInt(EndpointValueType.Position, SceneData[i].Values, 0);
    end;
end;

function CreateApplianceScenePacket(const SceneData: ArrayOfEndpointValuesOfScene): THACommand;
Var
    i: Integer;
begin
    Result := Default(THACommand);
    Result.Scenes.SceneType := SCENE_TYPE_LIGHT;
    Result.Scenes.SceneCount := Length(SceneData);
    for i := Low(SceneData) to High(SceneData) do begin
        Result.Scenes.LightScenes[i].SceneID := DWORDToPortable32(SceneData[i].SceneID);
        if GetEndpointValueBoolean(EndpointValueType.IsOn, SceneData[i].Values) then
            Result.Scenes.LightScenes[i].DimLevel := 100
        else begin
            Result.Scenes.LightScenes[i].DimLevel := 0;
        end;
    end;
end;

function HomeCloudCommandService.GetDeviceByTempAddress(macAddress: string): Device;
var
  i: Integer;
begin
  for i := 0 to GlobalDeviceList.Count - 1 do
  begin
    if GlobalDeviceList[i].Address = macAddress then
    begin
      Result := GlobalDeviceList[i];
      Exit;
    end;
  end;
  Result.Address := '';
end;

function HomeCloudCommandService.GetDeviceByAddress(const MAC: string): TDeviceCacheEntry;
var
  Device: TDeviceCacheEntry;
  i: Integer;
  tempMac : string;
  found: Boolean;
begin
  found := False;
  if uDeviceCache.GetDeviceCacheEntry(MAC, Device) then
  begin
  Result := Device;
  found := true;
  end;

  if not found then
  begin
    raise Exception.Create('Device not found in the list by MAC.');
  end;
end;

function HomeCloudCommandService.DeleteDeviceByAddress(const MAC: string): Boolean;
var
  Device: TDeviceCacheEntry;
  i: Integer;
  tempMac : string;
begin
  Result := False;
  if RemoveDeviceCacheEntryByAddress(MAC) then Result := true;
  if not Result then
  begin
    raise Exception.Create('Device not found in the list by MAC.');
  end;
end;

function HomeCloudCommandService.SetDevicePrivateKeyByAddress(const MAC: string; PrivateKey: string; const DeviceID: Int64; const HomeID: Int64): Boolean;
var
  i: Integer;
  tempMac: string;
  found: Boolean;
  BinStream: TMemoryStream;
  Device: TDeviceCacheEntry;
begin
  // Verificar la longitud de la dirección MAC y formatearla correctamente
  if Length(MAC) <> 17 then
    raise Exception.Create('Invalid MAC address.');
  tempMac := UpperCase(MAC);
  if (tempMac[3] <> ':') or (tempMac[6] <> ':') or (tempMac[9] <> ':') or
     (tempMac[12] <> ':') or (tempMac[15] <> ':') then
    raise Exception.Create('Invalid MAC address format.');
  // Verificar la validez de la clave privada
  if PrivateKey = '' then
    raise Exception.Create('Private key cannot be empty.');
  found := False;
    uDeviceCache.GetDeviceCacheEntryByMAC(StringToMACAddress(MAC), Device);
    if HomeCloudCommandService.MACAddressToString(Device.MAC) = tempMac then
    begin
      found := True;
      Device.Linked := true;
      Device.Secured := true;
      Device.DeviceID := DeviceID;
      Device.HomeID := HomeID;
      // Convertir la clave privada de string a TEncryptionKey
      BinStream := TMemoryStream.Create;
      try
        BinStream.SetSize(16); // Tamaño de TEncryptionKey
        HexToBin(PChar(PrivateKey), BinStream.Memory^, 16);
        Move(BinStream.Memory^, Device.PrivateKey, 16);
      finally
        BinStream.Free;
      end;
      // Reemplazar el registro original en la lista con la copia modificada
      UpdateDeviceCacheEntry(Device);
      //TODO: Establecer Fecha y Hora al Hub a partir de  LocalDateTime
      Result := True;
      Exit; // Salir de la función después de encontrar el dispositivo y asignar la clave privada
  end;
  if not found then
    raise Exception.Create('Device not found in the list by MAC.');
end;

class function HomeCloudCommandService.StringToMACAddress(MAC: string): TMACAddress;
var
  Parts: TStringList;
  i: Integer;
begin
  Parts := TStringList.Create;
  try
    Parts.Delimiter := ':';
    Parts.DelimitedText := MAC;
    if Parts.Count <> 6 then
      raise Exception.Create('Invalid MAC address');
    for i := 0 to 5 do
      Result[i] := StrToInt('$' + Parts[i]);
  finally
    Parts.Free;
  end;
end;

class function HomeCloudCommandService.MACAddressToString(MAC: TMACAddress): string;
var
  i: Integer;
begin
  Result := IntToHex(MAC[0], 2);
  for i := 1 to 5 do
    Result := Result + ':' + IntToHex(MAC[i], 2);
end;

function HomeCloudCommandService.StoreDeviceByTempAddress(macAddress: string): Boolean;
var
  i: Integer;
  WS: NetCoreServicesIns;
begin
  WS := InstantiateHomeCloudPrivateService();
  for i := 0 to GlobalDeviceList.Count - 1 do
  begin
    if GlobalDeviceList[i].Address = macAddress then
    begin
      WS.StoreDeviceOnDB(GlobalDeviceList[i]);
      Exit;
    end;
  end;
  Result := true;
end;

function CreateDimmerScenePacket(const SceneData: ArrayOfEndpointValuesOfScene): THACommand;
Var
    i: Integer;
begin
    Result := Default(THACommand);
    Result.Scenes.SceneType := SCENE_TYPE_LIGHT;
    Result.Scenes.SceneCount := Length(SceneData);
    for i := Low(SceneData) to High(SceneData) do begin
        Result.Scenes.LightScenes[i].SceneID := DWORDToPortable32(SceneData[i].SceneID);
        if GetEndpointValueBoolean(EndpointValueType.IsOn, SceneData[i].Values) then
            Result.Scenes.LightScenes[i].DimLevel := GetEndpointValueInt(EndpointValueType.Dim, SceneData[i].Values, 100)
        else begin
            Result.Scenes.LightScenes[i].DimLevel := 0;
        end;
    end;
end;

function CreateThermostatScenePacket(const SceneData: ArrayOfEndpointValuesOfScene): THACommand;
Var
    i: Integer;
    Temp: Double;
begin
    Result := Default(THACommand);
    Result.Scenes.SceneType := SCENE_TYPE_THERMOSTAT;
    Result.Scenes.SceneCount := Length(SceneData);
    for i := Low(SceneData) to High(SceneData) do begin
        Result.Scenes.HVACScenes[i].SceneID     := DWORDToPortable32(SceneData[i].SceneID);
        Result.Scenes.HVACScenes[i].Mode        := GetEndpointValueInt(EndpointValueType.ThermostatMode, SceneData[i].Values, 0);
        Result.Scenes.HVACScenes[i].FanMode     := GetEndpointValueInt(EndpointValueType.ThermostatFanMode, SceneData[i].Values, 0);
        Result.Scenes.HVACScenes[i].Flags       := 0;
        Temp := GetEndpointValueDouble(EndpointValueType.ThermostatDesiredTempC, SceneData[i].Values, 0);
        if (Temp = HVAC_SETPOINT_DO_NOT_CHANGE) then begin
            Result.Scenes.HVACScenes[i].DesiredTemp := WORDToPortable16(WORD(HVAC_SETPOINT_DO_NOT_CHANGE));
        end else begin
            Result.Scenes.HVACScenes[i].DesiredTemp := WORDToPortable16(WORD(Round(Temp * 100)));
        end;
    end;
end;

function _ProgramEndpointScenes(WS: NetCoreServicesIns; const Device: TDeviceCacheEntry; const Endpoint: Endpoint): Boolean;
Var
    L: Pointer;
    Len: integer;
    Pkt, Rsp: THACommand;
    Rsp2: ListOfScenesOfEndpointResponse;
begin
    Result := False;
    WS := InstantiateHomeCloudPrivateService();
    try
        // Get endpoint scenes
        Rsp2 := WS.EnumEndpointScenes(Endpoint.EndpointID);
        if Rsp2.ResponseStatus.Status <> ResponseStatus.Success then
          Exit;
        // Create scene packet
        case Endpoint.EndpointType of
          EndpointType.CurtainController:
            Pkt := CreateCurtainScenePacket(Rsp2.EndpointValuesOfScene);
          EndpointType.Thermostat:
            Pkt := CreateThermostatScenePacket(Rsp2.EndpointValuesOfScene);
          EndpointType.Appliance:
            Pkt := CreateApplianceScenePacket(Rsp2.EndpointValuesOfScene);
          EndpointType.Dimmer:
            Pkt := CreateDimmerScenePacket(Rsp2.EndpointValuesOfScene);
          else
            Pkt := Default(THACommand);
        end;
        Pkt.Header.DestinationMAC := Device.MAC;
        Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
        Pkt.Header.DestinationEndpoint := StrToIntDef(Endpoint.Address, 0);
        Pkt.Header.CommandID := HA_SET_SCENES;

        // Send packet and wait for response
        L := RegisterPacketListener(Pkt.Header.DestinationMAC);
        try
          EncryptAndSend(Pkt, 2 + Length(Pkt.Scenes.CurtainScenes) * SizeOf(t_HA_SceneEntryCurtain), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
          Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
          if Len = 0 then
            Exit;
          Result := Rsp.Header.CommandID = HA_ACK;
        finally
          UnregisterPacketListener(L);
        end;
    finally
        WS.Free;
    end;
end;

function TimeDTToMinutes(const T: TimeDT): Integer;
begin
  Result := T.Hour * 60 + T.Minute;
end;

function _ProgramEndpointSceneSchedules(WS: NetCoreServicesIns; const Device: TDeviceCacheEntry; const Endpoint: Endpoint): Boolean;
Var
    L: Pointer;
    RspS: SceneResponse;
    Pkt, Rsp: THACommand;
    Len, iScene, iSchedule: integer;
    Rsp2: ListOfScenesOfEndpointResponse;
    Schedules: Array of t_HA_SceneScheduleEntry;
begin
    Result := False;
    WS := InstantiateHomeCloudPrivateService();
    try
        // Get endpoint scenes
        Rsp2 := WS.EnumEndpointScenes(Endpoint.EndpointID);
        if Rsp2.ResponseStatus.Status <> ResponseStatus.Success then
          Exit;

        // Extract schedules
        SetLength(Schedules, 0);
        for iScene := Low(Rsp2.EndpointValuesOfScene) to High(Rsp2.EndpointValuesOfScene) do begin
          RspS := WS.GetScene(Rsp2.EndpointValuesOfScene[iScene].SceneID);
          if RspS.ResponseStatus.Status <> ResponseStatus.Success then
            Exit;
          // Triggers for scenes that have them disabled are ignored.
          if RspS.Scene.TriggersAreEnabled then begin
            for iSchedule := Low(RspS.Scene.Triggers) to High(RspS.Scene.Triggers) do begin
              if RspS.Scene.Triggers[iSchedule].TriggerType = TriggerType.Weekly then begin
                 SetLength(Schedules, Length(Schedules) + 1);
                 Schedules[High(Schedules)].SceneID := DWORDToPortable32(RspS.Scene.SceneID);
                 Schedules[High(Schedules)].Time    := DWORDToPortable32(TimeDTToMinutes(RspS.Scene.Triggers[iSchedule].RunningTime) * 60);
                 Schedules[High(Schedules)].Days    :=
                   iif(RspS.Scene.Triggers[iSchedule].OnMonday,    1, 0) +
                   iif(RspS.Scene.Triggers[iSchedule].OnTuesday,   2, 0) +
                   iif(RspS.Scene.Triggers[iSchedule].OnWednesday, 4, 0) +
                   iif(RspS.Scene.Triggers[iSchedule].OnThursday,  8, 0) +
                   iif(RspS.Scene.Triggers[iSchedule].OnFriday,   16, 0) +
                   iif(RspS.Scene.Triggers[iSchedule].OnSaturday, 32, 0) +
                   iif(RspS.Scene.Triggers[iSchedule].OnSunday,   64, 0);
              end;
            end;
          end;
        end;

        // A limited number of schedules can be sent
        if Length(Schedules) > 16 then
          SetLength(Schedules, 16);

        // Create scene schedule packet
        Pkt := Default(THACommand);
        Pkt.Header.DestinationMAC := Device.MAC;
        Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
        Pkt.Header.DestinationEndpoint := StrToIntDef(Endpoint.Address, 0);
        Pkt.Header.CommandID := HA_SET_SCENE_SCHEDULES;
        Pkt.SceneSchedules.ScheduleCount := Length(Schedules);
        for iSchedule := Low(Schedules) to High(Schedules) do
          Pkt.SceneSchedules.Schedules[iSchedule] := Schedules[iSchedule];

        // Send packet and wait for response
        L := RegisterPacketListener(Pkt.Header.DestinationMAC);
        try
          EncryptAndSend(Pkt, 1 + Length(Schedules) * SizeOf(t_HA_SceneScheduleEntry), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
          Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
          if Len = 0 then
            Exit;
          Result := Rsp.Header.CommandID = HA_ACK;
        finally
          UnregisterPacketListener(L);
        end;
    finally
        WS.Free;
    end;
end;

function CreateCommandContext(const Pkt: THACommand): TCommandContext;
begin
    Result.Chain := Format('Request={Cmd=%s; Seq=%d}', [IntToHex(Pkt.Header.CommandID, 2), Pkt.Header.SequenceNumber]);
end;

function StringToMACAddress(MAC: string): TMACAddress;
var
  Parts: TStringList;
  i: Integer;
begin
  Parts := TStringList.Create;
  try
    Parts.Delimiter := ':';
    Parts.DelimitedText := MAC;
    if Parts.Count <> 6 then
      raise Exception.Create('Invalid MAC address');
    for i := 0 to 5 do
      Result[i] := StrToInt('$' + Parts[i]);
  finally
    Parts.Free;
  end;
end;

{ HomeCloudCommandService }

function HomeCloudCommandService.ActivateScene(sceneID: Int64): Boolean;
Var
    i: Integer;
    Pkt: THACommand;
    Rsp: SceneResponse;
    Devices: TDeviceCacheEntryArray;
    WS: NetCoreServicesIns;
begin
    Result := False;
    WS := InstantiateHomeCloudPrivateService();
    try
        Rsp := WS.GetScene(sceneID);
        if (Rsp.ResponseStatus.Status = ResponseStatus.Success) then begin
            Devices := GetDeviceCacheEntriesForHome(Rsp.Scene.HomeID);
            Result := Length(Devices) > 0;
            if Result then begin
                for i := Low(Devices) to High(Devices) do begin
                    if Assigned(Devices[i].Socket) then begin
                        Pkt := Default(THACommand);
                        Pkt.Header.DestinationMAC := Devices[i].MAC;
                        Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Devices[i].DeviceID);
                        Pkt.Header.DestinationEndpoint := 0;
                        Pkt.Header.CommandID := HA_ACTIVATE_SCENE;
                        Pkt.ActivateScene.SceneID := DWORDToPortable32(sceneID);
                        Pkt.ActivateScene.Radius  := 1;
                        EncryptAndSend(Pkt, SizeOf(Pkt.ActivateScene), Devices[i].EncryptionType, Devices[i].PrivateKey, Devices[i].RemoteIP, Devices[i].RemotePort, Devices[i].Socket);
                    end;
                end;
            end;
        end;
    finally
        WS.Free;
    end;
end;

function HomeCloudCommandService.CurtainDown(deviceID: Int64; const endpointAddress: String; stopIfMoving: Boolean): Boolean;
begin
  Result := CurtainUpDownStop(deviceID, endpointAddress, iif(stopIfMoving, HA_CURTAIN_DOWN_STOP, HA_CURTAIN_DOWN));
end;

function HomeCloudCommandService.CurtainSetPosition(deviceID: Int64; const endpointAddress: String; position: Byte): Boolean;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  Result := False;
  EndpointNumber := StrToIntDef(endpointAddress, 0);
  if not GetDeviceCacheEntry(deviceID, Device) then Exit;
  if not Assigned(Device.Socket) then Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_CURTAIN_POSITION;
  Pkt.CurtainPosition.Position := position;

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(Pkt.CurtainPosition), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.CurtainStop(deviceID: Int64; const endpointAddress: String): Boolean;
begin
  Result := CurtainUpDownStop(deviceID, endpointAddress, HA_CURTAIN_STOP);
end;

function HomeCloudCommandService.CurtainUp(deviceID: Int64; const endpointAddress: String; stopIfMoving: Boolean): Boolean;
begin
  Result := CurtainUpDownStop(deviceID, endpointAddress, iif(stopIfMoving, HA_CURTAIN_UP_STOP, HA_CURTAIN_UP));
end;

function HomeCloudCommandService.Dim(deviceID: Int64; const endpointAddress: String; dimValue: Integer): Boolean;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  Result := False;
  EndpointNumber := StrToIntDef(endpointAddress, 0);
  if not GetDeviceCacheEntry(deviceID, Device) then Exit;
  if not Assigned(Device.Socket) then Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_DIM;
  Pkt.Dim.DimValue := DimValue;

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(Pkt.Dim), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.DoorlockLockUnlock(deviceID: Int64; const endpointAddress: String; isLocked: Boolean; const entryCode: String): CommandResponse;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Context: TCommandContext;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  EndpointNumber := StrToIntDef(endpointAddress, 0);

  if not GetDeviceCacheEntry(deviceID, Device) then
    Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.BusinessError, 5002, 'Unknown device ID'), False));

  if not Assigned(Device.Socket) then
    Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, 'No active socket for the given device ID'), False));

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_DOORLOCK_COMMAND;
  if isLocked then begin
      Pkt.DoorLock.SubCommand := DOORLOCK_LOCK;
      AnsiStrings.StrLCopy(@Pkt.DoorLock.Lock, PAnsiChar(UTF8Encode(entryCode)), SizeOf(Pkt.DoorLock.Lock.PIN));
  end else begin
      Pkt.DoorLock.SubCommand := DOORLOCK_UNLOCK;
      AnsiStrings.StrLCopy(@Pkt.Doorlock.Unlock, PAnsiChar(UTF8Encode(entryCode)), SizeOf(Pkt.Doorlock.Unlock.PIN));
  end;

  Context := CreateCommandContext(Pkt);
  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(Pkt.DoorLock), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp, TIMEOUT_20_SECONDS, @Context);
    if Len = 0 then
      Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, 'Timeout: no response from the device. ' + Context.Chain), False));
    if Rsp.Header.CommandID <> HA_ACK then
      Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, Format('Unexpected response. ' + Context.Chain, [Rsp.Header.CommandID])), False));
    Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, ''), True);
  finally
    UnregisterPacketListener(L);
  end;
end;

function HomeCloudCommandService.DoorlockSynchronizeSlot(deviceID: Int64; const endpointAddress: String; userID: Integer; const slot: AccessControlSlotSyncInfo; operationType: SynchronizationOperationType): CommandResponse;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Context: TCommandContext;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  EndpointNumber := StrToIntDef(endpointAddress, 0);

  if not GetDeviceCacheEntry(deviceID, Device) then
    Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.BusinessError, 5002, 'Unknown device ID'), False));

  if not Assigned(Device.Socket) then
    Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, 'No active socket for the given device ID'), False));

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_DOORLOCK_COMMAND;
  if operationType = SynchronizationOperationType.StoreOp then begin
      Pkt.DoorLock.SubCommand := DOORLOCK_ACCESS_SLOT_UPD;
      Pkt.DoorLock.AccessSlotUpdate.UserID := userID;
      Pkt.DoorLock.AccessSlotUpdate.AccessSlotID := slot.SlotID;
      Pkt.DoorLock.AccessSlotUpdate.DoW          :=
        iif(slot.OnMonday,    1 shl (TIME_DOW_MONDAY - 1),    0) +
        iif(slot.OnTuesday,   1 shl (TIME_DOW_TUESDAY - 1),   0) +
        iif(slot.OnWednesday, 1 shl (TIME_DOW_WEDNESDAY - 1), 0) +
        iif(slot.OnThursday,  1 shl (TIME_DOW_THURSDAY - 1),  0) +
        iif(slot.OnFriday,    1 shl (TIME_DOW_FRIDAY - 1),    0) +
        iif(slot.OnSaturday,  1 shl (TIME_DOW_SATURDAY - 1),  0) +
        iif(slot.OnSunday,    1 shl (TIME_DOW_SUNDAY - 1),    0);
      Pkt.DoorLock.AccessSlotUpdate.StartTime := WORDToPortable16(TimeDTToSeconds(slot.TimeFrom) div 60);
      Pkt.DoorLock.AccessSlotUpdate.EndTime   := WORDToPortable16(TimeDTToSeconds(slot.TimeTo) div 60);
      Pkt.DoorLock.AccessSlotUpdate.Enabled   := 1;
  end else begin
      Pkt.DoorLock.SubCommand := DOORLOCK_ACCESS_SLOT_DEL;
      Pkt.DoorLock.AccessSlot.UserID := userID;
      Pkt.DoorLock.AccessSlot.AccessSlotID := slot.SlotID;
  end;

  Context := CreateCommandContext(Pkt);
  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(Pkt.DoorLock), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp, TIMEOUT_20_SECONDS, @Context);
    if Len = 0 then
      Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, 'Timeout: no response from the device. ' + Context.Chain), False));
    if Rsp.Header.CommandID <> HA_ACK then
      Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, Format('Unexpected response. ' + Context.Chain, [Rsp.Header.CommandID])), False));
    Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, Context.Chain), True);
  finally
    UnregisterPacketListener(L);
  end;
end;

function HomeCloudCommandService.DoorlockSynchronizeUser(deviceID: Int64; const endpointAddress: String; userID: Integer; enabled: Boolean; const entryCode: String; operationType: SynchronizationOperationType): CommandResponse;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Context: TCommandContext;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
  LogFile: TextFile;
  LogFileName: string;
begin
  EndpointNumber := StrToIntDef(endpointAddress, 0);

  if not GetDeviceCacheEntry(deviceID, Device) then
    Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.BusinessError, 5002, 'Unknown device ID'), False));

  if not Assigned(Device.Socket) then
    Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, 'No active socket for the given device ID'), False));

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_DOORLOCK_COMMAND;
  if operationType = SynchronizationOperationType.StoreOp then begin
      Pkt.DoorLock.SubCommand := DOORLOCK_USER_UPD;
      Pkt.DoorLock.UserUpdate.UserID := userID;
      AnsiStrings.StrLCopy(@Pkt.DoorLock.UserUpdate.PIN, PAnsiChar(AnsiString(UTF8Encode(entryCode))), DOORLOCK_USER_PIN_MAXLEN);
      Pkt.DoorLock.UserUpdate.Enabled := iif(enabled, 1, 0);
  end else begin
      Pkt.DoorLock.SubCommand := DOORLOCK_USER_DEL;
      Pkt.DoorLock.User.UserID := userID;
  end;

  // Define el nombre del archivo de log
  LogFileName := 'PacketLog.txt';

  // Abre el archivo de log para escribir
  AssignFile(LogFile, LogFileName);

  // Si el archivo ya existe, añade a él. Si no, crea uno nuevo.
  if FileExists(LogFileName) then
    Append(LogFile)
  else
    Rewrite(LogFile);

  // Escribe los datos del paquete en el archivo de log
  WriteLn(LogFile, 'Destination MAC: ', MACToStr(Pkt.Header.DestinationMAC));
  WriteLn(LogFile, 'Sequence Number: ', Pkt.Header.SequenceNumber);
  WriteLn(LogFile, 'Destination Endpoint: ', Pkt.Header.DestinationEndpoint);
  WriteLn(LogFile, 'Command ID: ', Pkt.Header.CommandID);
  if operationType = SynchronizationOperationType.StoreOp then begin
    WriteLn(LogFile, 'Sub Command: DOORLOCK_USER_UPD');
    WriteLn(LogFile, 'User ID: ', Pkt.DoorLock.UserUpdate.UserID);
    WriteLn(LogFile, 'PIN: ', PAnsiChar(@Pkt.DoorLock.UserUpdate.PIN));
    WriteLn(LogFile, 'Enabled: ', Pkt.DoorLock.UserUpdate.Enabled);
  end else begin
    WriteLn(LogFile, 'Sub Command: DOORLOCK_USER_DEL');
    WriteLn(LogFile, 'User ID: ', Pkt.DoorLock.User.UserID);
  end;

  // Cierra el archivo de log
  CloseFile(LogFile);

  Context := CreateCommandContext(Pkt);
  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(Pkt.DoorLock), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp, TIMEOUT_20_SECONDS, @Context);
    if Len = 0 then
      Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, 'Timeout: no response from the device. ' + Context.Chain), False));
    if Rsp.Header.CommandID <> HA_ACK then
      Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, Format('Unexpected response. ' + Context.Chain, [Rsp.Header.CommandID])), False));
    Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, ''), True);
  finally
    UnregisterPacketListener(L);
  end;
end;

function HomeCloudCommandService.EndpointEnrollmentStart(deviceID: Int64; const endpointAddress, Name: String; const timeOut: Integer): CommandResponse;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Context: TCommandContext;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  EndpointNumber := StrToIntDef(endpointAddress, 0);

  if not GetDeviceCacheEntry(deviceID, Device) then
    Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.BusinessError, 5002, 'Unknown device ID'), False));

  if not Assigned(Device.Socket) then
    Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, 'No active socket for the given device ID'), False));

  //ClearEndpointCacheEnrollmentResult(deviceMAC, EndpointNumber);

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_EP_MANAGER_COMMAND;
  Pkt.EndpointManager.SubCommand := ENDPOINT_MANAGER_ENROLL;
  AnsiStrings.StrLCopy(PAnsiChar(@Pkt.EndpointManager.Enroll.Name[0]), PAnsiChar(UTF8Encode(Name)), SizeOf(Pkt.EndpointManager.Enroll.Name));
  Pkt.EndpointManager.Enroll.Timeout := WORDToPortable16(timeOut);

  Context := CreateCommandContext(Pkt);
  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(Pkt.EndpointManager), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp, TIMEOUT_10_SECONDS, @Context);
    if Len = 0 then
      Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, 'Timeout: no response from the device. ' + Context.Chain), False));
    if Rsp.Header.CommandID <> HA_ACK then
      Exit(MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, Format('Unexpected response. ' + Context.Chain, [Rsp.Header.CommandID])), False));
    Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, ''), True);
  finally
    UnregisterPacketListener(L);
  end;
end;

function HomeCloudCommandService.GetDeviceVersion(deviceID: Int64): CommandDeviceVersionResponse;

  function MakeDeviceVersionResponse(const CommandResponse: ResponseContract; CommandResult: Boolean; const Version: String): CommandDeviceVersionResponse;
  begin
    Result := Default(CommandDeviceVersionResponse);
    Result.ResponseStatus := CommandResponse;
    Result.Result := CommandResult;
    Result.Version := Version;
  end;

Var
  L: Pointer;
  Len: Integer;
  Pkt, Rsp: THACommand;
  Context: TCommandContext;
  Device: TDeviceCacheEntry;
begin
  if not GetDeviceCacheEntry(deviceID, Device) then
    Exit(MakeDeviceVersionResponse(MakeResponseContract(ResponseStatus.BusinessError, 5002, 'Unknown device ID'), False, ''));

  if not Assigned(Device.Socket) then
    Exit(MakeDeviceVersionResponse(MakeResponseContract(ResponseStatus.Success, 0, 'No active socket for the given device ID'), False, ''));

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.CommandID := HA_GET_VERSION;

  Context := CreateCommandContext(Pkt);
  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, 0, Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp, TIMEOUT_10_SECONDS, @Context);
    if Len = 0 then
      Exit(MakeDeviceVersionResponse(MakeResponseContract(ResponseStatus.Success, 0, 'Timeout: no response from the device. ' + Context.Chain), False, ''));
    if Rsp.Header.CommandID <> HA_VERSION then
      Exit(MakeDeviceVersionResponse(MakeResponseContract(ResponseStatus.Success, 0, Format('Unexpected response. ' + Context.Chain, [Rsp.Header.CommandID])), False, ''));
    Result := MakeDeviceVersionResponse(MakeResponseContract(ResponseStatus.Success, 0, ''), True, UTF8ToString(AnsiStrings.StrPas(@Rsp.AppVersion.Version)));
  finally
    UnregisterPacketListener(L);
  end;
end;

function HomeCloudCommandService.GetDeviceVersionByAddress(macAddress: string): CommandDeviceVersionResponse;
  function MakeDeviceVersionResponse(const CommandResponse: ResponseContract; CommandResult: Boolean; const Version: String): CommandDeviceVersionResponse;
  begin
    Result := Default(CommandDeviceVersionResponse);
    Result.ResponseStatus := CommandResponse;
    Result.Result := CommandResult;
    Result.Version := Version;
  end;
Var
  L: Pointer;
  Len: Integer;
  Pkt, Rsp: THACommand;
  Context: TCommandContext;
  Device: TDeviceCacheEntry;
  macAddressFinal: TMACAddress;
begin
  Device := GetDeviceByAddress(macAddress);
  if Device.RemoteIP = '' then
    Exit(MakeDeviceVersionResponse(MakeResponseContract(ResponseStatus.Success, 0, 'No active IP for device address'), False, ''));
  if not Assigned(Device.Socket) then
    Exit(MakeDeviceVersionResponse(MakeResponseContract(ResponseStatus.Success, 0, 'No active socket for the given device address'), False, ''));
  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := Device.LastInboundSequenceNumber;
  Pkt.Header.CommandID := HA_GET_VERSION;
  Context := CreateCommandContext(Pkt);
  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, 0, Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp, TIMEOUT_10_SECONDS, @Context);
    if Len = 0 then
      Exit(MakeDeviceVersionResponse(MakeResponseContract(ResponseStatus.Success, 0, 'Timeout: no response from the device. ' + Context.Chain), False, ''));
    if Rsp.Header.CommandID <> HA_VERSION then
      Exit(MakeDeviceVersionResponse(MakeResponseContract(ResponseStatus.Success, 0, Format('Unexpected response. ' + Context.Chain, [Rsp.Header.CommandID])), False, ''));
    Result := MakeDeviceVersionResponse(MakeResponseContract(ResponseStatus.Success, 0, ''), True, UTF8ToString(AnsiStrings.StrPas(@Rsp.AppVersion.Version)));
  finally
    UnregisterPacketListener(L);
  end;
end;

function HomeCloudCommandService.EndpointEnrollmentCancel(deviceID: Int64; const endpointAddress: String): CommandResponse;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  EndpointNumber := StrToIntDef(endpointAddress, 0);

  if not GetDeviceCacheEntry(deviceID, Device) then begin
      Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.BusinessError, 5002, 'Unknown device ID'), False);
      Exit;
  end;

  Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, ''), False);

  if not Assigned(Device.Socket) then
    Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_EP_MANAGER_COMMAND;
  Pkt.EndpointManager.SubCommand := ENDPOINT_MANAGER_CANCEL;

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(Pkt.EndpointManager), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    if Rsp.Header.CommandID <> HA_ACK then
      Exit;
    Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, ''), True);
  finally
    UnregisterPacketListener(L);
  end;
end;

function HomeCloudCommandService.EndpointEnrollmentDelete(deviceID: Int64; const endpointAddress, childEndpointAddress: String): CommandResponse;
var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, ChildEndpointNumber, Len: Integer;
begin
  EndpointNumber := StrToIntDef(endpointAddress, 0);
  if EndpointNumber = 0 then
  begin
    Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.BusinessError, 5001, 'Invalid endpoint address'), False);
    Exit;
  end;

  ChildEndpointNumber := StrToIntDef(childEndpointAddress, 0);
  if ChildEndpointNumber = 0 then
  begin
    Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.BusinessError, 5006, 'Invalid childendpoint address'), False);
    Exit;
  end;

  if not GetDeviceCacheEntry(deviceID, Device) then
  begin
    Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.BusinessError, 5002, 'Unknown device ID'), False);
    Exit;
  end;

  if not Assigned(Device.Socket) then
  begin
    Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.BusinessError, 5003, 'Device socket not assigned'), False);
    Exit;
  end;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_EP_MANAGER_COMMAND;
  Pkt.EndpointManager.SubCommand := ENDPOINT_MANAGER_DISCONNECT;
  Pkt.EndpointManager.Disconnect.ManagedEndpointNumber := ChildEndpointNumber;

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(Pkt.EndpointManager), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
    begin
      Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.BusinessError, 5004, 'No response received'), False);
      Exit;
    end;
    if Rsp.Header.CommandID <> HA_ACK then
    begin
      Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.BusinessError, 5005, 'Unexpected command ID in response'), False);
      Exit;
    end;
    Result := MakeCommandResponse(MakeResponseContract(ResponseStatus.Success, 0, ''), True);
  finally
    UnregisterPacketListener(L);
  end;
end;

function HomeCloudCommandService.EndpointEnrollmentGetStatus(deviceID: Int64; const endpointAddress: String): CommandEndpointEnrollmentResponse;
Var
    EndpointNumber: Integer;
    ERes: t_HAEndpointManager_EnrollmentResult;
begin
    Result := Default(CommandEndpointEnrollmentResponse);
    EndpointNumber := StrToIntDef(endpointAddress, 0);
    Result.ResponseStatus := MakeResponseContract(ResponseStatus.Success, 0, '');
    if GetEndpointCacheEnrollmentResult(deviceID, EndpointNumber, ERes) then begin
        Result.Result := True;
        Result.Information.EnrollmentStatus := ERes.EnrollmentStatus;
        Result.Information.ManagedEndpointAddress := IntToStr(ERes.ManagedEndpointNumber);
        Result.Information.EndpointType := ERes.Descriptor.EndpointType;
        Result.Information.Name := UTF8ToString(PAnsiChar(@ERes.Descriptor.Name));
        Result.Information.Model := UTF8ToString(PAnsiChar(@ERes.Descriptor.Model));
        Result.Information.ID := UTF8ToString(PAnsiChar(@ERes.Descriptor.ID));
    end else begin
        Result.Result := False;
    end;
end;

function HomeCloudCommandService.EndpointEnrollmentGetAllStatus(): CommandEndpointEnrollmentResponseList;
Var
  ERes: t_HAEndpointManager_EnrollmentResult;
  L: TList<TEnrollmentResultEntry>;
  I: Integer;
  Info: EndpointEnrollmentInformation;
  InfoList: TList<EndpointEnrollmentInformation>;  // Lista genérica
begin
  Result := Default(CommandEndpointEnrollmentResponseList);
  Result.ResponseStatus := MakeResponseContract(ResponseStatus.Success, 0, '');
  L := GetAllEndpointCacheEnrollmentResult();

  InfoList := TList<EndpointEnrollmentInformation>.Create;  // Crear la lista

  for I := 0 to L.Count - 1 do
  begin
    ERes := L[I].Result;
    Info.EnrollmentStatus := ERes.EnrollmentStatus;
    Info.ManagedEndpointAddress := IntToStr(ERes.ManagedEndpointNumber);
    Info.EndpointType := ERes.Descriptor.EndpointType;
    Info.Name := UTF8ToString(PAnsiChar(@ERes.Descriptor.Name));
    Info.Model := UTF8ToString(PAnsiChar(@ERes.Descriptor.Model));
    Info.ID := UTF8ToString(PAnsiChar(@ERes.Descriptor.ID));
    InfoList.Add(Info);  // Agregar a la lista
  end;

  // Asignar los elementos de la lista al array
  SetLength(Result.Information, InfoList.Count);
  for I := 0 to InfoList.Count - 1 do
    Result.Information[I] := InfoList[I];

  InfoList.Free;  // Liberar la lista

  Result.Result := True;
end;

function HomeCloudCommandService.SetFadeRate(deviceID: Int64; const endpointAddress: String; fadeRate: Single): Boolean;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  Result := False;
  EndpointNumber := StrToIntDef(endpointAddress, 0);
  if not GetDeviceCacheEntry(deviceID, Device) then Exit;
  if not Assigned(Device.Socket) then Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_SET_FADE_RATE;
  Pkt.SetFadeRate.FadeRate := Round(fadeRate * 10);

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(t_HACommand_SetFadeRate), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.HVACSendCommand(deviceID: Int64; const endpointAddress: String; subCommand: Byte): Boolean;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
  Endpoint: TEndpointCacheEntry;
begin
  Result := False;
  EndpointNumber := StrToIntDef(endpointAddress, 0);
  if not GetDeviceCacheEntry(deviceID, Device) then Exit;
  if not Assigned(Device.Socket) then Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_HVAC_COMMAND;
  Pkt.HVACCommand.Command := subCommand;

  // Invalidate endpoint values for this endpoint, to make sure the next status
  // report makes it to the database even if nothing changed.
  if GetEndpointCacheEntry(deviceID, EndpointNumber, Endpoint) then
    InvalidateEndpointValuesInCache(Endpoint.EndpointID);

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, 1, Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.HVACSetModes(deviceID: Int64; const endpointAddress: String; desiredTempC: Double; mode, fanMode, flags: Byte): Boolean;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
  Endpoint: TEndpointCacheEntry;
begin
  Result := False;
  EndpointNumber := StrToIntDef(endpointAddress, 0);
  if not GetDeviceCacheEntry(deviceID, Device) then Exit;
  if not Assigned(Device.Socket) then Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_HVAC_SET_MODE;
  Pkt.HVACSetMode.Mode := mode;
  Pkt.HVACSetMode.FanMode := fanMode;
  Pkt.HVACSetMode.Flags := flags;
  Pkt.HVACSetMode.DesiredTemp := WORDToPortable16(Word(SmallInt(Round(desiredTempC * 100))));

  // Invalidate endpoint values for this endpoint, to make sure the next status
  // report makes it to the database even if nothing changed.
  if GetEndpointCacheEntry(deviceID, EndpointNumber, Endpoint) then
    InvalidateEndpointValuesInCache(Endpoint.EndpointID);

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(Pkt.HVACSetMode), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.MakeCommandResponse(ResponseContract: ResponseContract; ResultOk: Boolean): CommandResponse;
begin
    Result.ResponseStatus := ResponseContract;
    Result.Result := ResultOk;
end;

function HomeCloudCommandService.MakeResponseContract(ResponseStatus: ResponseStatus; ErrorCode: Integer; const ErrorDescription: String): ResponseContract;
begin
    Result.Status := ResponseStatus;
    if (Trim(ErrorDescription) = '') and (ErrorCode = 0) then begin
        SetLength(Result.Messages, 0);
    end else begin
        SetLength(Result.Messages, 1);
        Result.Messages[0].Code := ErrorCode;
        Result.Messages[0].Description := ErrorDescription;
    end;
end;

function HomeCloudCommandService.OnOffSwitch(deviceID: Int64; const endpointAddress: String; isOn: Boolean): Boolean;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  Result := False;
  EndpointNumber := StrToIntDef(endpointAddress, 0);
  if not GetDeviceCacheEntry(deviceID, Device) then Exit;
  if not Assigned(Device.Socket) then Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := iif(IsOn, HA_LIGHT_ON, HA_LIGHT_OFF);

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, 0, Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.SetAutoOff(deviceID: Int64; const endpointAddress: String; offTimeout: Word): Boolean;
Var
  L: Pointer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  Result := False;
  EndpointNumber := StrToIntDef(endpointAddress, 0);
  if not GetDeviceCacheEntry(deviceID, Device) then Exit;
  if not Assigned(Device.Socket) then Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_SET_AUTO_OFF;
  Pkt.SetAutoOff.OffTimeout := WORDToPortable16(offTimeout);

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, SizeOf(t_HACommand_SetAutoOff), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.SetCloudNotificationIP(deviceID: Int64; const IPAddress: string): Boolean;
Var
  L: Pointer;
  Len: Integer;
  B: RawByteString;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
begin
  Result := False;

  if not GetDeviceCacheEntry(deviceID, Device)
    or not Assigned(Device.Socket) then
    Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.CommandID := HA_JOIN;
  Pkt.Join.SubCommand := JOIN_COMMAND_SET_CLOUD_NOTIFICATION_IP;
  B := RawByteString(IPAddress);
  if Length(B) > 0 then
    Move(B[1], Pkt.Join.CloudNotificationIP.Address, Length(B));

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, Length(B), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.ProgramEndpointScenes(deviceID: Int64; const endpointAddress: String): Boolean;
Var
    Rsp: EndpointResponse;
    Device: TDeviceCacheEntry;
    WS: NetCoreServicesIns;
begin
    Result := False;
    if not GetDeviceCacheEntry(deviceID, Device) or (Device.Socket = nil) then
      Exit;

    WS := InstantiateHomeCloudPrivateService();
    try
        // Get endpoint data
        Rsp := WS.GetEndpointByAddress(deviceID, endpointAddress);
        if Rsp.ResponseStatus.Status <> ResponseStatus.Success then
          Exit;
        // Program endpoint scenes
        Result := _ProgramEndpointScenes(WS, Device, Rsp.Endpoint);
        // Program endpoint scene schedules
        if Result then
          Result := _ProgramEndpointSceneSchedules(WS, Device, Rsp.Endpoint);
    finally
        WS.Free;
    end;
end;

function HomeCloudCommandService.RebootDevice(deviceID: Int64): Boolean;
begin
  Result := SimpleCommand(deviceID, HA_REBOOT);
end;

function HomeCloudCommandService.SendCustomCommand(deviceID: Int64; const endpointAddress: String; customCommandID: Byte; const dataBytesBase64: String): Boolean;
Var
  L: Pointer;
  DataBytes: TBytes;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  Result := False;
  EndpointNumber := StrToIntDef(endpointAddress, 0);
  DataBytes := DecodeBase64(AnsiString(dataBytesBase64));

  if not GetDeviceCacheEntry(deviceID, Device)
    or not Assigned(Device.Socket) then
    Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_CUSTOM_COMMAND;
  Pkt.CustomCommand.Command := customCommandID;
  if Length(dataBytes) > 0 then
    Move(dataBytes[0], Pkt.CustomCommand.Data, Length(dataBytes));

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, 1 + Length(DataBytes), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID in [HA_ACK, HA_CUSTOM_COMMAND]);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.SendCustomCommandWithResponse(deviceID: Int64;
  const endpointAddress: String; customCommandID: Byte;
  const dataBytesBase64: String; out responseCommandID: Byte;
  out responseBytesBase64: String): Boolean;
Var
  L: Pointer;
  DataBytes: TBytes;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
  EndpointNumber, Len: Integer;
begin
  Result := False;
  EndpointNumber := StrToIntDef(endpointAddress, 0);
  DataBytes := DecodeBase64(AnsiString(dataBytesBase64));

  if not GetDeviceCacheEntry(deviceID, Device)
    or not Assigned(Device.Socket) then
    Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.DestinationEndpoint := EndpointNumber;
  Pkt.Header.CommandID := HA_CUSTOM_COMMAND;
  Pkt.CustomCommand.Command := customCommandID;
  if Length(dataBytes) > 0 then
    Move(dataBytes[0], Pkt.CustomCommand.Data, Length(dataBytes));

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, 1 + Length(DataBytes), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp, TIMEOUT_10_SECONDS);
    if (Len = 0) or not (Rsp.Header.CommandID in [HA_ACK, HA_CUSTOM_COMMAND]) then
      Exit;
    // Extract response data
    responseCommandID := 0;
    responseBytesBase64 := '';
    if (Rsp.Header.CommandID = HA_CUSTOM_COMMAND) and (Len > SizeOf(THACommandHeader)) then begin
        responseCommandID := Rsp.CustomCommand.Command;
        if Len > SizeOf(THACommandHeader) + 1 then
          responseBytesBase64 := String(EncodeBase64(@Rsp.CustomCommand.Data, Len - SizeOf(THACommandHeader) - 1));
    end;
    Exit(True);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.SimpleCommand(deviceID: Int64; Command: Byte; CommandContext: PCommandContext = nil): Boolean;
Var
  L: Pointer;
  Len: Integer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
begin
  Result := False;

  if not GetDeviceCacheEntry(deviceID, Device)
    or not Assigned(Device.Socket) then
    Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.CommandID := Command;
  if Assigned(CommandContext) then
    CommandContext^ := CreateCommandContext(Pkt);

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, 0, Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp, 5000, CommandContext);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.SimpleCommandMAC(macAddress: String; Command: Byte; CommandContext: PCommandContext = nil): Boolean;
Var
  L: Pointer;
  Len: Integer;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
begin
  Result := False;

  Device := GetDeviceByAddress(macAddress);
  if not Assigned(Device.Socket) then
    Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.CommandID := Command;
  if Assigned(CommandContext) then
    CommandContext^ := CreateCommandContext(Pkt);

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, 0, Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp, 5000, CommandContext);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.UnjoinDevice(macAddress: String): Boolean;
var
  DeviceIndex: Int64;
begin
  Result := SimpleCommandMAC(macAddress, HA_LEAVE);
  if Result then
    DeleteDeviceByAddress(macAddress);
end;

function HomeCloudCommandService.UpdateDeviceFirmware(deviceID: Int64; const updateURL: String): Boolean;
Var
  L: Pointer;
  Len: Integer;
  B: RawByteString;
  Pkt, Rsp: THACommand;
  Device: TDeviceCacheEntry;
begin
  Result := False;

  if not GetDeviceCacheEntry(deviceID, Device)
    or not Assigned(Device.Socket) then
    Exit;

  Pkt := Default(THACommand);
  Pkt.Header.DestinationMAC := Device.MAC;
  Pkt.Header.SequenceNumber := CreateDeviceOutboundSequenceNumber(Device.DeviceID);
  Pkt.Header.CommandID := HA_UPGRADE;
  B := RawByteString(updateURL);
  if Length(B) > 0 then
    Move(B[1], Pkt.Upgrade.Data, Length(B));

  L := RegisterPacketListener(Device.MAC);
  try
    EncryptAndSend(Pkt, Length(B), Device.EncryptionType, Device.PrivateKey, Device.RemoteIP, Device.RemotePort, Device.Socket);
    Len := GetResponse(L, Pkt.Header.SequenceNumber, Rsp);
    if Len = 0 then
      Exit;
    Exit(Rsp.Header.CommandID = HA_ACK);
  finally
    UnregisterPacketListener(L);
  end;
  Result := False;
end;

function HomeCloudCommandService.HomeCloudPrivateService: NetCoreServicesIns;
begin
    if not Assigned(FHomeCloudprivateService) then
      FHomeCloudprivateService := InstantiateHomeCloudPrivateService();
    Result := FHomeCloudprivateService;
end;

end.
