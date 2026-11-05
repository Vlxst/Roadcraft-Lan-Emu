#include "emu.h"
#include "licenses.h"
#include "instance.h"
#include "steam_identity.h"
#include <sddl.h>
#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <iomanip>
namespace emu {
std::atomic<bool> stopping{false};HMODULE module=nullptr,sdk=nullptr;uintptr_t game=0;
std::filesystem::path directory;std::string identity,alias;unsigned portOffset=0;
namespace {std::mutex taskMutex,logMutex;std::deque<std::function<void()>> tasks;std::atomic<unsigned> status{0};InstanceLease instanceLease;std::string logName;}
void log(const std::string& event,Json fields){if(fields.contains("event"))fields["kind"]=event;else fields["event"]=event;fields["pid"]=GetCurrentProcessId();fields["time"]=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();std::lock_guard<std::mutex> lock(logMutex);if(directory.empty())return;if(logName.empty())logName="native-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(fields["time"].get<int64_t>())+".jsonl";std::ofstream out(directory/L"logs"/logName,std::ios::app);out<<fields.dump()<<'\n';}
void enqueue(std::function<void()> callback){if(stopping)return;std::lock_guard<std::mutex> lock(taskMutex);tasks.push_back(std::move(callback));}
void drainTasks(){std::deque<std::function<void()>> work;{std::lock_guard<std::mutex> lock(taskMutex);work.swap(tasks);}for(auto& task:work)task();}
bool hookAddress(void* address,void* replacement,void** original){void* ignored=nullptr;auto result=MH_CreateHook(address,replacement,original?original:&ignored);if(result!=MH_OK){log("hook_failed",{{"minhook",MH_StatusToString(result)}});return false;}return MH_QueueEnableHook(address)==MH_OK;}
bool hook(const char* name,void* replacement,void** original){auto address=GetProcAddress(sdk,name);if(!address){log("missing_export",{{"name",name}});return false;}return hookAddress(reinterpret_cast<void*>(address),replacement,original);}
std::string randomHex(size_t bytes){std::vector<unsigned char> data(bytes);if(BCryptGenRandom(nullptr,data.data(),static_cast<ULONG>(bytes),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw std::runtime_error("random generation");std::ostringstream out;for(auto value:data)out<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<unsigned>(value);return out.str();}
std::string uuid(){auto value=randomHex(16);value[12]='4';value[16]="89ab"[(value[16]-'0')&3];return value.substr(0,8)+"-"+value.substr(8,4)+"-"+value.substr(12,4)+"-"+value.substr(16,4)+"-"+value.substr(20);}
static std::filesystem::path userDirectory(){
 std::wstring environment(32768,L'\0');DWORD n=GetEnvironmentVariableW(L"LOCALAPPDATA",environment.data(),static_cast<DWORD>(environment.size()));if(!n||n>=environment.size())throw std::runtime_error("LOCALAPPDATA unavailable");environment.resize(n);
 HANDLE token=nullptr;std::wstring sid=L"unknown";
 if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)){DWORD bytes=0;GetTokenInformation(token,TokenUser,nullptr,0,&bytes);std::vector<unsigned char> storage(bytes);if(GetTokenInformation(token,TokenUser,storage.data(),bytes,&bytes)){LPWSTR text=nullptr;if(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid,&text)){sid=text;LocalFree(text);}}CloseHandle(token);}
 return std::filesystem::path(environment)/L"ProsNativeLAN"/sid;
}
static void chooseInstance(){instanceLease.acquire();portOffset=instanceLease.offset;log("instance_reserved",{{"instance",portOffset/10+1},{"modioPort",18630+portOffset},{"echoPort",18632+portOffset},{"turnPort",18633+portOffset}});}
bool ensureSteamIdentity(){
 if(identityReady.load(std::memory_order_acquire))return true;
 static std::mutex mutex;std::lock_guard<std::mutex> lock(mutex);if(identityReady.load(std::memory_order_relaxed))return true;
 try{auto steamID=currentSteamID();if(!steamID)return false;identity=identityForSteamID(steamID);alias="LAN-"+identity.substr(0,8);identityReady.store(true,std::memory_order_release);log("identity_ready",{{"alias",alias},{"scope","SteamID only"},{"source","SteamAPI_ISteamUser_GetSteamID"},{"persistentIdentityFiles",false}});return true;}catch(const std::exception& error){log("steam_identity_error",{{"message",error.what()}});return false;}
}
static void validateAdapterLayout(){
 for(const char* name:{"prosdk_update","prosdk_authorization_user_create","prosdk_user_connect_steam3","prosdk_account_get_status"})
  if(!GetProcAddress(sdk,name))throw std::runtime_error(std::string("Missing required PROS API: ")+name);
 log("adapter_selected",{{"profile",adapter::name},{"binaryHashesChecked",false},{"runtimeValidated",false},{"roomEmulationEnabled",adapter::enableExperimentalSessions}});
}
static DWORD WINAPI worker(void*){try{std::wstring executable(32768,L'\0');const auto length=GetModuleFileNameW(nullptr,executable.data(),static_cast<DWORD>(executable.size()));if(!length||length>=executable.size())throw std::runtime_error("Executable path unavailable");executable.resize(length);auto bin=std::filesystem::path(executable).parent_path();directory=bin/L"lan emu";std::error_code pathError;std::filesystem::create_directories(directory/L"logs",pathError);{std::ofstream probe(directory/L"logs"/(".probe-"+std::to_string(GetCurrentProcessId())));if(!probe){directory=userDirectory();std::filesystem::create_directories(directory/L"logs");}else{probe.close();std::filesystem::remove(directory/L"logs"/(".probe-"+std::to_string(GetCurrentProcessId())));}}log("initializing",{{"implementation","native-cpp"},{"python",false},{"frida",false}});

 WSADATA data{};if(WSAStartup(MAKEWORD(2,2),&data))throw std::runtime_error("WSAStartup");chooseInstance();log("identity_pending",{{"source","SteamID"},{"persistentIdentityFiles",false}});game=reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
 sdk=LoadLibraryExW((bin/L"pros.sdk.x64.dll").c_str(),nullptr,
     LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
 if(!sdk)throw std::runtime_error("Unable to load RoadCraft PROS SDK: "+std::to_string(GetLastError()));
 validateAdapterLayout();
 turnConfig={"127.0.0.1","lan-"+randomHex(8),randomHex(24),18633+portOffset};startServices();startTurn();if(MH_Initialize()!=MH_OK)throw std::runtime_error("MinHook initialize");installCore();if constexpr(adapter::enableExperimentalSessions)installRooms();else{installParty();log("session_hooks_pending");}if(MH_ApplyQueued()!=MH_OK)throw std::runtime_error("Enable native hooks");status=2;log("development_ready",{{"instance",portOffset/10+1},{"turnPort",turnConfig.port},{"multiplayerValidated",false}});
 }catch(const std::exception& error){status=3;stopping=true;MH_DisableHook(MH_ALL_HOOKS);stopBridge();stopTurn();stopServices();log("initialization_failed",{{"message",error.what()}});}return 0;}
}
extern "C" __declspec(dllexport) const char* LanEmuLicenses(){return kLicenses;}
extern "C" __declspec(dllexport) unsigned LanEmuStatus(){return emu::status.load();}
extern "C" __declspec(dllexport) BOOL LanEmuStart(){unsigned expected=0;if(!emu::status.compare_exchange_strong(expected,1))return expected==2;HANDLE thread=CreateThread(nullptr,0,emu::worker,nullptr,0,nullptr);if(!thread){emu::status=3;return FALSE;}CloseHandle(thread);return TRUE;}
// Explicit shutdown is for controlled tests. The module remains pinned while hooks exist.
extern "C" __declspec(dllexport) void LanEmuStop(){emu::stopping=true;MH_DisableHook(MH_ALL_HOOKS);emu::stopBridge();emu::stopTurn();emu::stopServices();emu::status=4;emu::log("stopped");}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH){
 wchar_t executable[MAX_PATH]{};
 const DWORD length=GetModuleFileNameW(nullptr,executable,MAX_PATH);
 if(!length||length>=MAX_PATH)return TRUE;
 const wchar_t* name=wcsrchr(executable,L'\\');
 if(_wcsicmp(name?name+1:executable,L"Roadcraft - Retail.exe")!=0)return TRUE;
 emu::module=module;HMODULE pinned=nullptr;GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(&DllMain),&pinned);LanEmuStart();}return TRUE;}
