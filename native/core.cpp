#include "emu.h"
#include <algorithm>
#include <cstring>
#include <intrin.h>
namespace emu {
namespace {
struct User {void* callback=nullptr;int state=0;unsigned generation=0;std::deque<int> pending;};
std::mutex stateMutex;std::map<void*,User> users;
using AuthCallback=void(*)(void*,int,int,void*);
using CreateFn=void*(*)(void*);
CreateFn originalCreate=nullptr;
void(*originalUpdate)()=nullptr;
std::atomic<int> presenceState{0};unsigned presenceGeneration=0;
void* presenceUser=nullptr;void(*presenceCallback)(void*,int,int,const char*)=nullptr;
thread_local bool flushing=false;
std::string currentPresenceMetadata;
void flush(){
 if(flushing||stopping)return;flushing=true;
 struct Notice{void* user;void* callback;int state;};std::vector<Notice> notices;
 {std::lock_guard<std::mutex> lock(stateMutex);for(auto& item:users){auto& rec=item.second;if(rec.pending.empty())continue;rec.state=rec.pending.front();rec.pending.pop_front();notices.push_back({item.first,rec.callback,rec.state});}}
 for(const auto& notice:notices){auto callback=notice.callback;if(!callback){log("authorization_callback_missing");continue;}reinterpret_cast<AuthCallback>(callback)(notice.user,notice.state,0,nullptr);log("auth_callback",{{"state",notice.state}});}
 // A snapshot ensures nested enqueues run on the next native tick.
 drainTasks();flushing=false;
}
void* createUser(void* options){
 auto callback=options?reinterpret_cast<void**>(options)[1]:nullptr;
 auto result=originalCreate(options);
 if(result){std::lock_guard<std::mutex> lock(stateMutex);users[result].callback=callback;}
 log("authorization_user_create",{{"created",result!=nullptr},{"callbackProvided",callback!=nullptr}});
 return result;
}
int connectUser(void* user,const void*,unsigned,void*){if(!user||!ensureSteamIdentity())return 100;std::lock_guard<std::mutex> lock(stateMutex);auto& rec=users[user];if(rec.state!=2&&rec.pending.empty()){rec.state=1;rec.pending={1,2};++rec.generation;}return 0;}
int connectUserSteam3(void* user,const void* ticket,unsigned length,void* extra,bool){return connectUser(user,ticket,length,extra);}
void presenceTransition(int state,unsigned generation){if(generation!=presenceGeneration)return;presenceState=state;if(presenceCallback)presenceCallback(presenceUser,state,0,"");log("presence_state",{{"state",state}});}
void disconnectUser(void* user){if(!user)return;{std::lock_guard<std::mutex> lock(stateMutex);auto& rec=users[user];if(rec.state!=3&&!(rec.state==0&&rec.pending.empty())){rec.state=3;rec.pending={3,0};++rec.generation;}}
 auto generation=++presenceGeneration;enqueue([generation]{presenceTransition(3,generation);enqueue([generation]{presenceTransition(0,generation);});});cleanupCoordinator();log("disconnect_requested");}
int connectionState(void* user){ensureSteamIdentity();
 std::lock_guard<std::mutex> lock(stateMutex);return user?users[user].state:0;}
const char* getIdentity(void*){
 ensureSteamIdentity();
 const auto caller=reinterpret_cast<uintptr_t>(_ReturnAddress());
 if(game&&caller==game+0x8aba98)log("matchmaking_identity_query",{{"available",!identity.empty()}});
 return identity.c_str();
}
const char* getAlias(void*){ensureSteamIdentity();return alias.c_str();}
void sdkUpdate(){originalUpdate();flush();}
int presenceConnect(void* user,void* callback,const char* metadata){currentPresenceMetadata=metadata?metadata:"";presenceUser=user;presenceCallback=reinterpret_cast<decltype(presenceCallback)>(callback);auto generation=++presenceGeneration;enqueue([generation]{presenceTransition(1,generation);enqueue([generation]{presenceTransition(2,generation);});});return 0;}
int presenceGetState(void* user){
 const bool matches=user&&user==presenceUser;
 const int state=matches?presenceState.load():0;
 const auto caller=reinterpret_cast<uintptr_t>(_ReturnAddress());
 if(game&&caller==game+0x8ab476)log("matchmaking_presence_query",{{"sameUser",matches},{"state",state}});
 return state;
}
bool presenceActivated(void* user){return presenceGetState(user)==2;}
using RoomStatusQuery=void*(*)(void*);
RoomStatusQuery originalSessionQuery=nullptr;
void* traceSessionQuery(void* user){
 auto result=originalSessionQuery(user);
 const char* id=result?*static_cast<const char**>(result):nullptr;
 int state=0;
 if(result)std::memcpy(&state,static_cast<const unsigned char*>(result)+0x90,sizeof(state));
 log("original_session_status",{{"hasRoom",id&&*id},{"state",state}});
 return result;
}
using ThreeArgRequest=int(*)(void*,void*,void*);
ThreeArgRequest originalMessagingConnect=nullptr;
int traceMessagingConnect(void* user,void* callback,void* options){
 const int result=originalMessagingConnect(user,callback,options);
 log("original_messaging_connect",{{"result",result}});
 return result;
}
// Public PROS signaling ABI: connect result and send result are 16 bytes.
struct SignalConnectResult {uint32_t error,padding;void* handler;};
struct SignalSendResult {uint32_t error,padding;const char* id;};
struct SignalEvent {const char* id;const char* sender;const void* bytes;uint64_t size;uint32_t type,padding;};
struct SignalEvents {SignalEvent* events;uint64_t count;};
static_assert(sizeof(SignalEvent)==40&&sizeof(SignalEvents)==16);
using SignalStateCallback=void(*)(void*,int,int,const char*);
using SignalSendCallback=void(*)(void*,SignalSendResult*);
struct SignalUser {int state=0;uint64_t generation=0;SignalStateCallback callback=nullptr;};
struct SignalReply {std::string id;SignalSendResult result{};};
struct SignalBatch {std::vector<std::string> strings;std::vector<SignalEvent> events;SignalEvents result{};};
struct PendingSignal {void* user;SignalSendCallback callback;};
std::map<void*,SignalUser> signalUsers;
uint64_t nextSignalGeneration=0;
std::map<void*,std::unique_ptr<SignalReply>> signalReplies;
std::map<void*,std::unique_ptr<SignalBatch>> signalBatches;
std::map<std::string,PendingSignal> pendingSignals;
std::deque<Json> incomingSignals;
void(*releaseOriginalSignalReply)(void*)=nullptr;
void(*releaseOriginalSignalBatch)(void*)=nullptr;

void signalTransition(void* user,uint64_t generation,int value){
 SignalStateCallback callback=nullptr;
 {std::lock_guard<std::mutex> lock(stateMutex);auto it=signalUsers.find(user);
  if(it==signalUsers.end()||it->second.generation!=generation)return;
  it->second.state=value;callback=it->second.callback;}
 if(callback)callback(user,value,0,"");
 log("local_signaling_state",{{"state",value}});
}
SignalConnectResult* localSignalingConnect(SignalConnectResult* out,void* user,SignalStateCallback callback,void*){
 if(!out)return out;
 *out={100,0,nullptr};if(!user)return out;
 uint64_t generation;
 {std::lock_guard<std::mutex> lock(stateMutex);auto& record=signalUsers[user];record.callback=callback;record.generation=generation=++nextSignalGeneration;}
 *out={0,0,user};
 enqueue([=]{signalTransition(user,generation,1);enqueue([=]{signalTransition(user,generation,2);});});
 return out;
}
void* localSignalingHandler(void* user){
 std::lock_guard<std::mutex> lock(stateMutex);return signalUsers.count(user)?user:nullptr;
}
int localSignalingState(void* user){
 std::lock_guard<std::mutex> lock(stateMutex);auto it=signalUsers.find(user);return it==signalUsers.end()?0:it->second.state;
}
const char* localSignalingId(void* user){return localSignalingState(user)==2&&identityReady.load()?identity.c_str():nullptr;}
void localSignalingCleanup(void* user){
 std::lock_guard<std::mutex> lock(stateMutex);auto it=signalUsers.find(user);if(it!=signalUsers.end())it->second.callback=nullptr;
 for(auto& entry:pendingSignals)if(entry.second.user==user)entry.second.callback=nullptr;
}
int localSignalingDisconnect(void* user){
 localSignalingCleanup(user);
 std::lock_guard<std::mutex> lock(stateMutex);const bool existed=signalUsers.erase(user)!=0;incomingSignals.clear();return existed?0:100;
}
SignalSendResult* makeSignalReply(uint32_t error,std::string id){
 auto reply=std::make_unique<SignalReply>();reply->id=std::move(id);
 reply->result={error,0,reply->id.empty()?nullptr:reply->id.c_str()};
 auto* result=&reply->result;signalReplies.emplace(result,std::move(reply));return result;
}
SignalSendResult* localReliableSend(void* user,const char* recipient,const unsigned char* bytes,uint64_t size,SignalSendCallback callback){
 const bool ready=localSignalingState(user)==2;
 std::lock_guard<std::mutex> lock(stateMutex);
 if(!ready||!recipient||!*recipient||!bytes||!size||size>32768||pendingSignals.size()>=128)return makeSignalReply(2,{});
 auto id=uuid();std::string payload;payload.reserve(size*2);
 constexpr char digits[]="0123456789abcdef";
 for(uint64_t i=0;i<size;++i){payload.push_back(digits[bytes[i]>>4]);payload.push_back(digits[bytes[i]&15]);}
 pendingSignals.emplace(id,PendingSignal{user,callback});
 bridgeSubmit("signal",{{"signalId",id},{"recipient",recipient},{"payload",std::move(payload)}});
 log("local_signaling_queued",{{"bytes",size}});
 return makeSignalReply(0,id);
}
void releaseSignalReply(void* pointer){
 {std::lock_guard<std::mutex> lock(stateMutex);if(signalReplies.erase(pointer))return;}
 if(releaseOriginalSignalReply)releaseOriginalSignalReply(pointer);
}
SignalEvents* popLocalSignals(void* user){
 const bool ready=localSignalingState(user)==2;
 std::lock_guard<std::mutex> lock(stateMutex);
 auto batch=std::make_unique<SignalBatch>();
 if(ready){batch->strings.reserve(incomingSignals.size()*3);batch->events.reserve(incomingSignals.size());
  for(auto& message:incomingSignals){
   auto data=message.value("payload",std::string());if(data.size()%2)continue;
   std::string bytes;bytes.reserve(data.size()/2);
   auto digit=[](unsigned char c)->int{return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;};
   for(size_t i=0;i<data.size();i+=2){int high=digit(data[i]),low=digit(data[i+1]);if(high<0||low<0)break;bytes.push_back(static_cast<char>(high*16+low));}
   if(bytes.size()*2!=data.size())continue;
   batch->strings.push_back(message.value("sender",std::string()));
   batch->strings.push_back(message.value("id",std::string()));
   batch->strings.push_back(std::move(bytes));
   auto i=batch->strings.size()-3;auto& b=batch->strings[i+2];
   batch->events.push_back({batch->strings[i+1].c_str(),batch->strings[i].c_str(),b.data(),b.size(),10,0});
  }
  incomingSignals.clear();
 }
 batch->result={batch->events.empty()?nullptr:batch->events.data(),batch->events.size()};
 auto* result=&batch->result;signalBatches.emplace(result,std::move(batch));return result;
}
void releaseSignalBatch(void* pointer){
 {std::lock_guard<std::mutex> lock(stateMutex);if(signalBatches.erase(pointer))return;}
 if(releaseOriginalSignalBatch)releaseOriginalSignalBatch(pointer);
}

using RedstoneConnect=void*(*)(void*,const char*,void*);
using RedstoneConfigure=bool(*)(void*);
RedstoneConnect originalRedstoneConnect=nullptr;
RedstoneConfigure originalRedstoneConfigure=nullptr;
void* traceRedstoneConnect(void* endpoint,const char* uri,void* options){
 log("redstone_connect_enter",{{"hasEndpoint",endpoint!=nullptr},{"hasAddress",uri!=nullptr}});
 auto result=originalRedstoneConnect(endpoint,uri,options);
 log("redstone_connect_return",{{"hasConnection",result!=nullptr}});
 return result;
}
bool traceRedstoneConfigure(void* config){
 const bool result=originalRedstoneConfigure(config);
 log("redstone_endpoint_configuration",{{"accepted",result}});
 return result;
}
void installRedstoneTrace(){
 auto image=GetModuleHandleW(L"RedstoneSocket-x64.dll");
 if(!image){log("redstone_trace_unavailable");return;}
 auto connect=GetProcAddress(image,"rsock_connect");
 auto configure=GetProcAddress(image,"?rsock_set_endpoint_autoconfigurator@@YA_NPEAURSockRtcEndpointAutoCfg@@@Z");
 const bool connectReady=connect&&hookAddress(reinterpret_cast<void*>(connect),reinterpret_cast<void*>(traceRedstoneConnect),reinterpret_cast<void**>(&originalRedstoneConnect));
 const bool configureReady=configure&&hookAddress(reinterpret_cast<void*>(configure),reinterpret_cast<void*>(traceRedstoneConfigure),reinterpret_cast<void**>(&originalRedstoneConfigure));
 log("redstone_trace_prepared",{{"connect",connectReady},{"configuration",configureReady}});
}
struct Account {alignas(8) unsigned char status[adapter::accountStatusSize]{};void(*callback)(void*,int)=nullptr;unsigned generation=0;bool delivered=false,scheduled=false;};
std::map<void*,std::unique_ptr<Account>> accounts;std::set<void*> accountStatuses;
Account& account(void* user){auto& rec=accounts[user];if(!rec){rec=std::make_unique<Account>();*reinterpret_cast<int*>(rec->status)=user?1:0;for(size_t off:{0x38,0x40,0x48,0x50})*reinterpret_cast<const char**>(rec->status+off)="";accountStatuses.insert(rec->status);}return *rec;}
void scheduleAccount(void* user){auto& rec=account(user);if(rec.scheduled||!rec.callback)return;rec.scheduled=true;auto generation=rec.generation;enqueue([user,generation]{auto& r=account(user);r.scheduled=false;if(generation==r.generation&&r.callback){r.callback(user,1);r.delivered=true;}});}
int accountConnect(void* user,void* callback){if(!user)return 100;auto& rec=account(user);rec.callback=reinterpret_cast<decltype(rec.callback)>(callback);++rec.generation;rec.delivered=false;rec.scheduled=false;scheduleAccount(user);return 0;}
int accountFetch(void* user){if(!user)return 100;if(!account(user).delivered)scheduleAccount(user);return 0;}
void* accountStatus(void* user){return account(user).status;}
void(*originalAccountRelease)(void*)=nullptr;
void accountRelease(void* pointer){if(accountStatuses.count(pointer))return;originalAccountRelease(pointer);}
using ConfigurationFn=int(*)(void*,void*,uint64_t,void*,void*);ConfigurationFn originalConfiguration=nullptr;
int configuration(void* user,void* properties,uint64_t count,void* context,void* callback){log("configuration_passthrough",{{"propertyCount",count}});return originalConfiguration(user,properties,count,context,callback);}
void(*originalLayerRelease)(void*,uint64_t)=nullptr;
void layerRelease(void* pointer,uint64_t count){originalLayerRelease(pointer,count);}
struct Endpoint{const char* ip="127.0.0.1";unsigned port=18632,family=2;};
struct Center{const char* id="lan-local";Endpoint* endpoints=nullptr;uint64_t count=1;};Endpoint endpoint;Center center;
int dataCenters(void* user,void* context,void* callback){enqueue([user,context,callback]{if(callback)reinterpret_cast<void(*)(void*,Center*,uint64_t,void*,int)>(callback)(user,&center,1,context,0);});return 0;}
void(*originalCentersRelease)(void*,uint64_t)=nullptr;
void centersRelease(void* pointer,uint64_t count){if(pointer==&center)return;originalCentersRelease(pointer,count);}
struct EchoSample{unsigned status;int rtt;};struct EchoResult{const char* id;EchoSample* samples;uint64_t count;};
std::mutex echoMutex;std::map<void*,std::unique_ptr<EchoSample[]>> echoOwned;
void(*originalEchoRelease)(void*)=nullptr;
void echoRelease(void* pointer){std::lock_guard<std::mutex> lock(echoMutex);if(echoOwned.erase(pointer)){delete static_cast<EchoResult*>(pointer);return;}originalEchoRelease(pointer);}
int udpEcho(const char* name,unsigned timeout,unsigned count,unsigned interval,void* context,void* callback){
 if(!name||std::strcmp(name,"lan-local"))return 121;timeout=std::clamp(timeout,1u,5000u);count=std::clamp(count,1u,32u);interval=std::min(interval,1000u);
 std::thread([=]{auto samples=std::make_shared<std::vector<EchoSample>>();SOCKET socketHandle=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);sockaddr_in target{};target.sin_family=AF_INET;target.sin_port=htons(static_cast<u_short>(18632+portOffset));inet_pton(AF_INET,"127.0.0.1",&target.sin_addr);setsockopt(socketHandle,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));connect(socketHandle,reinterpret_cast<sockaddr*>(&target),sizeof(target));
  for(unsigned i=0;i<count&&!stopping;++i){unsigned char sent[32],received[64];BCryptGenRandom(nullptr,sent,32,BCRYPT_USE_SYSTEM_PREFERRED_RNG);auto started=GetTickCount64();send(socketHandle,reinterpret_cast<char*>(sent),32,0);int n=recv(socketHandle,reinterpret_cast<char*>(received),64,0);bool success=n==32&&!std::memcmp(sent,received,32);samples->push_back({success?0u:1u,success?static_cast<int>(GetTickCount64()-started):0});if(i+1<count)Sleep(interval);}closesocket(socketHandle);
  enqueue([=]{auto values=std::make_unique<EchoSample[]>(samples->size());std::copy(samples->begin(),samples->end(),values.get());auto result=new EchoResult{"lan-local",values.get(),samples->size()};{std::lock_guard<std::mutex> lock(echoMutex);echoOwned[result]=std::move(values);}if(callback)reinterpret_cast<void(*)(int,uint64_t,void*,EchoResult*)>(callback)(0,0,context,result);});
 }).detach();return 0;
}
}
std::string presenceMetadata(){return currentPresenceMetadata;}
void acceptLocalSignals(const Json& result){
 PendingSignal pending{};SignalSendResult* completion=nullptr;
 {std::lock_guard<std::mutex> lock(stateMutex);
  for(auto& message:result.value("signals",Json::array()))if(incomingSignals.size()<128)incomingSignals.push_back(message);
  auto id=result.value("signalId",std::string());auto it=pendingSignals.find(id);
  if(it!=pendingSignals.end()){
   pending=it->second;pendingSignals.erase(it);
   if(pending.callback)completion=makeSignalReply(result.value("accepted",false)?0:2,id);
  }
 }
 if(completion){log("local_signaling_send_completed",{{"result",completion->error}});pending.callback(pending.user,completion);}
}
void installCore(){
 endpoint.port=18632+portOffset;center.endpoints=&endpoint;
 // Use explicit calls because optional generic pointer deduction cannot infer nullptr.
 if(!hook("prosdk_authorization_user_create",reinterpret_cast<void*>(createUser),reinterpret_cast<void**>(&originalCreate)))throw std::runtime_error("authorization create hook");
#define INSTALL(name,fn) if(!hook(name,reinterpret_cast<void*>(fn)))throw std::runtime_error(name)
#define INSTALL_ORIGINAL(name,fn,orig) if(!hook(name,reinterpret_cast<void*>(fn),reinterpret_cast<void**>(&orig)))throw std::runtime_error(name)
 INSTALL("prosdk_user_get_connection_state",connectionState);INSTALL("prosdk_user_connect_steam",connectUser);INSTALL("prosdk_user_disconnect",disconnectUser);
 INSTALL("prosdk_user_connect_steam2",connectUser);INSTALL("prosdk_user_connect_steam3",connectUserSteam3);
 INSTALL("prosdk_user_get_identity",getIdentity);INSTALL("prosdk_user_get_kernel_session_id_string",getIdentity);INSTALL("prosdk_user_get_kernel_session_id_visual_alias",getAlias);
 INSTALL("hydra5_presence_connect",presenceConnect);INSTALL("hydra5_presence_get_service_state",presenceGetState);INSTALL("hydra5_presence_is_service_activated",presenceActivated);
 INSTALL("prosdk_account_connect",accountConnect);INSTALL("prosdk_account_try_to_fetch_status",accountFetch);INSTALL("prosdk_account_get_status",accountStatus);INSTALL_ORIGINAL("prosdk_account_service_status_release",accountRelease,originalAccountRelease);
 if constexpr(!adapter::enableExperimentalSessions){
  INSTALL_ORIGINAL("hydra5_messaging_2_connect",traceMessagingConnect,originalMessagingConnect);
  INSTALL_ORIGINAL("hydra5_matchmake_session_get_status",traceSessionQuery,originalSessionQuery);
 }
 installRedstoneTrace();
 INSTALL("hydra5_client_signaling_connect",localSignalingConnect);
 INSTALL("hydra5_client_get_signaling_handler",localSignalingHandler);
 INSTALL("hydra5_signaling_get_connection_state",localSignalingState);
 INSTALL("hydra5_signaling_get_id",localSignalingId);
 INSTALL("hydra5_signaling_cleanup_connect_callbacks",localSignalingCleanup);
 INSTALL("hydra5_signaling_disconnect",localSignalingDisconnect);
 INSTALL("hydra5_signaling_send_reliable",localReliableSend);
 INSTALL("hydra5_signaling_pop_received_messages",popLocalSignals);
 INSTALL_ORIGINAL("hydra5_release_signaling_send_result",releaseSignalReply,releaseOriginalSignalReply);
 INSTALL_ORIGINAL("hydra5_release_signaling_event_array",releaseSignalBatch,releaseOriginalSignalBatch);
 INSTALL_ORIGINAL("hydra5_get_game_configuration",configuration,originalConfiguration);INSTALL_ORIGINAL("hydra5_release_layers_data_array",layerRelease,originalLayerRelease);
 INSTALL("hydra5_session_control_get_all_data_centers",dataCenters);INSTALL_ORIGINAL("hydra5_release_session_control_data_centers_array",centersRelease,originalCentersRelease);INSTALL("hydra5_udp_echo_async",udpEcho);INSTALL_ORIGINAL("hydra5_release_udp_echo_async_result",echoRelease,originalEchoRelease);
 INSTALL_ORIGINAL("prosdk_update",sdkUpdate,originalUpdate);
 log("core_hooks_installed");
}
}
