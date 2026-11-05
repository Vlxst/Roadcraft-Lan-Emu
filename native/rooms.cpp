#include "emu.h"
#include "dynamic_image.h"
#include <cstring>
#include <algorithm>
namespace emu { namespace {
using Completion=void(__cdecl*)(void*,void*,int);using Subscriber=void(__cdecl*)(void*,void*,int);
struct Pair{void* context;Completion fn;};struct Sub{void* user;Subscriber fn;};
std::recursive_mutex mutex;Json state={{"party",nullptr},{"session",nullptr}},search=nullptr;bool suspended=false,suppress=false;uint64_t serial=0;std::string lastParty,lastSession;std::map<uint64_t,std::pair<void*,Pair>> completions;std::vector<Sub> partySubs,sessionSubs;
std::map<void*,int> turnStates;uint64_t turnGeneration=0;
void resetSessionTurn(){turnStates.clear();++turnGeneration;}
struct Arena{std::vector<void*> blocks;~Arena(){for(auto p:blocks)HeapFree(GetProcessHeap(),0,p);}void* alloc(size_t n){void*p=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,std::max<size_t>(n,1));if(!p)throw std::bad_alloc();blocks.push_back(p);return p;}char* str(std::string s){auto p=(char*)alloc(s.size()+1);memcpy(p,s.c_str(),s.size()+1);return p;}};
std::map<void*,std::unique_ptr<Arena>> owned;void(__cdecl* releaseParty)(void*);void(__cdecl* releaseSession)(void*);void(__cdecl* releaseTurn)(void*);
template<class T>T read(void*p,size_t o=0){return p?*reinterpret_cast<T*>((char*)p+o):T{};}template<class T>void put(void*p,size_t o,T v){*reinterpret_cast<T*>((char*)p+o)=v;}
std::string text(const char*p){return p?p:"";}std::string at(void*p,size_t o){return text(read<char*>(p,o));}uint64_t count(void*p,size_t o){auto n=read<uint64_t>(p,o);if(n>4096)throw std::runtime_error("native array count");return n;}
Json arr(void*p,size_t o){Json a=Json::array();auto q=read<void*>(p,o);for(size_t i=0;i<count(p,o+8);++i)a.push_back(at(q,i*8));return a;}
std::string str(const Json&j,const char*k){return j.contains(k)&&j[k].is_string()?j[k].get<std::string>():"";}uint64_t num(const Json&j,const char*k,uint64_t d=0){if(!j.contains(k)||j[k].is_null())return d;auto&v=j[k];if(v.is_string()){try{return std::stoull(v.get<std::string>());}catch(...){return d;}}return v.get<uint64_t>();}
Json rows(const Json&j,const char*k){return j.contains(k)&&j[k].is_array()?j[k]:Json::array();}
void strings(Arena&a,void*p,std::initializer_list<size_t>os,std::initializer_list<std::string>vs){auto v=vs.begin();for(auto o:os)put(p,o,a.str(*v++));}
void array(Arena&a,void*p,size_t o,size_t stride,const Json&js,std::function<void(void*,const Json&)>fn){if(js.empty())return;auto q=a.alloc(stride*js.size());put(p,o,q);put<uint64_t>(p,o+8,js.size());for(size_t i=0;i<js.size();++i)fn((char*)q+i*stride,js[i]);}
void stringArray(Arena&a,void*p,size_t o,Json js){array(a,p,o,8,js,[&](void*q,const Json&r){put(q,0,a.str(r.get<std::string>()));});}
void* serialize(const std::string&kind,Json s){auto a=std::make_unique<Arena>();auto p=a->alloc(kind=="party"?0x50:adapter::sessionStatusSize);if(s.is_null())s=Json::object();strings(*a,p,{0,8},{str(s,"id"),str(s,"owner")});auto settings=rows(s,"settings");if(kind=="party"){
put(p,0x10,a->str(str(s,"data")));for(size_t i=0;i<4;i++)put<uint32_t>(p,0x18+i*4,i<settings.size()?settings[i].get<uint32_t>():0);put<uint8_t>(p,0x28,num(s,"flag28"));stringArray(*a,p,0x30,rows(s,"strings30"));array(*a,p,0x40,0x30,rows(s,"members"),[&](void*q,const Json&m){strings(*a,q,{0,8,0x10},{str(m,"id"),str(m,"name"),str(m,"data")});put<uint8_t>(q,0x18,num(m,"flag18"));put<uint8_t>(q,0x20,str(m,"id")==identity);auto ns=rows(m,"numbers");size_t os[]={0x1c,0x24,0x28,0x2c};for(size_t i=0;i<4;i++)put<uint32_t>(q,os[i],i<ns.size()?ns[i].get<uint32_t>():0);});
}else{for(size_t i=0;i<3;i++)put<uint32_t>(p,0x10+i*4,i<settings.size()?settings[i].get<uint32_t>():0);stringArray(*a,p,0x20,rows(s,"data"));array(*a,p,0x30,16,rows(s,"variants"),[&](void*q,const Json&r){strings(*a,q,{0,8},{r[0].get<std::string>(),r[1].get<std::string>()});});array(*a,p,0x40,0x98,rows(s,"members"),[&](void*q,const Json&m){strings(*a,q,{0,8,0x10,0x20},{str(m,"id"),str(m,"name"),str(m,"data"),str(m,"field20")});put<uint8_t>(q,0x18,num(m,"flag18"));put<uint8_t>(q,0x19,str(m,"id")==identity);put<uint32_t>(q,0x1c,num(m,"field1c"));put<uint32_t>(q,0x28,num(m,"field28"));auto ns=rows(m,"numericTail");for(size_t i=0;i<3;i++)put<uint32_t>(q,0x78+i*4,i<ns.size()?ns[i].get<uint32_t>():0);if(m.contains("securitySpans")){put<uint8_t>(q,0x30,1);for(int i=0;i<4;i++){std::vector<uint8_t>b=m["securitySpans"][i].get<std::vector<uint8_t>>();void*r=a->alloc(b.size());memcpy(r,b.data(),b.size());put(q,0x38+i*16,r);put<uint64_t>(q,0x40+i*16,b.size());}}if(m.contains("optional90")&&!m["optional90"].is_null()){put<uint8_t>(q,0x88,1);put(q,0x90,a->str(str(m,"optional90")));}});for(auto o:{0x50,0x68,0xa8}){const char*k=o==0x50?"field50":o==0x68?"field68":"fielda8";put<uint32_t>(p,o<0x68?o:o+adapter::sessionTailShift,num(s,k));}put(p,0x68,a->str(str(s,"roadcraftExtra68")));strings(*a,p,{0x58,0x60,0x70+adapter::sessionTailShift,0x98+adapter::sessionTailShift},{str(s,"field58"),str(s,"field60"),str(s,"field70"),str(s,"field98")});array(*a,p,0x78+adapter::sessionTailShift,24,rows(s,"groups"),[&](void*q,const Json&r){put(q,0,a->str(str(r,"key")));stringArray(*a,q,8,rows(r,"values"));});put<uint32_t>(p,0x88+adapter::sessionTailShift,num(s,"state"));put<uint64_t>(p,0x90+adapter::sessionTailShift,num(s,"field90"));put<uint64_t>(p,0xa0+adapter::sessionTailShift,num(s,"fielda0"));}
owned[p]=std::move(a);return p;}
Json ownMember(const Json&s){for(auto&m:rows(s,"members"))if(str(m,"id")==identity)return m;return nullptr;}
void notify(std::string kind,int event){std::lock_guard<std::recursive_mutex>g(mutex);auto current=state[kind];if(!suppress){if(!current.is_null()&&event==1)suspended=false;if(kind=="party"){auto own=ownMember(current);auto sm=ownMember(state["session"]);if(!state["session"].is_null()&&num(sm,"flag18"))bridgeSubmit("publish",{{"session",state["session"]},{"party",current}});else if(!own.is_null()&&!num(own,"flag18"))bridgeSubmit("party_member",{{"member",own}});}else if(current.is_null()||str(current,"id").empty()){if(event==2)bridgeSubmit("leave",Json::object());}else{auto own=ownMember(current);if(!own.is_null())bridgeSubmit(num(own,"flag18")?"publish":"member",num(own,"flag18")?Json{{"session",current},{"party",state["party"]}}:Json{{"member",own}});}}
for(auto sub:kind=="party"?partySubs:sessionSubs)sub.fn(sub.user,serialize(kind,current),event);}
// Application metadata is opaque to PROS. Preserve caller bytes.
std::string metadata(){return presenceMetadata();}
Json localMember(bool session,bool owner){
 Json r={{"id",identity},{"name",""},{"data",metadata()},{"flag18",owner?1:0}};
 if(session){r["field1c"]=1;r["field20"]=uuid();r["field28"]=0;r["numericTail"]=Json::array({1,200,0});r["optional90"]=nullptr;}
 else r["numbers"]=Json::array({1,0,0,1});return r;
}
Json inputPairs(void* p,size_t offset){Json out=Json::array();auto q=read<void*>(p,offset);for(size_t i=0;i<count(p,offset+8);++i)out.push_back({at(q,i*16),read<int32_t>(q,i*16+8)});return out;}
Json inputBindings(void* p,size_t offset){Json out=Json::array();auto q=read<void*>(p,offset);for(size_t i=0;i<count(p,offset+8);++i){auto row=(char*)q+i*32;out.push_back({{"first",at(row,0)},{"second",at(row,8)},{"values",arr(row,16)}});}return out;}
Json build(bool session,void*p){
 auto own=localMember(session,true);
 if(!session){own["name"]=at(p,0x30);return {{"id",uuid()},{"owner",at(p,0x28)},{"data",""},{"settings",Json::array({read<uint32_t>(p),read<uint32_t>(p,4),read<uint32_t>(p,8),read<uint32_t>(p,12)})},{"flag28",read<uint8_t>(p,0x10)},{"strings30",arr(p,0x18)},{"members",Json::array({own})}};}
 // Local development snapshot. RoadCraft status semantics still require a live trace.
 Json s={{"owner",""},{"state",2},{"groups",Json::array()},{"variants",Json::array()}};s["id"]=uuid();s["members"]=Json::array({own});
 s["settings"]=Json::array({read<uint32_t>(p,0x20),read<uint32_t>(p,0x24),read<uint32_t>(p,0x28)});
 s["data"]=arr(p,0x30);s["field60"]=s["field70"]=at(p,0);
 auto q=read<void*>(p,0x40);for(size_t i=0;i<count(p,0x48);++i)s["variants"].push_back({at(q,i*16),at(q,i*16+8)});
 s["inputOptions"]={{"scalar18",read<uint32_t>(p,0x18)},{"pings",inputPairs(p,8)},{"bindings",inputBindings(p,0x50)}};return s;
}
Pair pair(void*p){return p?read<Pair>(p):Pair{};}void done(void*u,Pair p,int e=0){if(p.fn)p.fn(u,p.context,e);}
template<bool S>int create(void*u,void*p,void*c){std::lock_guard<std::recursive_mutex>g(mutex);std::string k=S?"session":"party";if constexpr(S)resetSessionTurn();state[k]=build(S,p);log("local_room_created",{{"scope",k}});suspended=false;auto cb=pair(c);enqueue([=]{if(!S)notify(k,1);done(u,cb);if(S)notify(k,1);});return 0;}
template<bool S>void* status(void*){std::lock_guard<std::recursive_mutex>g(mutex);return serialize(S?"session":"party",state[S?"session":"party"]);}
template<bool S>void subscribe(void*u,Subscriber f){std::lock_guard<std::recursive_mutex>g(mutex);if(f)(S?sessionSubs:partySubs).push_back({u,f});}
template<bool S>void release(void*p){std::lock_guard<std::recursive_mutex>g(mutex);if(owned.erase(p)==0){auto f=S?releaseSession:releaseParty;if(f)f(p);}}
template<bool S,bool M>int setter(void*,const char*p){std::lock_guard<std::recursive_mutex>g(mutex);std::string k=S?"session":"party";auto&s=state[k];if(!s.is_null()){s["opaqueData"][M?"member_data":"data"]=text(p);if(!M)s["owner"]=text(p);else for(auto&m:s["members"])if(str(m,"id")==identity)m["name"]=text(p);enqueue([k]{notify(k,0);});}return 0;}
template<bool S>int settings(void*,void*p){std::lock_guard<std::recursive_mutex>g(mutex);std::string k=S?"session":"party";if(state[k].is_null())return 2;auto&s=state[k];s["settings"]=Json::array();for(size_t i=0;i<(S?3:4);i++)s["settings"].push_back(read<uint32_t>(p,i*4));if(S)s["data"]=arr(p,0x10);else{s["flag28"]=read<uint8_t>(p,0x10);s["strings30"]=arr(p,0x18);}enqueue([k]{notify(k,0);});return 0;}
int variants(void*,void*p,uint64_t n){std::lock_guard<std::recursive_mutex>g(mutex);if(n>4096||state["session"].is_null())return 2;Json v=Json::array();for(size_t i=0;i<n;i++)v.push_back({at(p,i*16),at(p,i*16+8)});state["session"]["variants"]=v;enqueue([]{notify("session",0);});return 0;}
template<int K>int leave(void*u,void*c){std::lock_guard<std::recursive_mutex>g(mutex);cleanupCoordinator();const char*k=K==0?"party":"session";if(K<2&&state[k].is_null())return 139;if constexpr(K==1)resetSessionTurn();if(K<2)state[k]=nullptr;auto cb=pair(c);enqueue([=]{if(K<2)notify(k,K==0?4:2);done(u,cb);});return 0;}
template<bool Reset>int code(void*u,void*c){std::lock_guard<std::recursive_mutex>g(mutex);if(state["party"].is_null())return 2;if(Reset&&str(state["party"],"data").empty())return 139;auto v=uuid();v.erase(std::remove(v.begin(),v.end(),'-'),v.end());state["party"]["data"]=Reset?"":v.substr(0,5);auto cb=pair(c);enqueue([=]{notify("party",0);done(u,cb);});return 0;}
Json guest(){auto m=localMember(true,false);auto own=ownMember(state["party"]);if(own.is_null())return nullptr;m["data"]=own["data"];m["name"]="";m["flag18"]=0;m["flag19"]=1;return m;}
uint64_t token(void*u,void*c){auto n=++serial;completions[n]={u,pair(c)};return n;}
int start(void*u,void*p,void*c){std::lock_guard<std::recursive_mutex>g(mutex);if(!search.is_null())return 138;Json options={{"playlist",at(p,0)},{"variants",Json::object()},{"inputOptions",{{"scalar18",read<uint32_t>(p,0x18)},{"pings",inputPairs(p,8)},{"quality",read<float>(p,0x30)},{"bindings",inputBindings(p,0x38)}}}};auto n=count(p,0x28);if(n>128)return 2;auto rows=read<void*>(p,0x20);for(size_t i=0;i<n;i++){auto r=(char*)rows+i*24;auto values=arr(r,8);if(!values.empty())options["variants"][at(r,0)]=values;}auto m=guest();if(m.is_null())return 2;suspended=false;search=options;search["member"]=m;state["session"]={{"id",""},{"owner",""},{"members",Json::array()},{"state",1}};auto cb=pair(c);enqueue([=]{notify("session",0);done(u,cb);});bridgeSubmit("join",search);return 0;}
int useCode(void*u,const char*c,void*p){std::lock_guard<std::recursive_mutex>g(mutex);auto m=ownMember(state["party"]);std::string v=text(c);auto first=v.find_first_not_of(" \t\r\n"),last=v.find_last_not_of(" \t\r\n");if(first==std::string::npos||m.is_null())return 2;v=v.substr(first,last-first+1);suspended=false;bridgeSubmit("join_code",{{"code",v},{"partyMember",m},{"requestToken",token(u,p)}});return 0;}
int join(void*u,const char*id,void*p){std::lock_guard<std::recursive_mutex>g(mutex);if(!state["session"].is_null()&&str(state["session"],"id")==text(id))return 139;auto m=guest();if(m.is_null())return 2;suspended=false;bridgeSubmit("session_join",{{"sessionId",text(id)},{"member",m},{"requestToken",token(u,p)}});return 0;}
int join2(void*u,const char*id,void*,void*p){return join(u,id,p);}int join3(void*u,const char*id,void*,void*,uint64_t,void*p){return join(u,id,p);}
void result(Json r){enqueue([r]{acceptLocalSignals(r);std::lock_guard<std::recursive_mutex>g(mutex);if(suspended)return;bool accepted=r.value("accepted",true);for(auto k:{"party","session"})if(accepted&&r.contains(k)&&!r[k].is_null()){auto j=r[k];for(auto&m:j["members"])m[k==std::string("party")?"flag20":"flag19"]=str(m,"id")==identity?1:0;auto&s=k==std::string("party")?lastParty:lastSession;if(j.dump()!=s){s=j.dump();bool joining=state[k].is_null()||str(state[k],"id")!=str(j,"id");if(joining&&k==std::string("session"))resetSessionTurn();state[k]=j;suppress=true;notify(k,joining?(k==std::string("party")?2:1):0);suppress=false;if(joining&&k==std::string("session")){search=nullptr;log("session_snapshot_applied",{{"state",num(j,"state")},{"members",rows(j,"members").size()}});}}}
auto t=r.value("requestToken",uint64_t(0));auto i=completions.find(t);if(i!=completions.end()){auto c=i->second;completions.erase(i);done(c.first,c.second,accepted?0:2);}});}
using TurnCallback=void(__cdecl*)(void*,void*,void*,int);
TurnCallback registerRedstoneTurn=nullptr;

void resolveRedstoneTurn(){
 // The native request path passes this callback in R9. Its successful
 // completion registers the server with Redstone and refreshes endpoints.
 const auto site=dynamic::uniqueCodePattern(game,
   "4C 8D 0D ?? ?? ?? ?? 4C 89 75 F7 45 33 C0 C7 45 EF 02 00 00 00 48 8D 55 EF");
 if(!site){log("redstone_turn_registration_unavailable");return;}
 int32_t displacement=0;
 std::memcpy(&displacement,reinterpret_cast<const void*>(site+3),sizeof(displacement));
 const auto target=site+7+displacement;
 const unsigned char prefix[]={0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x55,0x57,0x41,0x56};
 if(!dynamic::readable(target,sizeof(prefix))||
    std::memcmp(reinterpret_cast<const void*>(target),prefix,sizeof(prefix))){
  log("redstone_turn_registration_unavailable");return;
 }
 registerRedstoneTurn=reinterpret_cast<TurnCallback>(target);
 log("redstone_turn_registration_resolved");
}
void fillTurn(Arena&a,void*p){put(p,0,a.str(turnConfig.host));put<uint32_t>(p,8,turnConfig.port);put(p,16,a.str(turnConfig.username));put(p,24,a.str(turnConfig.password));put<uint64_t>(p,32,0);}
int turnRequest(void*u,void*c,void(__cdecl*f)(void*,void*,void*,int)){std::lock_guard<std::recursive_mutex>g(mutex);if(state["session"].is_null()||str(state["session"],"id").empty())return 120;if(turnStates[u]==2)return 139;if(turnStates[u]==1)return 138;turnStates[u]=1;const auto generation=turnGeneration;log("session_turn_requested");enqueue([=]{std::lock_guard<std::recursive_mutex>g(mutex);if(generation!=turnGeneration)return;turnStates[u]=2;static Arena notification;static void*p=nullptr;if(!p){p=notification.alloc(40);fillTurn(notification,p);}if(registerRedstoneTurn&&registerRedstoneTurn!=f){
 registerRedstoneTurn(u,p,nullptr,0);log("redstone_turn_registered",{{"port",turnConfig.port}});
 }if(f){log("session_turn_callback_enter",{{"port",turnConfig.port}});f(u,p,c,0);log("session_turn_callback_return");}});return 0;}
void* turnGet(void*u){std::lock_guard<std::recursive_mutex>g(mutex);auto a=std::make_unique<Arena>();auto p=a->alloc(48);if(turnStates[u]==2)fillTurn(*a,(char*)p+8);else put<uint32_t>(p,0,135);owned[p]=std::move(a);return p;}
void turnRelease(void*p){std::lock_guard<std::recursive_mutex>g(mutex);if(!owned.erase(p)&&releaseTurn)releaseTurn(p);}
} // anonymous
Json roomSnapshot(){std::lock_guard<std::recursive_mutex>g(mutex);return state;}
void cleanupCoordinator(){std::lock_guard<std::recursive_mutex>g(mutex);suspended=true;search=nullptr;lastParty.clear();lastSession.clear();bridgeSubmit("leave",Json::object());}
void installParty(){
 if(!hook("hydra5_party_create",(void*)create<false>)||
    !hook("hydra5_party_get_status",(void*)status<false>)||
    !hook("hydra5_party_subscribe_on_party_update",(void*)subscribe<false>)||
    !hook("hydra5_release_party_status",(void*)release<false>,(void**)&releaseParty)||
    !hook("hydra5_party_set_data",(void*)setter<false,false>)||
    !hook("hydra5_party_set_member_data",(void*)setter<false,true>)||
    !hook("hydra5_party_set_settings",(void*)settings<false>)||
    !hook("hydra5_party_leave",(void*)leave<0>))
  throw std::runtime_error("party hook failed");
 log("local_party_hooks_installed");
}
void installRooms(){
resolveRedstoneTurn();
#define H(n,f) do { if(!hook(n,reinterpret_cast<void*>(f)))throw std::runtime_error(std::string("room hook failed: ")+n); } while(0)
H("hydra5_party_create",create<false>);H("hydra5_matchmake_session_create",create<true>);H("hydra5_party_get_status",status<false>);H("hydra5_matchmake_session_get_status",status<true>);H("hydra5_party_subscribe_on_party_update",subscribe<false>);H("hydra5_matchmake_subscribe_on_session_update",subscribe<true>);
if(!hook("hydra5_release_party_status",(void*)release<false>,(void**)&releaseParty)||!hook("hydra5_release_matchmake_session_status",(void*)release<true>,(void**)&releaseSession))throw std::runtime_error("room release hook failed");
H("hydra5_party_set_data",(setter<false,false>));H("hydra5_party_set_member_data",(setter<false,true>));H("hydra5_matchmake_session_set_data",(setter<true,false>));H("hydra5_matchmake_session_set_member_data",(setter<true,true>));H("hydra5_party_set_settings",settings<false>);H("hydra5_matchmake_session_set_settings",settings<true>);H("hydra5_matchmake_session_set_variants",variants);
H("hydra5_party_leave",leave<0>);H("hydra5_matchmake_session_leave",leave<1>);H("hydra5_matchmake_stop",leave<2>);H("hydra5_party_join_code_generate",code<false>);H("hydra5_party_join_code_reset",code<true>);H("hydra5_party_join_code_use",useCode);H("hydra5_matchmake_start",start);H("hydra5_matchmake_session_join",join);H("hydra5_matchmake_session_join_2",join2);H("hydra5_matchmake_session_join_3",join3);H("hydra5_matchmake_session_request_turn_server",turnRequest);H("hydra5_matchmake_session_get_turn_server_connection_info",turnGet);if(!hook("hydra5_matchmake_session_release_turn_server_result",(void*)turnRelease,(void**)&releaseTurn))throw std::runtime_error("TURN release hook failed");
#undef H
startBridge([]{std::lock_guard<std::recursive_mutex>g(mutex);return search;},result);log("rooms_installed");}
}
