#include "emu.h"
#include <algorithm>
#include <condition_variable>
#include <cctype>
#include <stdexcept>
#include <sstream>

namespace emu {
std::atomic<bool> identityReady{false};
namespace {
using Clock=std::chrono::steady_clock;
std::atomic<bool> serviceStop{false}, bridgeStop{false};
std::vector<std::thread> serviceThreads;
std::vector<SOCKET> serviceSockets;
std::thread bridgeThread;
std::mutex bridgeMutex;
std::condition_variable bridgeWake;
std::deque<std::pair<std::string,Json>> bridgeInbox;
std::function<Json()> bridgeSearch;
std::function<void(Json)> bridgeResult;
#ifdef EMU_SERVICE_TEST_PORT_BASE
unsigned brokerPort=EMU_SERVICE_TEST_PORT_BASE;
constexpr unsigned discoveryPort=EMU_SERVICE_TEST_PORT_BASE+1;
#else
unsigned brokerPort=0;
#ifdef EMU_SERVICE_TEST_DISCOVERY_PORT
constexpr unsigned discoveryPort=EMU_SERVICE_TEST_DISCOVERY_PORT;
#else
constexpr unsigned discoveryPort=18651;
#endif
#endif
std::string localUrl="http://127.0.0.1:"+std::to_string(brokerPort);
bool winsockStarted=false;
std::vector<unsigned> discoveryPorts(){
#ifdef EMU_SERVICE_TEST_PORT_BASE
 return {discoveryPort};
#else
 std::vector<unsigned> ports;for(unsigned i=0;i<8;++i)ports.push_back(discoveryPort+i*10);return ports;
#endif
}
void bindFailure(bool tcp,const char*host,unsigned port,int error){
 Json owners=Json::array();if(!tcp){ULONG length=0;GetExtendedUdpTable(nullptr,&length,FALSE,AF_INET,UDP_TABLE_OWNER_PID,0);std::vector<unsigned char> buffer(length);if(length&&GetExtendedUdpTable(buffer.data(),&length,FALSE,AF_INET,UDP_TABLE_OWNER_PID,0)==NO_ERROR){auto table=reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buffer.data());for(DWORD i=0;i<table->dwNumEntries;++i)if(ntohs(static_cast<u_short>(table->table[i].dwLocalPort))==port)owners.push_back(table->table[i].dwOwningPid);}}
 log("socket_bind_failed",{{"transport",tcp?"TCP":"UDP"},{"address",host},{"port",port},{"wsaError",error},{"ownerPids",owners}});
}

std::string lower(std::string s) { for(char& c:s)c=char(std::tolower(static_cast<unsigned char>(c)));return s; }
std::string trim(std::string s) { auto a=s.find_first_not_of(" \t\r\n"),b=s.find_last_not_of(" \t\r\n");return a==std::string::npos?"":s.substr(a,b-a+1); }
std::wstring wide(const std::string& s) { int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0);if(!n&&!s.empty())throw std::runtime_error("invalid UTF8 URL");std::wstring w(n,0);MultiByteToWideChar(CP_UTF8,0,s.data(),int(s.size()),w.data(),n);return w; }
struct Internet {HINTERNET h=nullptr;explicit Internet(HINTERNET p):h(p){if(!h)throw std::runtime_error("WinHTTP "+std::to_string(GetLastError()));}~Internet(){WinHttpCloseHandle(h);}operator HINTERNET()const{return h;} };
sockaddr_in address(const char* ip,unsigned port) {sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(static_cast<u_short>(port));inet_pton(AF_INET,ip,&a.sin_addr);return a;}
std::string ipString(const sockaddr_in& a) {char s[INET_ADDRSTRLEN]{};inet_ntop(AF_INET,&a.sin_addr,s,sizeof(s));return s;}
bool readable(SOCKET s,unsigned ms) {fd_set set;FD_ZERO(&set);FD_SET(s,&set);timeval tv{long(ms/1000),long(ms%1000)*1000};return select(0,&set,nullptr,nullptr,&tv)>0;}
struct Interface {uint32_t ip;unsigned prefix;};
std::vector<Interface> interfaces() {
 ULONG n=16384;std::vector<unsigned char> bytes(n);auto p=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(bytes.data());
 ULONG rc=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,p,&n);
 if(rc==ERROR_BUFFER_OVERFLOW){bytes.resize(n);p=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(bytes.data());rc=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,p,&n);}
 std::vector<Interface> out;if(rc!=NO_ERROR)return out;
 for(auto a=p;a;a=a->Next)if(a->OperStatus==IfOperStatusUp)for(auto u=a->FirstUnicastAddress;u;u=u->Next)if(u->Address.lpSockaddr&&u->Address.lpSockaddr->sa_family==AF_INET){auto v=reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr);auto ip=ntohl(v->sin_addr.s_addr);if(ip&&ip<0xe0000000)out.push_back({ip,u->OnLinkPrefixLength});}
 return out;
}
SOCKET listenSocket(bool tcp,const char* host,unsigned port,bool shareBroadcast=false) {
 SOCKET s=socket(AF_INET,tcp?SOCK_STREAM:SOCK_DGRAM,tcp?IPPROTO_TCP:IPPROTO_UDP);if(s==INVALID_SOCKET)return s;
 BOOL yes=TRUE;setsockopt(s,SOL_SOCKET,shareBroadcast?SO_REUSEADDR:SO_EXCLUSIVEADDRUSE,reinterpret_cast<char*>(&yes),sizeof(yes));
 auto a=address(host,port);if(bind(s,reinterpret_cast<sockaddr*>(&a),sizeof(a))|| (tcp&&listen(s,32))){int error=WSAGetLastError();bindFailure(tcp,host,port,error);closesocket(s);WSASetLastError(error);return INVALID_SOCKET;}
 serviceSockets.push_back(s);return s;
}
struct Client {std::string session,party;Clock::time_point seen;Json signals=Json::array();};
struct Registry {
 std::mutex mutex;std::map<std::string,Json> sessions;std::map<std::string,Client> clients;uint64_t revision=0;
 void leave(const std::string& id) {
  for(auto it=sessions.begin();it!=sessions.end();){auto& r=it->second;if(r["host"]==id){it=sessions.erase(it);continue;}
   for(auto key:{"snapshot","party"})if(r.contains(key)&&r[key].is_object()) {auto& m=r[key]["members"];m.erase(std::remove_if(m.begin(),m.end(),[&](const Json& x){return x.value("id","")==id;}),m.end());}++it;}
  auto c=clients.find(id);if(c!=clients.end()){c->second.session.clear();c->second.party.clear();c->second.signals.clear();}++revision;
 }
 void expire() {auto now=Clock::now();for(auto it=clients.begin();it!=clients.end();)if(now-it->second.seen>std::chrono::seconds(20)){leave(it->first);it=clients.erase(it);}else ++it;}
 Json reject(){return {{"accepted",false},{"revision",revision},{"session",nullptr},{"party",nullptr}};}
 static Json* member(Json& list,const std::string& id){for(auto& m:list)if(m.value("id","")==id)return &m;return nullptr;}
 static void validateMember(const Json& m,const std::string& id){if(!m.is_object()||m.value("id","")!=id)throw std::runtime_error("member identity mismatch");}
 Json dispatch(const std::string& op,const Json& body) {
  std::lock_guard<std::mutex> lock(mutex);expire();if(op=="health")return {{"protocol",4}};
  auto id=body.value("identity",std::string());if(id.empty()||id.size()>128)throw std::runtime_error("identity required");auto& c=clients[id];c.seen=Clock::now();Json diag=Json::object();
  if(op=="publish"){
   Json incoming=body.at("session");auto sid=incoming.value("id",std::string());if(sid.empty())throw std::runtime_error("session required");auto own=member(incoming.at("members"),id);if(!own)throw std::runtime_error("publisher member missing");Json ownCopy=*own;
   auto old=sessions.find(sid);if(old!=sessions.end()&&old->second["host"]!=id)throw std::runtime_error("only host may publish session");
   if(old!=sessions.end()){incoming["members"]=Json::array({ownCopy});for(auto& m:old->second["snapshot"]["members"])if(m.value("id","")!=id)incoming["members"].push_back(m);}
   Json party=body.value("party",Json());if(party.is_object()&&old!=sessions.end()&&old->second["party"].is_object()) {Json ms=Json::array();for(auto& m:party["members"])if(m.value("id","")==id)ms.push_back(m);for(auto& m:old->second["party"]["members"])if(m.value("id","")!=id)ms.push_back(m);party["members"]=ms;}
   sessions[sid]={{"host",id},{"snapshot",incoming},{"party",party}};if(party.is_object())c.party=sid;c.session=sid;++revision;
  }else if(op=="party_member"){
   auto r=sessions.find(c.party);if(r!=sessions.end()&&r->second["party"].is_object()){auto m=body.at("member");validateMember(m,id);if(auto old=member(r->second["party"]["members"],id)){(*old)["name"]=m.value("name","");++revision;}}
  }else if(op=="join_code"){
   auto code=lower(trim(body.value("code",std::string())));Json* room=nullptr;for(auto& entry:sessions)if(entry.second["party"].is_object()&&!code.empty()&&lower(entry.second["party"].value("data",std::string()))==code){room=&entry.second;break;}if(!room)return reject();
   auto& party=(*room)["party"];auto m=body.at("partyMember");validateMember(m,id);auto old=member(party["members"],id);if(!old&&party["members"].size()>=party["settings"][0].get<size_t>())return reject();if(!old){m["flag18"]=0;party["members"].push_back(m);}c.party=(*room)["snapshot"]["id"].get<std::string>();++revision;
  }else if(op=="session_join"){
   auto sid=body.value("sessionId",std::string());auto r=sessions.find(sid);if(r==sessions.end()||c.party!=sid)return reject();auto& session=r->second["snapshot"];auto m=body.at("member");validateMember(m,id);auto old=member(session["members"],id);if(!old&&session["members"].size()>=session["settings"][0].get<size_t>())return reject();if(!old){m["flag18"]=0;session["members"].push_back(m);}c.session=sid;++revision;
  }else if(op=="member"){
   auto r=sessions.find(c.session);if(r!=sessions.end()){auto m=body.at("member");validateMember(m,id);if(auto old=member(r->second["snapshot"]["members"],id)){for(auto key:{"name","data","numericTail","securitySpans"})if(m.contains(key))(*old)[key]=m[key];++revision;}}
  }else if(op=="join"){
   if(sessions.empty())diag["no_rooms"]=1;auto m=body.at("member");validateMember(m,id);
   auto rejected=[&](const char* reason){diag[reason]=diag.value(reason,0)+1;};
   for(auto& entry:sessions){auto& r=entry.second;auto& s=r["snapshot"];if(r["host"]==id){rejected("own_room");continue;}
    Json variants=Json::object();for(auto& row:s.value("variants",Json::array()))if(row.is_array()&&row.size()>=2&&row[0].is_string())variants[row[0].get<std::string>()]=row[1];bool mismatch=false;auto requested=body.value("variants",Json::object());for(auto it=requested.begin();it!=requested.end();++it)if(variants.contains(it.key())&&(it.value().is_array()?std::find(it.value().begin(),it.value().end(),variants[it.key()])==it.value().end():variants[it.key()]!=it.value()))mismatch=true;if(mismatch){rejected("variant_mismatch");for(auto it=requested.begin();it!=requested.end();++it){if(!variants.contains(it.key()))continue;const auto& actual=variants[it.key()];const bool matches=it.value().is_array()?std::find(it.value().begin(),it.value().end(),actual)!=it.value().end():actual==it.value();if(!matches)diag["mismatched_keys"][it.key()]={{"room",actual},{"search",it.value()}};}continue;}
    auto playlist=body.value("playlist",std::string());if(!playlist.empty()&&s.value("field60",std::string())!=playlist){rejected("playlist_mismatch");continue;}
    if(s["settings"][1]==0||s["settings"][1]==false){rejected("closed");continue;}auto old=member(s["members"],id);if(!old&&s["members"].size()>=s["settings"][0].get<size_t>()){rejected("full");continue;}if(!old){m["flag18"]=0;s["members"].push_back(m);}c.session=entry.first;++revision;break;
   }
  }else if(op=="signal"){
   auto recipient=clients.find(body.value("recipient",std::string()));
   auto room=sessions.find(c.session);
   const auto& payload=body.at("payload");
   if(recipient==clients.end()){log("signal_route_rejected",{{"reason","recipient_unknown"}});return reject();}
   if(room==sessions.end()||recipient->second.session!=c.session){log("signal_route_rejected",{{"reason","different_session"}});return reject();}
   if(
      !payload.is_string()||payload.get_ref<const std::string&>().size()>65536||
      recipient->second.signals.size()>=128)return reject();
   recipient->second.signals.push_back({{"sender",id},{"id",body.at("signalId")},{"payload",payload}});
   return {{"accepted",true}};
  }else if(op=="leave")leave(id);else if(op!="poll")throw std::runtime_error("unknown operation");
  auto r=sessions.find(c.session),p=sessions.find(c.party);
  Json messages=Json::array();if(op=="poll")messages.swap(c.signals);
  return {{"signals",messages},{"revision",revision},{"accepted",true},{"party",p==sessions.end()?Json():p->second["party"]},{"session",r==sessions.end()?Json():r->second["snapshot"]},{"host",r==sessions.end()?Json():r->second["host"]},{"joinDiagnostics",diag}};
 }
 int count(){std::lock_guard<std::mutex> lock(mutex);expire();return int(sessions.size());}
} registry;
bool sendAll(SOCKET s,const std::string& data){size_t offset=0;while(offset<data.size()&&!serviceStop){int n=send(s,data.data()+offset,int(data.size()-offset),0);if(n<=0)return false;offset+=size_t(n);}return offset==data.size();}
void httpConnection(SOCKET client,bool broker) {
 DWORD timeout=1200;setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<char*>(&timeout),sizeof(timeout));setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<char*>(&timeout),sizeof(timeout));
 const auto deadline=Clock::now()+std::chrono::seconds(4);
 Json result;int status=200;try{
  std::string data;size_t end=std::string::npos;char block[8192];while((end=data.find("\r\n\r\n"))==std::string::npos){if(serviceStop||Clock::now()>deadline)throw std::runtime_error("request expired");int n=recv(client,block,sizeof(block),0);if(n<=0)throw std::runtime_error("incomplete headers");data.append(block,n);if(data.size()>65536)throw std::runtime_error("headers too large");}
  std::istringstream headers(data.substr(0,end));std::string method,path,version;headers>>method>>path>>version;size_t length=0;std::string line;while(std::getline(headers,line)){auto colon=line.find(':');if(colon!=std::string::npos&&lower(trim(line.substr(0,colon)))=="content-length")length=std::stoull(trim(line.substr(colon+1)));}if(length>1048576)throw std::runtime_error("request too large");
  std::string body=data.substr(end+4);while(body.size()<length){if(serviceStop||Clock::now()>deadline)throw std::runtime_error("request expired");int n=recv(client,block,int(std::min(sizeof(block),length-body.size())),0);if(n<=0)throw std::runtime_error("incomplete body");body.append(block,n);}body.resize(length);
  path=path.substr(0,path.find('?'));if(broker){if(method!="POST")throw std::runtime_error("POST required");while(!path.empty()&&path.front()=='/')path.erase(path.begin());while(!path.empty()&&path.back()=='/')path.pop_back();result=registry.dispatch(path,Json::parse(body));}
  else {status=501;result={{"error","RoadCraft mod.io adapter not implemented"}};log("modio_adapter_unavailable",{{"method",method},{"status",501}});}
 }catch(const std::exception& e){status=400;result={{"error",e.what()}};}
 auto body=result.dump();sendAll(client,"HTTP/1.1 "+std::to_string(status)+(status==200?" OK":status==501?" Not Implemented":" Bad Request")+"\r\nContent-Type: application/json\r\nContent-Length: "+std::to_string(body.size())+"\r\nConnection: close\r\n\r\n"+body);
}
void httpLoop(SOCKET server,bool broker) {while(!serviceStop&&!stopping){if(!readable(server,150))continue;SOCKET client=accept(server,nullptr,nullptr);if(client==INVALID_SOCKET)continue;httpConnection(client,broker);closesocket(client);}}
bool validDiscovery(const Json& p,const char* kind) {
 if(!p.is_object()||p.value("protocol",std::string())!="roadcraft-lan-broker"||!p.contains("version")||!p["version"].is_number_integer()||p["version"]!=1||p.value("kind",std::string())!=kind)return false;
 auto n=p.value("nonce",std::string());return n.size()==32&&n.find_first_not_of("0123456789abcdefABCDEF")==std::string::npos;
}
void discoveryLoop(SOCKET s) {auto serverId=randomHex(16);while(!serviceStop&&!stopping){if(!readable(s,150))continue;char b[513];sockaddr_in from{};int size=sizeof(from);int n=recvfrom(s,b,sizeof(b),0,reinterpret_cast<sockaddr*>(&from),&size);if(n<1||n>512)continue;try{auto q=Json::parse(b,b+n);if(!validDiscovery(q,"query"))continue;Json reply={{"protocol","roadcraft-lan-broker"},{"version",1},{"kind","reply"},{"nonce",q["nonce"]},{"http_port",brokerPort},{"server_id",serverId},{"room_count",std::min(registry.count(),65535)}};auto bytes=reply.dump();sendto(s,bytes.data(),int(bytes.size()),0,reinterpret_cast<sockaddr*>(&from),size);}catch(...){}}}
void echoLoop(SOCKET s) {std::vector<char> buffer(65535);while(!serviceStop&&!stopping){if(!readable(s,150))continue;sockaddr_in from{};int size=sizeof(from);int n=recvfrom(s,buffer.data(),static_cast<int>(buffer.size()),0,reinterpret_cast<sockaddr*>(&from),&size);if(n>=0)sendto(s,buffer.data(),n,0,reinterpret_cast<sockaddr*>(&from),size);}}
std::vector<std::string> candidates(const std::vector<std::string>& peers){std::vector<std::string> out{localUrl};for(auto& p:peers)if(std::find(out.begin(),out.end(),p)==out.end())out.push_back(p);return out;}
void result(Json r){if(bridgeResult&&!bridgeStop&&!stopping)bridgeResult(std::move(r));}
void bridgeLoop(){
 std::string url=localUrl;auto nextPoll=Clock::now(),nextDiscovery=Clock::time_point{};std::vector<std::string> peers;
 while(!bridgeStop&&!stopping){if(!identityReady.load(std::memory_order_acquire)){Sleep(50);continue;}std::pair<std::string,Json> event;bool hasEvent=false;{std::unique_lock<std::mutex> lock(bridgeMutex);bridgeWake.wait_for(lock,std::chrono::milliseconds(100),[]{return bridgeStop||!bridgeInbox.empty();});if(!bridgeInbox.empty()){event=std::move(bridgeInbox.front());bridgeInbox.pop_front();hasEvent=true;}}
  try{
   if(hasEvent){auto op=event.first;auto body=event.second;body["identity"]=identity;Json response;if(op=="publish")url=localUrl;
    if(op=="join_code"){response={{"accepted",false},{"session",nullptr},{"party",nullptr}};for(auto& candidate:candidates(discover())){if(bridgeStop||stopping)break;try{auto found=httpRequest(candidate,op,body);if(found.value("accepted",false)){response=found;url=candidate;break;}}catch(...){}}}
    else response=httpRequest(url,op,body);if(body.contains("requestToken"))response["requestToken"]=body["requestToken"];if(op=="signal")response["signalId"]=body.at("signalId");result(response);log("room_broker",{{"event",op}});
   }
   if(Clock::now()>=nextPoll&&!bridgeStop&&!stopping){nextPoll=Clock::now()+std::chrono::milliseconds(300);Json search=bridgeSearch?bridgeSearch():Json();Json response;
    if(search.is_object()&&!search.empty()){if(Clock::now()>=nextDiscovery){peers=discover();nextDiscovery=Clock::now()+std::chrono::seconds(1);}response={{"session",nullptr}};search["identity"]=identity;for(auto& candidate:candidates(peers)){if(bridgeStop||stopping)break;try{auto found=httpRequest(candidate,"join",search);const bool matched=found.contains("session")&&found["session"].is_object();log("search_broker_result",{{"matched",matched},{"filters",found.value("joinDiagnostics",Json::object())}});if(matched){response=found;url=candidate;break;}}catch(...){}}}
    else response=httpRequest(url,"poll",{{"identity",identity}});result(response);
   }
  }catch(const std::exception& e){if(hasEvent&&event.first=="signal")result({{"signalId",event.second["signalId"]},{"accepted",false}});if(hasEvent&&event.second.contains("requestToken"))result({{"requestToken",event.second["requestToken"]},{"accepted",false}});if(!bridgeStop&&!stopping)log("room_broker",{{"event","error"},{"error",e.what()}});}
 }
 try{httpRequest(url,"leave",{{"identity",identity}});}catch(...){}
}
} // namespace

std::string preferredIP(){
 auto pairs=interfaces();SOCKET s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);if(s!=INVALID_SOCKET){auto remote=address("8.8.8.8",9);if(connect(s,reinterpret_cast<sockaddr*>(&remote),sizeof(remote))==0){sockaddr_in own{};int n=sizeof(own);if(!getsockname(s,reinterpret_cast<sockaddr*>(&own),&n)){auto ip=ntohl(own.sin_addr.s_addr);if(ip>>24!=127&&ip>>16!=0xa9fe){closesocket(s);return ipString(own);}}}closesocket(s);}
 for(bool onlyPrivate:{true,false})for(auto a:pairs){if(a.ip>>24==127||a.ip>>16==0xa9fe)continue;bool priv=(a.ip>>24==10)||(a.ip>>20==0xac1)||(a.ip>>16==0xc0a8);if(onlyPrivate&&!priv)continue;sockaddr_in own{};own.sin_family=AF_INET;own.sin_addr.s_addr=htonl(a.ip);return ipString(own);}return "127.0.0.1";
}
Json httpRequest(const std::string& url,const std::string& operation,const Json& body){
 auto w=wide(url+"/"+operation);URL_COMPONENTS c{};c.dwStructSize=sizeof(c);c.dwHostNameLength=c.dwUrlPathLength=c.dwExtraInfoLength=DWORD(-1);if(!WinHttpCrackUrl(w.c_str(),DWORD(w.size()),0,&c))throw std::runtime_error("invalid broker URL");if(c.nScheme!=INTERNET_SCHEME_HTTP)throw std::runtime_error("broker HTTP required");
 std::wstring host(c.lpszHostName,c.dwHostNameLength),path(c.lpszUrlPath,c.dwUrlPathLength);Internet session(WinHttpOpen(L"ProsLocalLAN/1",WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0));WinHttpSetTimeouts(session,1000,1000,1500,1500);Internet connection(WinHttpConnect(session,host.c_str(),c.nPort,0));Internet request(WinHttpOpenRequest(connection,L"POST",path.c_str(),nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,0));auto bytes=body.dump();if(!WinHttpSendRequest(request,L"Content-Type: application/json\r\n",DWORD(-1),bytes.data(),DWORD(bytes.size()),DWORD(bytes.size()),0)||!WinHttpReceiveResponse(request,nullptr))throw std::runtime_error("broker request "+std::to_string(GetLastError()));
 DWORD code=0,n=sizeof(code);WinHttpQueryHeaders(request,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&code,&n,WINHTTP_NO_HEADER_INDEX);if(code!=200)throw std::runtime_error("broker HTTP "+std::to_string(code));std::string response;auto deadline=Clock::now()+std::chrono::seconds(4);for(;;){if(Clock::now()>deadline)throw std::runtime_error("broker response expired");DWORD available=0;if(!WinHttpQueryDataAvailable(request,&available))throw std::runtime_error("broker response failed");if(!available)break;if(response.size()+available>1048576)throw std::runtime_error("broker response too large");size_t at=response.size();response.resize(at+available);DWORD got=0;if(!WinHttpReadData(request,response.data()+at,available,&got))throw std::runtime_error("broker response read failed");response.resize(at+got);if(!got)break;}return Json::parse(response);
}
std::vector<std::string> discover(){
 SOCKET s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);if(s==INVALID_SOCKET)return {};BOOL yes=TRUE;setsockopt(s,SOL_SOCKET,SO_BROADCAST,reinterpret_cast<char*>(&yes),sizeof(yes));auto own=address("0.0.0.0",0);if(bind(s,reinterpret_cast<sockaddr*>(&own),sizeof(own))){closesocket(s);return {};}
 auto nonce=randomHex(16);auto q=Json({{"protocol","roadcraft-lan-broker"},{"version",1},{"kind","query"},{"nonce",nonce}}).dump();std::set<uint32_t> targets{0xffffffff,0x7f000001};for(auto a:interfaces())if(a.ip>>24!=127&&a.prefix<31){uint32_t mask=a.prefix?0xffffffffu<<(32-a.prefix):0;targets.insert(a.ip|~mask);}for(auto port:discoveryPorts())for(auto ip:targets){sockaddr_in target{};target.sin_family=AF_INET;target.sin_port=htons(static_cast<u_short>(port));target.sin_addr.s_addr=htonl(ip);sendto(s,q.data(),int(q.size()),0,reinterpret_cast<sockaddr*>(&target),sizeof(target));}
 auto deadline=Clock::now()+std::chrono::milliseconds(200);std::map<std::string,int> replies;while(Clock::now()<deadline&&!bridgeStop&&!serviceStop&&!stopping){auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();if(!readable(s,unsigned(std::max<int64_t>(left,1))))continue;char b[513];sockaddr_in source{};int nsource=sizeof(source);int n=recvfrom(s,b,sizeof(b),0,reinterpret_cast<sockaddr*>(&source),&nsource);if(n<1||n>512)continue;try{auto p=Json::parse(b,b+n);if(!validDiscovery(p,"reply")||p["nonce"]!=nonce||!p["http_port"].is_number_integer()||!p["room_count"].is_number_integer())continue;auto port=p["http_port"].get<int>(),count=p["room_count"].get<int>();auto server=p.value("server_id",std::string());auto ip=ntohl(source.sin_addr.s_addr);if(port<1||port>65535||count<0||count>65535||server.size()!=32||server.find_first_not_of("0123456789abcdefABCDEF")!=std::string::npos||!ip||ip>=0xe0000000)continue;replies["http://"+ipString(source)+":"+std::to_string(port)]=count;}catch(...){} }
 closesocket(s);std::vector<std::string> out;for(auto& r:replies)out.push_back(r.first);std::sort(out.begin(),out.end(),[&](auto& a,auto& b){return replies[a]==replies[b]?a<b:replies[a]>replies[b];});return out;
}
void startServices(){
 if(winsockStarted)return;WSADATA data{};if(WSAStartup(MAKEWORD(2,2),&data))throw std::runtime_error("WSAStartup failed");winsockStarted=true;serviceStop=false;if(!identity.empty())identityReady.store(true,std::memory_order_release);
 bool existing=false;
#ifdef EMU_SERVICE_TEST_PORT_BASE
 // Fixed-port mode exists only for the Python protocol4 interoperability test.
 try{existing=httpRequest(localUrl,"health",Json::object()).value("protocol",0)==4;}catch(...){}
#else
 // Every DLL process owns its registry. No helper lifetime or primary-player dependency.
 brokerPort=0;
#endif
 if(!existing){auto s=listenSocket(true,"0.0.0.0",brokerPort);if(s==INVALID_SOCKET)throw std::runtime_error("broker bind failed");sockaddr_in assigned{};int assignedSize=sizeof(assigned);if(getsockname(s,reinterpret_cast<sockaddr*>(&assigned),&assignedSize))throw std::runtime_error("broker address failed");brokerPort=ntohs(assigned.sin_port);localUrl="http://127.0.0.1:"+std::to_string(brokerPort);serviceThreads.emplace_back([s]{httpLoop(s,true);});
  // Each local broker needs its own port so loopback discovery reaches every instance.
  constexpr bool shareDiscovery=false;
  SOCKET d=INVALID_SOCKET;unsigned selectedPort=0;for(auto port:discoveryPorts()){d=listenSocket(false,"0.0.0.0",port,shareDiscovery);if(d!=INVALID_SOCKET){selectedPort=port;break;}}if(d==INVALID_SOCKET)throw std::runtime_error("All discovery ports unavailable; see socket_bind_failed Windows errors and ownerPids");log("discovery_listening",{{"port",selectedPort},{"fallback",selectedPort!=discoveryPort},{"scannedPorts",discoveryPorts()}});serviceThreads.emplace_back([d]{discoveryLoop(d);});}
 auto mod=listenSocket(true,"127.0.0.1",18630+portOffset);if(mod==INVALID_SOCKET)throw std::runtime_error("modio bind failed");serviceThreads.emplace_back([mod]{httpLoop(mod,false);});auto echo=listenSocket(false,"127.0.0.1",18632+portOffset);if(echo==INVALID_SOCKET)throw std::runtime_error("echo bind failed");serviceThreads.emplace_back([echo]{echoLoop(echo);});log("services",{{"event","started"},{"brokerReused",existing},{"brokerPort",brokerPort},{"address",preferredIP()}});
}
void stopServices(){serviceStop=true;for(auto s:serviceSockets){shutdown(s,SD_BOTH);closesocket(s);}for(auto& t:serviceThreads)if(t.joinable())t.join();serviceThreads.clear();serviceSockets.clear();if(winsockStarted){WSACleanup();winsockStarted=false;}}
void startBridge(std::function<Json()> search,std::function<void(Json)> update){if(bridgeThread.joinable())return;bridgeSearch=std::move(search);bridgeResult=std::move(update);bridgeStop=false;{std::lock_guard<std::mutex> lock(bridgeMutex);bridgeInbox.clear();}if(identityReady.load(std::memory_order_acquire))try{httpRequest(localUrl,"leave",{{"identity",identity}});}catch(...){}bridgeThread=std::thread(bridgeLoop);}
void bridgeSubmit(const std::string& operation,Json body){if(bridgeStop||stopping)return;{std::lock_guard<std::mutex> lock(bridgeMutex);bridgeInbox.emplace_back(operation,std::move(body));}bridgeWake.notify_one();}
void stopBridge(){bridgeStop=true;bridgeWake.notify_all();if(bridgeThread.joinable())bridgeThread.join();{std::lock_guard<std::mutex> lock(bridgeMutex);bridgeInbox.clear();}}
} // namespace emu
