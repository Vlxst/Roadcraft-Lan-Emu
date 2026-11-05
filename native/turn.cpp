#include "emu.h"
#include <array>
#include <algorithm>
#include <stdexcept>
#include <cstring>

// IPv4/UDP subset matching the tested local Python service. No TCP/TLS,
// IPv6, EVEN-PORT, reservation tokens or SHA256 credential negotiation.
namespace emu {
TurnConfig turnConfig;
namespace {
using Bytes=std::vector<unsigned char>;
using Clock=std::chrono::steady_clock;
double now(){return std::chrono::duration<double>(Clock::now().time_since_epoch()).count();}
constexpr uint32_t Cookie=0x2112a442;
enum : uint16_t {User=6,Integrity=8,Error=9,Unknown=10,Channel=12,Lifetime=13,Peer=18,Data=19,Realm=20,Nonce=21,Relayed=22,Transport=25,Mapped=32,Software=0x8022,Fingerprint=0x8028};
unsigned u16(const Bytes& b,size_t n){return (unsigned(b.at(n))<<8)|b.at(n+1);}
uint32_t u32(const Bytes& b,size_t n){return (uint32_t(u16(b,n))<<16)|u16(b,n+2);}
void put16(Bytes& b,unsigned n){b.push_back((unsigned char)(n>>8));b.push_back((unsigned char)n);}
void put32(Bytes& b,uint32_t n){put16(b,n>>16);put16(b,n);}
Bytes str(const std::string& s){return Bytes(s.begin(),s.end());}
Bytes number(uint32_t n){Bytes b;put32(b,n);return b;}
Bytes digest(LPCWSTR algorithm,const Bytes& data,const Bytes* key=nullptr){
 BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;DWORD n=0,size=0,length=0;
 if(BCryptOpenAlgorithmProvider(&alg,algorithm,nullptr,key?BCRYPT_ALG_HANDLE_HMAC_FLAG:0)<0)throw std::runtime_error("BCrypt algorithm");
 auto close=[&]{if(hash)BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);};
 if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&size,sizeof(size),&n,0)<0||BCryptGetProperty(alg,BCRYPT_HASH_LENGTH,(PUCHAR)&length,sizeof(length),&n,0)<0){close();throw std::runtime_error("BCrypt property");}
 Bytes object(size),result(length);
 if(BCryptCreateHash(alg,&hash,object.data(),size,key?const_cast<PUCHAR>(key->data()):nullptr,key?(ULONG)key->size():0,0)<0||BCryptHashData(hash,const_cast<PUCHAR>(data.data()),(ULONG)data.size(),0)<0||BCryptFinishHash(hash,result.data(),length,0)<0){close();throw std::runtime_error("BCrypt digest");}
 close();return result;
}
uint32_t crc32(const unsigned char* p,size_t n){uint32_t c=~0u;while(n--){c^=*p++;for(int i=0;i<8;i++)c=(c>>1)^((0u-(c&1))&0xedb88320u);}return ~c;}
struct Address {
 uint32_t ip=0;uint16_t port=0; // network byte order, suitable for sockaddr_in
 Address()=default;
 explicit Address(const sockaddr_in& a):ip(a.sin_addr.s_addr),port(a.sin_port){}
 sockaddr_in native()const{sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=ip;a.sin_port=port;return a;}
 bool operator<(const Address& o)const{return ip<o.ip||(ip==o.ip&&port<o.port);}
 bool operator==(const Address& o)const{return ip==o.ip&&port==o.port;}
 bool operator!=(const Address& o)const{return !(*this==o);}
 Json json()const{char text[INET_ADDRSTRLEN]{};in_addr a{};a.s_addr=ip;inet_ntop(AF_INET,&a,text,sizeof(text));return Json::array({text,ntohs(port)});}
};
Bytes xorAddress(Address a){Bytes b{0,1};put16(b,ntohs(a.port)^(Cookie>>16));put32(b,ntohl(a.ip)^Cookie);return b;}
Address decodeAddress(const Bytes& b){if(b.size()!=8||b[0]||b[1]!=1)throw std::runtime_error("IPv4 XOR address required");Address a;a.port=htons((uint16_t)(u16(b,2)^(Cookie>>16)));a.ip=htonl(u32(b,4)^Cookie);return a;}
using Attributes=std::vector<std::pair<uint16_t,Bytes>>;
void attribute(Bytes& b,uint16_t t,const Bytes& v){put16(b,t);put16(b,(unsigned)v.size());b.insert(b.end(),v.begin(),v.end());while(b.size()%4)b.push_back(0);}
Bytes header(unsigned method,unsigned cls,const Bytes& tid,size_t length){Bytes b;put16(b,(method&15)|((method&0x70)<<1)|((method&0xf80)<<2)|((cls&1)<<4)|((cls&2)<<7));put16(b,(unsigned)length);put32(b,Cookie);b.insert(b.end(),tid.begin(),tid.end());return b;}
Bytes pack(unsigned method,unsigned cls,const Bytes& tid,const Attributes& attrs,const Bytes* key=nullptr){
 Bytes body;for(auto& a:attrs)attribute(body,a.first,a.second);
 if(key){auto input=header(method,cls,tid,body.size()+24);input.insert(input.end(),body.begin(),body.end());attribute(body,Integrity,digest(BCRYPT_SHA1_ALGORITHM,input,key));}
 // The observed SDK parser does not accept the standard fingerprint XOR.
 // Omit the optional fingerprint in every outbound packet.
 auto result=header(method,cls,tid,body.size());result.insert(result.end(),body.begin(),body.end());return result;
}
struct Field {uint16_t type;Bytes value;size_t offset;};
struct Packet {unsigned method,cls;Bytes tid;std::vector<Field> fields;};
Packet parse(const Bytes& b){
 if(b.size()<20||u16(b,0)&0xc000||u32(b,4)!=Cookie||u16(b,2)%4||u16(b,2)+20!=b.size())throw std::runtime_error("invalid STUN framing");
 unsigned t=u16(b,0);Packet p{(t&15)|((t>>1)&0x70)|((t>>2)&0xf80),((t>>4)&1)|((t>>7)&2),Bytes(b.begin()+8,b.begin()+20),{}};
 for(size_t off=20;off<b.size();){if(off+4>b.size())throw std::runtime_error("short attribute");size_t n=u16(b,off+2),end=off+4+n;if(end>b.size())throw std::runtime_error("attribute overflow");p.fields.push_back({(uint16_t)u16(b,off),Bytes(b.begin()+off+4,b.begin()+end),off});off=end+((4-n%4)%4);if(off>b.size())throw std::runtime_error("attribute padding overflow");}
 return p;
}
bool verifyFingerprint(const Bytes& b,const Packet& p){unsigned count=0;for(auto& f:p.fields)if(f.type==Fingerprint){if(++count!=1||f.value.size()!=4||f.offset+8!=b.size()||u32(f.value,0)!=(crc32(b.data(),f.offset)^0x5354554e))return false;}return true;}
bool verifyIntegrity(const Bytes& b,const Packet& p,const Bytes& key){for(auto& f:p.fields)if(f.type==Integrity){if(f.value.size()!=20)return false;Bytes input(b.begin(),b.begin()+f.offset);unsigned length=(unsigned)f.offset+4;input[2]=(unsigned char)(length>>8);input[3]=(unsigned char)length;auto computed=digest(BCRYPT_SHA1_ALGORITHM,input,&key);unsigned diff=0;for(size_t i=0;i<20;i++)diff|=computed[i]^f.value[i];return diff==0;}return false;}
Bytes randomBytes(size_t size){Bytes b(size);if(BCryptGenRandom(nullptr,b.data(),(ULONG)size,BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw std::runtime_error("BCrypt random");return b;}
struct Allocation {Address client;SOCKET relay=INVALID_SOCKET;double expires=0;std::map<uint32_t,double> permissions;std::map<uint16_t,std::pair<Address,double>> channels;};
struct Cached {double expiry;Bytes packet;};
struct Server {
 SOCKET socket=INVALID_SOCKET;std::thread thread;std::atomic<bool> stop{false};std::map<Address,Allocation> allocations;
 std::map<Bytes,std::pair<Address,double>> nonces;std::map<std::string,Cached> cache;Bytes user,realm=str("lan-private"),key;
 Json counters={{"binding",0},{"allocated",0},{"client_to_peer_packets",0},{"peer_to_client_packets",0},{"client_to_peer_bytes",0},{"peer_to_client_bytes",0},{"dropped",0},{"auth_rejected",0}};
 uint32_t advertise=0;
 void count(const char* name,size_t n=1){counters[name]=counters[name].get<uint64_t>()+n;}
 void event(const char* kind,Json fields=Json::object()){log(std::string("turn_")+kind,std::move(fields));}
 static SOCKET bind(unsigned port){SOCKET s=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);if(s==INVALID_SOCKET)throw std::runtime_error("TURN socket");sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=INADDR_ANY;a.sin_port=htons((u_short)port);if(::bind(s,(sockaddr*)&a,sizeof(a))==SOCKET_ERROR){closesocket(s);throw std::runtime_error("TURN bind");}u_long nb=1;ioctlsocket(s,FIONBIO,&nb);return s;}
 void send(const Bytes& b,Address to){auto a=to.native();if(sendto(socket,(const char*)b.data(),(int)b.size(),0,(sockaddr*)&a,sizeof(a))==SOCKET_ERROR)count("dropped");}
 std::string cacheKey(Address client,unsigned method,const Bytes& tid){std::string k((const char*)&client.ip,4);k.append((const char*)&client.port,2);k.append((const char*)&method,sizeof(method));k.append((const char*)tid.data(),tid.size());return k;}
 void reply(const Packet& p,Address client,Attributes attrs={},unsigned error=0,bool signedReply=false,bool cacheReply=true){
  if(error)attrs.insert(attrs.begin(),{Error,Bytes{0,0,(unsigned char)(error/100),(unsigned char)(error%100)}});
  auto data=pack(p.method,error?3:2,p.tid,attrs,signedReply?&key:nullptr);
  if(cacheReply)cache[cacheKey(client,p.method,p.tid)]={now()+40,data};send(data,client);
 }
 void challenge(const Packet& p,Address client,unsigned code=401,bool sign=false){auto n=str(randomHex(8));nonces[n]={client,now()+600};reply(p,client,{{Nonce,n},{Realm,realm}},code,sign,false);}
 bool auth(const Bytes& raw,const Packet& p,Address client){std::map<unsigned,Bytes> d;for(auto& f:p.fields){d[f.type]=f.value;if(f.type==Integrity)break;}
  if(!d.count(User)||!d.count(Realm)||!d.count(Nonce)||!d.count(Integrity)){challenge(p,client);return false;}
  if(d[User]!=user||d[Realm]!=realm||!verifyIntegrity(raw,p,key)){count("auth_rejected");challenge(p,client);return false;}
  auto it=nonces.find(d[Nonce]);if(it==nonces.end()||it->second.first!=client||it->second.second<now()){challenge(p,client,438,true);return false;}return true;
 }
 bool receivedPacket=false;
 void remove(Address client){auto it=allocations.find(client);if(it==allocations.end())return;closesocket(it->second.relay);allocations.erase(it);event("allocation_closed",{{"client",client.json()}});}
 void forward(Allocation& a,Address peer,const Bytes& data){auto it=a.permissions.find(peer.ip);if(it==a.permissions.end()||it->second<now()){count("dropped");return;}auto to=peer.native();if(sendto(a.relay,(const char*)data.data(),(int)data.size(),0,(sockaddr*)&to,sizeof(to))==SOCKET_ERROR){count("dropped");return;}count("client_to_peer_packets");count("client_to_peer_bytes",data.size());}
 void client(const Bytes& raw,Address address){
  if(!receivedPacket){receivedPacket=true;event("first_packet",{{"bytes",raw.size()}});}
  if(raw.size()>=4&&u16(raw,0)>=0x4000&&u16(raw,0)<=0x7fff){auto it=allocations.find(address);auto ch=(uint16_t)u16(raw,0);size_t n=u16(raw,2);if(raw.size()<n+4||it==allocations.end()||!it->second.channels.count(ch)||it->second.channels[ch].second<now()){count("dropped");return;}forward(it->second,it->second.channels[ch].first,Bytes(raw.begin()+4,raw.begin()+4+n));return;}
  auto p=parse(raw);if(!verifyFingerprint(raw,p)){count("dropped");event("invalid_fingerprint");return;}if(p.cls!=0&&p.cls!=1)return;
  std::map<unsigned,Bytes> d;Attributes semantic;for(auto& f:p.fields){if(f.type==Integrity)break;d[f.type]=f.value;semantic.push_back({f.type,f.value});}
  if(p.cls==1){if(p.method==6){if(!d.count(Peer)||!d.count(Data)){count("dropped");return;}Address peer=decodeAddress(d[Peer]);auto it=allocations.find(address);if(it!=allocations.end())forward(it->second,peer,d[Data]);}return;}
  auto cached=cache.find(cacheKey(address,p.method,p.tid));if(cached!=cache.end()&&cached->second.expiry>now()){send(cached->second.packet,address);return;}
  if(p.method==1){count("binding");reply(p,address,{{Mapped,xorAddress(address)},{Software,str("lan-local")}});return;}
  if(!auth(raw,p,address))return;
  std::set<unsigned> known{User,Realm,Nonce,Integrity,Fingerprint,Software,Transport,Lifetime,Peer,Data,Channel,0x1a,0x22},unknown;
  for(auto& f:p.fields)if(f.type<0x8000&&!known.count(f.type))unknown.insert(f.type);
  if(!unknown.empty()){Bytes b;for(auto t:unknown)put16(b,t);reply(p,address,{{Unknown,b}},420,true);return;}
  if(d.count(0x1a)||d.count(0x22)){reply(p,address,{},420,true);return;}
  auto it=allocations.find(address);double current=now();
  if(p.method==3){
   if(it!=allocations.end()){reply(p,address,{},437,true);return;}
   // Winsock fd_set is bounded; reserve one entry for the listener instead
   // of silently creating a relay that select() cannot ever service.
   if(allocations.size()>=FD_SETSIZE-1){reply(p,address,{},508,true);return;}
   if(d[Transport]!=Bytes{17,0,0,0}){reply(p,address,{},442,true);return;}
   if(d.count(Lifetime)&&d[Lifetime].size()!=4){reply(p,address,{},400,true);return;}
   unsigned lifetime=std::min(std::max(d.count(Lifetime)?u32(d[Lifetime],0):600u,600u),3600u);
   Allocation a;a.client=address;a.relay=bind(0);a.expires=current+lifetime;sockaddr_in relay{};int len=sizeof(relay);getsockname(a.relay,(sockaddr*)&relay,&len);Address advertised(relay);advertised.ip=advertise;
   allocations.emplace(address,std::move(a));count("allocated");reply(p,address,{{Relayed,xorAddress(advertised)},{Mapped,xorAddress(address)},{Lifetime,number(lifetime)}},0,true);event("allocated",{{"client",address.json()},{"relay",advertised.json()},{"lifetime",lifetime}});return;
  }
  if(it==allocations.end()){reply(p,address,{},437,true);return;}auto& a=it->second;
  if(p.method==4){if(d.count(Lifetime)&&d[Lifetime].size()!=4){reply(p,address,{},400,true);return;}unsigned lifetime=std::min(d.count(Lifetime)?u32(d[Lifetime],0):600u,3600u);if(!lifetime)remove(address);else{lifetime=std::max(600u,lifetime);a.expires=current+lifetime;}reply(p,address,{{Lifetime,number(lifetime)}},0,true);return;}
  if(p.method==8){std::vector<Address> peers;try{for(auto& f:semantic)if(f.first==Peer)peers.push_back(decodeAddress(f.second));}catch(...){reply(p,address,{},400,true);return;}if(peers.empty()){reply(p,address,{},400,true);return;}for(auto peer:peers)a.permissions[peer.ip]=current+300;reply(p,address,{},0,true);return;}
  if(p.method==9){Address peer;unsigned ch;try{if(d[Channel].size()!=4)throw std::runtime_error("channel");ch=u16(d[Channel],0);if(ch<0x4000||ch>0x7fff)throw std::runtime_error("channel range");peer=decodeAddress(d[Peer]);}catch(...){reply(p,address,{},400,true);return;}
   if(a.channels.count((uint16_t)ch)&&a.channels[(uint16_t)ch].first!=peer){reply(p,address,{},400,true);return;}for(auto& entry:a.channels)if(entry.first!=ch&&entry.second.first==peer){reply(p,address,{},400,true);return;}a.channels[(uint16_t)ch]={peer,current+600};a.permissions[peer.ip]=current+300;reply(p,address,{},0,true);return;
  }
  reply(p,address,{},400,true);
 }
 void peer(Allocation& a){Bytes data(65535);sockaddr_in from{};int len=sizeof(from);int n=recvfrom(a.relay,(char*)data.data(),(int)data.size(),0,(sockaddr*)&from,&len);if(n==SOCKET_ERROR)return;data.resize(n);Address peer(from);auto permission=a.permissions.find(peer.ip);if(permission==a.permissions.end()||permission->second<now()){count("dropped");return;}Bytes packet;for(auto& ch:a.channels)if(ch.second.first==peer&&ch.second.second>now()){put16(packet,ch.first);put16(packet,(unsigned)data.size());packet.insert(packet.end(),data.begin(),data.end());break;}if(packet.empty())packet=pack(7,1,randomBytes(12),{{Peer,xorAddress(peer)},{Data,data}});send(packet,a.client);count("peer_to_client_packets");count("peer_to_client_bytes",data.size());}
 void clean(){double t=now();std::vector<Address> expired;for(auto& item:allocations){auto& a=item.second;if(a.expires<=t){expired.push_back(item.first);continue;}for(auto it=a.permissions.begin();it!=a.permissions.end();)if(it->second<=t)it=a.permissions.erase(it);else ++it;for(auto it=a.channels.begin();it!=a.channels.end();)if(it->second.second<=t)it=a.channels.erase(it);else ++it;}for(auto a:expired)remove(a);for(auto it=nonces.begin();it!=nonces.end();)if(it->second.second<=t)it=nonces.erase(it);else ++it;for(auto it=cache.begin();it!=cache.end();)if(it->second.expiry<=t)it=cache.erase(it);else ++it;}
 void run(){while(!stop&&!stopping){fd_set read;FD_ZERO(&read);FD_SET(socket,&read);for(auto& a:allocations)FD_SET(a.second.relay,&read);timeval timeout{0,100000};if(select(0,&read,nullptr,nullptr,&timeout)>0){if(FD_ISSET(socket,&read)){Bytes packet(65535);sockaddr_in from{};int size=sizeof(from);int n=recvfrom(socket,(char*)packet.data(),(int)packet.size(),0,(sockaddr*)&from,&size);if(n>=0){packet.resize(n);try{client(packet,Address(from));}catch(const std::exception& e){count("dropped");event("packet_rejected",{{"reason",e.what()}});}}}for(auto& a:allocations)if(FD_ISSET(a.second.relay,&read))try{peer(a.second);}catch(const std::exception& e){count("dropped");event("packet_rejected",{{"reason",e.what()}});}}clean();}
  while(!allocations.empty())remove(allocations.begin()->first);closesocket(socket);socket=INVALID_SOCKET;event("stopped",{{"counters",counters}});
 }
 void start(){user=str(turnConfig.username);if(user.empty()||turnConfig.password.empty())throw std::runtime_error("TURN per-run credentials required");key=digest(BCRYPT_MD5_ALGORITHM,str(turnConfig.username+":lan-private:"+turnConfig.password));auto ip=preferredIP();in_addr a{};if(inet_pton(AF_INET,ip.c_str(),&a)!=1||a.s_addr==0)throw std::runtime_error("TURN advertise address");advertise=a.s_addr;socket=bind(turnConfig.port);thread=std::thread([this]{run();});event("started",{{"address",Json::array({"0.0.0.0",turnConfig.port})},{"advertise",ip}});}
 ~Server(){stop=true;if(thread.joinable())thread.join();if(socket!=INVALID_SOCKET)closesocket(socket);}
};
std::unique_ptr<Server> server;
std::mutex lifecycle;
}
void startTurn(){std::lock_guard<std::mutex> lock(lifecycle);if(server)return;auto next=std::make_unique<Server>();next->start();server=std::move(next);}
void stopTurn(){std::lock_guard<std::mutex> lock(lifecycle);server.reset();}
}
