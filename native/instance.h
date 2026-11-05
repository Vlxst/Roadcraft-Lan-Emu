#pragma once
#include "emu.h"
namespace emu {
// Named events remain alive while the handle is held; unlike an owned mutex,
// they are not abandoned when the short initialization thread returns.
struct InstanceLease {
 HANDLE handle=nullptr;unsigned offset=0;
 InstanceLease()=default;InstanceLease(const InstanceLease&)=delete;
 ~InstanceLease(){if(handle)CloseHandle(handle);}
 void acquire(){
  SECURITY_DESCRIPTOR descriptor{};
  if(!InitializeSecurityDescriptor(&descriptor,SECURITY_DESCRIPTOR_REVISION)||!SetSecurityDescriptorDacl(&descriptor,TRUE,nullptr,FALSE))throw std::runtime_error("Instance lease security");
  SECURITY_ATTRIBUTES attributes{sizeof(attributes),&descriptor,FALSE};
  for(unsigned i=0;i<4096;++i){
   std::wstring name=L"Global\\SnowRunnerNativeLANSlotV2_"+std::to_wstring(i);
   HANDLE candidate=CreateEventW(&attributes,TRUE,FALSE,name.c_str());DWORD error=GetLastError();
   if(!candidate){if(error==ERROR_ACCESS_DENIED)continue;throw std::runtime_error("Global instance lease unavailable: "+std::to_string(error));}
   if(error==ERROR_ALREADY_EXISTS){CloseHandle(candidate);continue;}
   SOCKET sockets[3]={INVALID_SOCKET,INVALID_SOCKET,INVALID_SOCKET};bool available=true;
   for(unsigned j=0;j<3;++j){sockets[j]=socket(AF_INET,j==0?SOCK_STREAM:SOCK_DGRAM,j==0?IPPROTO_TCP:IPPROTO_UDP);BOOL exclusive=TRUE;setsockopt(sockets[j],SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<char*>(&exclusive),sizeof(exclusive));sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(j==2?INADDR_ANY:INADDR_LOOPBACK);address.sin_port=htons(static_cast<u_short>(18630+i*10+(j==0?0:j==1?2:3)));if(bind(sockets[j],reinterpret_cast<sockaddr*>(&address),sizeof(address)))available=false;}
   for(auto socketHandle:sockets)if(socketHandle!=INVALID_SOCKET)closesocket(socketHandle);
   if(available){handle=candidate;offset=i*10;return;}CloseHandle(candidate);
  }
  throw std::runtime_error("No free native LAN instance slot");
 }
};
}
