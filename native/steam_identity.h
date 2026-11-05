#pragma once
#include "emu.h"
#include <sstream>
#include <iomanip>
namespace emu {
inline std::string identityForSteamID(uint64_t steamID){
 if(!steamID)throw std::runtime_error("SteamID is unavailable");
 const std::string input="snowrunner-lan/steam-id/v1:"+std::to_string(steamID);
 BCRYPT_ALG_HANDLE algorithm=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;DWORD length=0,used=0;
 if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)throw std::runtime_error("SHA256 provider unavailable");
 BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&length),sizeof(length),&used,0);
 std::vector<unsigned char> object(length),digest(32);
 NTSTATUS result=BCryptCreateHash(algorithm,&hash,object.data(),length,nullptr,0,0);
 if(result>=0)result=BCryptHashData(hash,reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),static_cast<ULONG>(input.size()),0);
 if(result>=0)result=BCryptFinishHash(hash,digest.data(),static_cast<ULONG>(digest.size()),0);
 if(hash)BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(algorithm,0);
 if(result<0)throw std::runtime_error("Steam identity digest failed");
 digest[6]=static_cast<unsigned char>((digest[6]&15)|0x80); // UUIDv8: custom deterministic namespace.
 digest[8]=static_cast<unsigned char>((digest[8]&63)|0x80);
 std::ostringstream out;for(size_t i=0;i<16;++i){if(i==4||i==6||i==8||i==10)out<<'-';out<<std::hex<<std::setfill('0')<<std::setw(2)<<static_cast<unsigned>(digest[i]);}return out.str();
}
inline uint64_t currentSteamID(){
 HMODULE api=GetModuleHandleW(L"steam_api64.dll");if(!api)return 0;
 auto initialized=reinterpret_cast<int(*)()>(GetProcAddress(api,"SteamAPI_GetHSteamUser"));
 auto getID=reinterpret_cast<uint64_t(*)(void*)>(GetProcAddress(api,"SteamAPI_ISteamUser_GetSteamID"));
 if(!initialized||!initialized()||!getID)return 0;
 for(const char* name:{"SteamAPI_SteamUser_v023","SteamAPI_SteamUser_v022","SteamAPI_SteamUser_v021","SteamAPI_SteamUser_v020","SteamAPI_SteamUser_v019"}){
  auto getUser=reinterpret_cast<void*(*)()>(GetProcAddress(api,name));if(!getUser)continue;void* user=getUser();if(user)return getID(user);
 }
 return 0;
}
}
