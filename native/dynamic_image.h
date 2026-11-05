#pragma once
#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace emu { namespace dynamic {
inline bool readable(uintptr_t address,size_t size){
 if(!address||size>std::numeric_limits<uintptr_t>::max()-address)return false;
 auto end=address+size;
 while(address<end){MEMORY_BASIC_INFORMATION info{};
  if(!VirtualQuery(reinterpret_cast<void*>(address),&info,sizeof(info))||info.State!=MEM_COMMIT||(info.Protect&(PAGE_GUARD|PAGE_NOACCESS)))return false;
  auto protection=info.Protect&0xff;
  if(protection!=PAGE_READONLY&&protection!=PAGE_READWRITE&&protection!=PAGE_WRITECOPY&&protection!=PAGE_EXECUTE_READ&&protection!=PAGE_EXECUTE_READWRITE&&protection!=PAGE_EXECUTE_WRITECOPY)return false;
  auto next=reinterpret_cast<uintptr_t>(info.BaseAddress)+info.RegionSize;if(next<=address)return false;address=std::min(end,next);
 }return true;
}
struct Region{uintptr_t start;size_t size;};
inline std::vector<Region> sections(uintptr_t image,bool executable){
 std::vector<Region> result;
 if(!readable(image,sizeof(IMAGE_DOS_HEADER)))return result;
 auto dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(image);if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<0||dos->e_lfanew>1024*1024)return result;
 auto ntAddress=image+static_cast<unsigned>(dos->e_lfanew);
 if(!readable(ntAddress,sizeof(IMAGE_NT_HEADERS64)))return result;
 auto nt=reinterpret_cast<const IMAGE_NT_HEADERS64*>(ntAddress);
 if(nt->Signature!=IMAGE_NT_SIGNATURE||nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64||nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC||nt->FileHeader.NumberOfSections>96)return result;
 auto imageSize=nt->OptionalHeader.SizeOfImage;if(!imageSize||imageSize>1024u*1024*1024||imageSize>std::numeric_limits<uintptr_t>::max()-image)return result;
 auto table=ntAddress+offsetof(IMAGE_NT_HEADERS64,OptionalHeader)+nt->FileHeader.SizeOfOptionalHeader;
 auto count=nt->FileHeader.NumberOfSections;
 if(table<image||table-image>imageSize||size_t(count)*sizeof(IMAGE_SECTION_HEADER)>imageSize-(table-image)||!readable(table,size_t(count)*sizeof(IMAGE_SECTION_HEADER)))return result;
 auto headers=reinterpret_cast<const IMAGE_SECTION_HEADER*>(table);
 for(unsigned i=0;i<count;++i){auto& section=headers[i];
  if(!(section.Characteristics&IMAGE_SCN_MEM_READ)||bool(section.Characteristics&IMAGE_SCN_MEM_EXECUTE)!=executable)continue;
  size_t offset=section.VirtualAddress,size=std::max(section.Misc.VirtualSize,section.SizeOfRawData);
  if(offset>=imageSize)continue;size=std::min(size,size_t(imageSize)-offset);if(size)result.push_back({image+offset,size});
 }return result;
}
struct Pattern{std::vector<unsigned char> bytes,mask;};
inline Pattern parsePattern(const char* text){
 Pattern result;if(!text)return result;
 auto digit=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
 while(*text){while(*text==' ')++text;if(!*text)break;
  if(text[0]=='?'&&text[1]=='?'){result.bytes.push_back(0);result.mask.push_back(0);text+=2;}
  else{int a=digit(text[0]);if(a<0||!text[1])return {};int b=digit(text[1]);if(b<0)return {};result.bytes.push_back(static_cast<unsigned char>((a<<4)|b));result.mask.push_back(255);text+=2;}
  if(*text&&*text!=' ')return {};
 }return result;
}
inline void matches(const unsigned char* data,size_t size,const Pattern& pattern,std::vector<uintptr_t>& found){
 if(pattern.bytes.empty()||size<pattern.bytes.size())return;
 auto fixed=std::find(pattern.mask.begin(),pattern.mask.end(),255);if(fixed==pattern.mask.end())return;
 size_t anchor=static_cast<size_t>(fixed-pattern.mask.begin()),limit=size-pattern.bytes.size()+1,position=0;
 while(position<limit&&found.size()<2){
  auto hit=static_cast<const unsigned char*>(std::memchr(data+position+anchor,pattern.bytes[anchor],limit-position));if(!hit)break;
  position=static_cast<size_t>(hit-data)-anchor;bool equal=true;
  for(size_t i=0;i<pattern.bytes.size();++i)if(pattern.mask[i]&&data[position+i]!=pattern.bytes[i]){equal=false;break;}
  if(equal)found.push_back(reinterpret_cast<uintptr_t>(data+position));++position;
 }
}
inline uintptr_t uniquePattern(uintptr_t image,const Pattern& pattern,bool executable){
 if(pattern.bytes.empty())return 0;
 std::vector<uintptr_t> found;
 for(const auto& section:sections(image,executable)){
  uintptr_t cursor=section.start,end=section.start+section.size,runStart=0,runEnd=0;
  auto scanRun=[&]{if(runStart&&runEnd>runStart)matches(reinterpret_cast<const unsigned char*>(runStart),runEnd-runStart,pattern,found);runStart=runEnd=0;};
  while(cursor<end&&found.size()<2){MEMORY_BASIC_INFORMATION info{};if(!VirtualQuery(reinterpret_cast<void*>(cursor),&info,sizeof(info)))break;
   auto next=std::min(end,reinterpret_cast<uintptr_t>(info.BaseAddress)+info.RegionSize);if(next<=cursor)break;
   if(readable(cursor,next-cursor)){if(!runStart)runStart=cursor;runEnd=next;}else scanRun();cursor=next;
  }scanRun();if(found.size()>1)return 0;
 }return found.size()==1?found[0]:0;
}
inline uintptr_t uniqueCodePattern(uintptr_t image,const char* pattern){return uniquePattern(image,parsePattern(pattern),true);}
inline uintptr_t uniqueString(uintptr_t image,const char* value){
 Pattern pattern;size_t length=std::strlen(value)+1;pattern.bytes.assign(value,value+length);pattern.mask.assign(length,255);return uniquePattern(image,pattern,false);
}
inline bool stringEquals(const char* value,const std::string& expected){return readable(reinterpret_cast<uintptr_t>(value),expected.size()+1)&&!std::memcmp(value,expected.c_str(),expected.size()+1);}
// Captured public SDK ABI: each configuration property contains name/version pointers.
inline bool configurationMatches(void* properties,uint64_t count,const std::string& name,const std::string& version){
 if(count!=1||!readable(reinterpret_cast<uintptr_t>(properties),2*sizeof(const char*)))return false;
 auto strings=static_cast<const char* const*>(properties);return stringEquals(strings[0],name)&&(!strings[1]||stringEquals(strings[1],"")||stringEquals(strings[1],version));
}
}}
