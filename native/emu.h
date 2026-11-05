#pragma once
#include "adapter_profile.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include <atomic>
#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include "vendor/json.hpp"
#include "vendor/minhook/include/MinHook.h"
using Json=nlohmann::json;
namespace emu {
extern std::atomic<bool> stopping;
extern std::atomic<bool> identityReady;
bool ensureSteamIdentity();
extern HMODULE module, sdk;
extern uintptr_t game;
extern std::filesystem::path directory;
extern std::string identity, alias;
extern unsigned portOffset;
void log(const std::string& event,Json fields=Json::object());
void enqueue(std::function<void()> callback);
void drainTasks();
bool hook(const char* name,void* replacement,void** original=nullptr);
bool hookAddress(void* address,void* replacement,void** original=nullptr);
std::string uuid();
std::string randomHex(size_t bytes);
std::string preferredIP();
// Network service callbacks enqueue their game work rather than invoking native callbacks.
void startServices();
void stopServices();
Json httpRequest(const std::string& url,const std::string& operation,const Json& body);
std::vector<std::string> discover();
void startBridge(std::function<Json()> search,std::function<void(Json)> result);
void bridgeSubmit(const std::string& operation,Json body);
void stopBridge();
struct TurnConfig {std::string host,username,password;unsigned port=18633;};
extern TurnConfig turnConfig;
void startTurn();
void stopTurn();
void installRooms();void installParty();
Json roomSnapshot();
std::string presenceMetadata();
void cleanupCoordinator();
void installCore();
void acceptLocalSignals(const Json& result);
void installModDiagnostics();
void installGameModDiagnostics();
}
