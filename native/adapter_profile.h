#pragma once
#include <cstddef>
namespace emu::adapter {
// Proven by RoadCraft serializers. These offsets describe the public ABI,
// not the semantics or default values of newly introduced fields.
inline constexpr std::size_t accountStatusSize=0x58;
inline constexpr std::size_t sessionStatusSize=0xb8;
inline constexpr std::size_t sessionTailShift=8;
// Experimental local session path. Gameplay remains unvalidated.
inline constexpr bool enableExperimentalSessions=true;
inline constexpr const char* name="RoadCraft PROS ABI, development";
}
