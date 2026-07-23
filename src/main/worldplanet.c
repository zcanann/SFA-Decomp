#include "main/dll/partfx_interface.h"
#include "main/audio/sfx.h"
#include "main/audio/music_api.h"
#include "main/render_envfx_api.h"
#include "main/camera_interface.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/object_render.h"
#include "main/object_api.h"

#include "main/object.h"
#include "main/mapEvent.h"
#include "main/screen_transition.h"
#include "main/worldobj.h"
#include "main/worldplanet.h"
#include "main/worldplanet_lighting.h"
#include "main/pad.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/stream_api.h"
#include "main/lightmap_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/model.h"
#include "main/loaded_file_flags.h"
#include "main/map_load.h"
#include "main/rcp_dolphin.h"
#include "main/shader_api.h"
#include "main/sky_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/hint_text_api.h"
#include "main/pause_menu_api.h"

u8 gWorldPlanetHintFlagTable[8] = {1, 1, 0, 1, 1, 0, 0, 0};
u8 gWorldPlanetDefaultSelectOrder[8] = {2, 4, 1, 0, 3, 0, 0, 0};
u8 gWorldPlanetSelectionToIndex[8] = {0, 1, 2, 3, 4, 0, 0, 0};
u8 gWorldPlanetTitleStringIds[8] = {0, 1, 2, 3, 4, 0, 0, 0};
u8 gWorldPlanetWarpMapIndices[6] = {0x76, 0x6E, 0x6F, 0x75, 0x74, 0};
u8 gWorldPlanetLoadMapIndices[6] = {0x3D, 0x3C, 0x3A, 0x3E, 0x3B, 0};
u8 gWorldPlanetBriefingSpeakerModel[8] = {2, 2, 1, 0, 0, 0, 0, 0};
int gWorldPlanetSavedSelection = -1;
WorldPlanetColorRGBA8 gWorldPlanetLightFrom = {0x21, 0x35, 0x3F, 0};
WorldPlanetColorRGBA8 gWorldPlanetLightTo = {9, 0x0F, 0x1E, 0};
WorldPlanetColorRGBA8 gWorldPlanetSkyColorFrom = {0xFF, 0xE1, 0x87, 0};
WorldPlanetColorRGBA8 gWorldPlanetSkyColorTo = {0xC8, 0xE7, 0xFF, 0};
WorldPlanetColorRGBA8 gWorldPlanetAmbientFrom = {0x74, 0xA2, 0x85, 0};
WorldPlanetPaddedColorRGBA8 gWorldPlanetAmbientTo = {0x13, 0x23, 0x36, 0, {0, 0, 0, 0}};

/* Per-WorldPlanetSlot parameter table. Columns are WorldPlanetSlot 0..4
 * (Walled City / CloudRunner / Dinosaur / Dragon Rock / DarkIce).
 *   orbitObjectIds: the orbiting island objects. Each frame they are placed on the orbit
 *          ring (localPos from orbit radius + the row-1 angle) and spun; they are
 *          also the camera's focus/action target on select & confirm and carry
 *          the binary selection highlight (WorldObjState.effectState 0/1). Slot
 *          2's entry is WORLDPLANET_SPECIAL_ORBIT_OBJECT_ID (special-cased in the
 *          orbit placement).
 *   orbitAngleOffsets: 0/0x4000/0x5FA0/0x8000/0xC000
 *          (0/90/~135/180/270 deg) spacing the islands evenly around the ring.
 *   flightPathObjectIds: per-slot objects that rotate with the map and each hold the flight
 *          PATH for one destination. When a planet is selected the small ferry
 *          Arwing (WORLDPLANET_ARWING_OBJECT_ID) is interpolated along the
 *          selected slot's path each frame; effectState
 *          = locked(0) / available(1) / selected(2). Verified live that all five
 *          routes exist - the Arwing is just unlock-gated (the effectState-0 branch
 *          hides it), so in normal play only the reachable planet's is ever seen. */
WorldPlanetObjectTables gWorldPlanetObjectIdTable = {
    {0x00042FEA, 0x00042FE8, 0x0004300D, 0x00042FE9, 0x00042FEB},
    {0x00000000, 0x00004000, 0x00005FA0, 0x00008000, 0x0000C000},
    {0x00043099, 0x00042FFF, 0x0004309A, 0x00043098, 0x00043097},
};

/* unlock gamebit per WorldPlanetSlot: [0] Walled City, [1] CloudRunner,
 * [2] Dinosaur Planet (== WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN, always set),
 * [3] Dragon Rock, [4] DarkIce Mines. */
int gWorldPlanetGameBitTable[WORLDPLANET_PLANET_COUNT] = {1019, 1018, 2659, 1020, 1017};

int worldplanet_getExtraSize(void)
{
    return sizeof(WorldPlanetState);
}

int worldplanet_getObjectTypeId(void)
{
    return 0;
}

void worldplanet_free(void)
{
    setShowWorldMapHud(0);
    return;
}

void worldplanet_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    int draw;

    draw = visible;
    if (draw != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
    return;
}

void worldplanet_hitDetect(void)
{
    return;
}

/* descriptor/ptr table auto 0x8032a1c8-0x8032a200 */
ObjectDescriptor gWorldPlanetObjDescriptor = {
    0x00000000,
    0x00000000,
    0x00000000,
    0x00090000,
    (ObjectDescriptorCallback)worldplanet_initialise,
    (ObjectDescriptorCallback)worldplanet_release,
    0x00000000,
    (ObjectDescriptorCallback)worldplanet_init,
    (ObjectDescriptorCallback)worldplanet_update,
    (ObjectDescriptorCallback)worldplanet_hitDetect,
    (ObjectDescriptorCallback)worldplanet_render,
    (ObjectDescriptorCallback)worldplanet_free,
    (ObjectDescriptorCallback)worldplanet_getObjectTypeId,
    worldplanet_getExtraSize,
};
