/*
 * LinkA level-control sequence object (DLL 568). Sequence events prepare map
 * object groups, load and lock destination maps, select warp routes, and unload
 * neighboring maps. Map slots are converted to directory indices for locking
 * and unloading; warp IDs belong to a separate route table.
 */
#include "dlls/objects/568_LINKA_levco.h"

#include "main/audio/sfx_keep_alive_api.h"
#include "main/gamebit_ids.h"
#include "main/map_load.h"
#include "main/model_engine.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/sky_api.h"
#include "main/audio/music_api.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/mapEventTypes.h"

#define LINKA_LEVCONTROL_LOOP_SFX_ID 0x48B

/* Map acts 0..3 select the progression route. */

#define LINKA_LEVCONTROL_ANIM_EVENT_OPEN_PATH           1
#define LINKA_LEVCONTROL_ANIM_EVENT_WARP                2
#define LINKA_LEVCONTROL_ANIM_EVENT_UNLOAD_NEIGHBOR_MAP 3

#define LINKA_LEVCONTROL_MAP_SLOT_THORNTAIL  7
#define LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE 0x0B
#define LINKA_LEVCONTROL_MAP_SLOT_ICE_MOUNTAIN 0x17
#define LINKA_LEVCONTROL_MAP_SLOT_SNOWHORN 10

#define LINKA_LEVCONTROL_WARP_ID_MODE01        2
#define LINKA_LEVCONTROL_WARP_ID_MODE2_ROUTE_A 0x20
#define LINKA_LEVCONTROL_WARP_ID_MODE2_ROUTE_B 0x22
#define LINKA_LEVCONTROL_WARP_ID_MODE3         0x0F


#define LINKA_LEVCONTROL_MUSIC_FADE_TIME 0x2EE

/* per-instance extra block reserved by the object system; unused by this TU */
#define LINKA_LEVCONTROL_EXTRA_SIZE 4


int LinkALevControl_seqFn(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    int eventIndex;
    u8 mapAct;
    u8 eventId;
    int mapDirectory;

    mapAct = (u8)(*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);
    Sfx_KeepAliveLoopedObjectSound(0, LINKA_LEVCONTROL_LOOP_SFX_ID);
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++)
    {
        eventId = animUpdate->eventIds[eventIndex];
        if (eventId == LINKA_LEVCONTROL_ANIM_EVENT_OPEN_PATH)
        {
            defragMemory(0);
            switch (mapAct)
            {
            case 0:
            case 1:
                (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_THORNTAIL, 0, 0);
                (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_THORNTAIL, 2, 0);
                (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_THORNTAIL, 3, 0);
                (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_THORNTAIL, 7, 0);
                (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_THORNTAIL, 10, 0);
                (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_SNOWHORN, 7, 0);
                mainSetBits(GAMEBIT_IM_TrickyRelated01ED, 1);
                loadMapAndParent(LINKA_LEVCONTROL_MAP_SLOT_ICE_MOUNTAIN);
                mapDirectory = mapGetDirIdx(LINKA_LEVCONTROL_MAP_SLOT_ICE_MOUNTAIN);
                lockLevel(mapDirectory, 0);
                break;
            case 2:
                loadMapAndParent(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE);
                mapDirectory = mapGetDirIdx(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE);
                lockLevel(mapDirectory, 0);
                break;
            case 3:
                loadMapAndParent(LINKA_LEVCONTROL_MAP_SLOT_THORNTAIL);
                mapDirectory = mapGetDirIdx(LINKA_LEVCONTROL_MAP_SLOT_THORNTAIL);
                lockLevel(mapDirectory, 0);
                break;
            }
        }
        else if (eventId == LINKA_LEVCONTROL_ANIM_EVENT_WARP)
        {
            switch (mapAct)
            {
            case 0:
            case 1:
                warpToMap(LINKA_LEVCONTROL_WARP_ID_MODE01, 0);
                break;
            case 2:
                mainSetBits(GAMEBIT_WM_ObjGroups, 0);
                if (mainGetBit(GAMEBIT_ITEM_SpiritTestFear_Got) != 0)
                {
                    (*gMapEventInterface)->setMapAct(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE, 3);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE, 8, 1);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE, 9, 1);
                    warpToMap(LINKA_LEVCONTROL_WARP_ID_MODE2_ROUTE_B, 0);
                }
                else if (mainGetBit(GAMEBIT_ITEM_TestCombatSpirit_Got) != 0)
                {
                    (*gMapEventInterface)->setMapAct(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE, 2);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE, 5, 1);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE, 6, 1);
                    warpToMap(LINKA_LEVCONTROL_WARP_ID_MODE2_ROUTE_A, 0);
                }
                else if (mainGetBit(GAMEBIT_ITEM_SpiritTestStrength_Got) != 0)
                {
                    (*gMapEventInterface)->setMapAct(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE, 4);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE, 8, 1);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE, 9, 1);
                    warpToMap(LINKA_LEVCONTROL_WARP_ID_MODE2_ROUTE_B, 0);
                }
                break;
            case 3:
                warpToMap(LINKA_LEVCONTROL_WARP_ID_MODE3, 0);
                break;
            }
            loadUiDll(1);
        }
        else if (eventId == LINKA_LEVCONTROL_ANIM_EVENT_UNLOAD_NEIGHBOR_MAP)
        {
            switch (mapAct)
            {
            case 0:
            case 1:
            case 2:
                mapDirectory = mapGetDirIdx(LINKA_LEVCONTROL_MAP_SLOT_THORNTAIL);
                mapUnload(mapDirectory, 0x20000000);
                break;
            case 3:
                mapDirectory = mapGetDirIdx(LINKA_LEVCONTROL_MAP_SLOT_KRAZOA_PALACE);
                mapUnload(mapDirectory, 0x20000000);
                break;
            }
        }
    }
    return 0;
}

int LinkALevControl_getExtraSize(void)
{
    return LINKA_LEVCONTROL_EXTRA_SIZE;
}

int LinkALevControl_getObjectTypeId(void)
{
    return 0;
}

void LinkALevControl_free(void)
{
}

void LinkALevControl_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible)
{
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

void LinkALevControl_hitDetect(void)
{
}

void LinkALevControl_update(GameObject* obj)
{
    (*gObjectTriggerInterface)->runSequence(0, obj, 0xffffffff);
}

void LinkALevControl_init(GameObject* obj)
{
    u32 flags;
    obj->animEventCallback = LinkALevControl_seqFn;
    unlockLevel(0, 0, 1);
    flags = obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED;
    obj->objectFlags = flags;
    skySetEnvFxFlags(0);
    mainSetBits(GAMEBIT_SawMagic, 1);
    mainSetBits(GAMEBIT_SawBigHealth, 1);
    mainSetBits(GAMEBIT_SawApple, 1);
    Music_StopChannelsByPriorityGroup(3, MUSIC_CHANNEL_STOP_FADE, LINKA_LEVCONTROL_MUSIC_FADE_TIME);
}

void LinkALevControl_release(void)
{
}

void LinkALevControl_initialise(void)
{
}

ObjectDescriptor gLinkALevControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    LinkALevControl_initialise,
    LinkALevControl_release,
    0,
    (ObjectDescriptorCallback)LinkALevControl_init,
    (ObjectDescriptorCallback)LinkALevControl_update,
    LinkALevControl_hitDetect,
    (ObjectDescriptorCallback)LinkALevControl_render,
    LinkALevControl_free,
    (ObjectDescriptorCallback)LinkALevControl_getObjectTypeId,
    LinkALevControl_getExtraSize,
};
