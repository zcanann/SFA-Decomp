/*
 * dll_0238_linkalevco - "LinkA level control" sequence object (FireObject).
 *
 * A scripted level-progression controller placed in the LinkA map. It runs
 * trigger sequence 0 every update and reacts to that sequence's anim events
 * (fire_updateState), branching on the current map-event mode (getMapAct of
 * its mapEventMapId):
 *   - OPEN_PATH:  defrag memory, enable object groups, unlock Lightfoot and
 *                 load/lock the destination map for the active mode.
 *   - WARP:       warp to the mode's destination map (mode 2 picks one of
 *                 three routes from game bits) and load the UI DLL.
 *   - UNLOAD_NEIGHBOR_MAP: unload the adjacent map for the active mode.
 * init unlocks the starting level, flags the object as a sequence object,
 * sets three progression game bits, kicks an env-fx act and streams a
 * collectable. A looping object sound is kept alive while sequences run.
 */
#include "main/dll/dll_0238_linkalevco.h"
#include "main/gameplay_runtime.h"
#include "main/objseq.h"

extern f32 lbl_803E64D8;

#define LINKA_LEVCONTROL_LOOP_SFX_ID 0x48B

/* getMapAct mode is a small progression index 0..3 with no semantic label. */

#define LINKA_LEVCONTROL_ANIM_EVENT_OPEN_PATH 1
#define LINKA_LEVCONTROL_ANIM_EVENT_WARP 2
#define LINKA_LEVCONTROL_ANIM_EVENT_UNLOAD_NEIGHBOR_MAP 3

#define LINKA_LEVCONTROL_MAP_ID_7 7
#define LINKA_LEVCONTROL_MAP_ID_0B 0x0B
#define LINKA_LEVCONTROL_MAP_ID_17 0x17

#define LINKA_LEVCONTROL_WARP_ID_SHRINE 2
#define LINKA_LEVCONTROL_WARP_ID_MODE2_ROUTE_A 0x20
#define LINKA_LEVCONTROL_WARP_ID_MODE2_ROUTE_B 0x22
#define LINKA_LEVCONTROL_WARP_ID_MODE3 0x0F

#define LINKA_LEVCONTROL_MODE2_RESET_GAMEBIT 0x405
#define LINKA_LEVCONTROL_MODE2_ROUTE_A_GAMEBIT 0xBFD
#define LINKA_LEVCONTROL_MODE2_ROUTE_B_GAMEBIT 0x0FF
#define LINKA_LEVCONTROL_MODE2_ROUTE_C_GAMEBIT 0xC6E
#define LINKA_LEVCONTROL_LIGHTFOOT_UNLOCK_GAMEBIT 0x1ED

#define LINKA_LEVCONTROL_INIT_GAMEBIT_0 0x90D
#define LINKA_LEVCONTROL_INIT_GAMEBIT_1 0x90E
#define LINKA_LEVCONTROL_INIT_GAMEBIT_2 0x90F
#define LINKA_LEVCONTROL_INIT_COLLECTABLE_ID 0x2EE

/* per-instance extra block reserved by the object system; unused by this TU */
#define LINKA_LEVCONTROL_EXTRA_SIZE 4

int fire_updateState(FireObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int stateIndex;
    u8 mode;
    u8 eventId;
    int mapDir;

    mode = (u8)(*gMapEventInterface)->getMapAct((int)obj->mapEventMapId);
    Sfx_KeepAliveLoopedObjectSound(0, LINKA_LEVCONTROL_LOOP_SFX_ID);
    for (stateIndex = 0; stateIndex < animUpdate->eventCount; stateIndex++)
    {
        eventId = animUpdate->eventIds[stateIndex];
        if (eventId == LINKA_LEVCONTROL_ANIM_EVENT_OPEN_PATH)
        {
            defragMemory(0);
            switch (mode)
            {
            case 0:
            case 1:
                (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_ID_7, 0, 0);
                (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_ID_7, 2, 0);
                (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_ID_7, 3, 0);
                (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_ID_7, 7, 0);
                (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_ID_7, 10, 0);
                (*gMapEventInterface)->setObjGroupStatus(10, 7, 0);
                GameBit_Set(LINKA_LEVCONTROL_LIGHTFOOT_UNLOCK_GAMEBIT, 1);
                loadMapAndParent(LINKA_LEVCONTROL_MAP_ID_17);
                mapDir = mapGetDirIdx(LINKA_LEVCONTROL_MAP_ID_17);
                lockLevel(mapDir, 0);
                break;
            case 2:
                loadMapAndParent(LINKA_LEVCONTROL_MAP_ID_0B);
                mapDir = mapGetDirIdx(LINKA_LEVCONTROL_MAP_ID_0B);
                lockLevel(mapDir, 0);
                break;
            case 3:
                loadMapAndParent(LINKA_LEVCONTROL_MAP_ID_7);
                mapDir = mapGetDirIdx(LINKA_LEVCONTROL_MAP_ID_7);
                lockLevel(mapDir, 0);
                break;
            }
        }
        else if (eventId == LINKA_LEVCONTROL_ANIM_EVENT_WARP)
        {
            switch (mode)
            {
            case 0:
            case 1:
                warpToMap(LINKA_LEVCONTROL_WARP_ID_SHRINE, 0);
                break;
            case 2:
                GameBit_Set(LINKA_LEVCONTROL_MODE2_RESET_GAMEBIT, 0);
                if (GameBit_Get(LINKA_LEVCONTROL_MODE2_ROUTE_B_GAMEBIT) != 0)
                {
                    (*gMapEventInterface)->setMapAct(LINKA_LEVCONTROL_MAP_ID_0B, 3);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_ID_0B, 8, 1);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_ID_0B, 9, 1);
                    warpToMap(LINKA_LEVCONTROL_WARP_ID_MODE2_ROUTE_B, 0);
                }
                else if (GameBit_Get(LINKA_LEVCONTROL_MODE2_ROUTE_A_GAMEBIT) != 0)
                {
                    (*gMapEventInterface)->setMapAct(LINKA_LEVCONTROL_MAP_ID_0B, 2);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_ID_0B, 5, 1);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_ID_0B, 6, 1);
                    warpToMap(LINKA_LEVCONTROL_WARP_ID_MODE2_ROUTE_A, 0);
                }
                else if (GameBit_Get(LINKA_LEVCONTROL_MODE2_ROUTE_C_GAMEBIT) != 0)
                {
                    (*gMapEventInterface)->setMapAct(LINKA_LEVCONTROL_MAP_ID_0B, 4);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_ID_0B, 8, 1);
                    (*gMapEventInterface)->setObjGroupStatus(LINKA_LEVCONTROL_MAP_ID_0B, 9, 1);
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
            switch (mode)
            {
            case 0:
            case 1:
            case 2:
                mapDir = mapGetDirIdx(LINKA_LEVCONTROL_MAP_ID_7);
                mapUnload(mapDir, 0x20000000);
                break;
            case 3:
                mapDir = mapGetDirIdx(LINKA_LEVCONTROL_MAP_ID_0B);
                mapUnload(mapDir, 0x20000000);
                break;
            }
        }
    }
    return 0;
}

int fireObj_getExtraSize(void)
{
    return LINKA_LEVCONTROL_EXTRA_SIZE;
}

int fireObj_getObjectTypeId(void)
{
    return 0;
}

void fireObj_free(void)
{
}

void fireObj_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderModelAndHitVolumes(int, int, int, int, int, f32);
    objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E64D8);
}

void fireObj_hitDetect(void)
{
}

void fireObj_update(FireObject* obj)
{
    (*gObjectTriggerInterface)->runSequence(0, obj, 0xffffffff);
}

void fireObj_init(FireObject* obj)
{
    u32 flags;
    obj->animEventCallback = fire_updateState;
    unlockLevel(0, 0, 1);
    flags = obj->flags | LINKA_LEVCONTROL_SEQUENCE_OBJECT_FLAGS;
    obj->flags = flags;
    envFxActFn_800887f8(0);
    GameBit_Set(LINKA_LEVCONTROL_INIT_GAMEBIT_0, 1);
    GameBit_Set(LINKA_LEVCONTROL_INIT_GAMEBIT_1, 1);
    GameBit_Set(LINKA_LEVCONTROL_INIT_GAMEBIT_2, 1);
    streamFn_8000a380(3, 2, LINKA_LEVCONTROL_INIT_COLLECTABLE_ID);
}

void fireObj_release(void)
{
}

void fireObj_initialise(void)
{
}

ObjectDescriptor gFireObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    fireObj_initialise,
    fireObj_release,
    0,
    (ObjectDescriptorCallback)fireObj_init,
    (ObjectDescriptorCallback)fireObj_update,
    fireObj_hitDetect,
    (ObjectDescriptorCallback)fireObj_render,
    fireObj_free,
    (ObjectDescriptorCallback)fireObj_getObjectTypeId,
    fireObj_getExtraSize,
};
