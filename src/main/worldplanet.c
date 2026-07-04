#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/effect_interfaces.h"
#include "main/mapEvent.h"
#include "main/screen_transition.h"
#include "main/worldobj.h"
#include "main/worldplanet.h"
#include "main/pad.h"
#include "sfa_light_decls.h"
#include "main/audio/sfx_trigger_ids.h"

#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200
extern void objRenderFn_8003b8f4(double scale);
extern f32 lbl_803E6618;
extern int unlockLevel(s32 val, int idx, int flag);
int gWorldPlanetGameBitTable[WORLDPLANET_PLANET_COUNT] = {1019, 1018, 2659, 1020, 1017};
extern u8 gWorldPlanetHintFlagTable[8];
extern u8 gWorldPlanetDefaultSelectOrder[8];
extern int gWorldPlanetSavedSelection;
extern int gWorldPlanetSelectConfirmTimer;
extern u8 gWorldPlanetExitWarpTimer;
extern s16 gWorldPlanetInputLockTimer;
extern int gWorldPlanetLoadedMapId;
extern f32 gWorldPlanetPathProgress;
extern f32 lbl_803E65F8;
extern u16 getNextTaskHintText(void);
extern void setDrawLights(int v);
extern void audioStopByMask(int mask);
extern void Music_Trigger(int id, int arg);
extern int mapUnload(int mapId, int flags);

extern void envFxActFn_800887f8(u8 value);
extern int padGetStickX(int controller);
extern int padGetStickY(int controller);
extern int getLoadedFileFlags(int file);
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern void* Obj_SetupObject(int a, int b, int c, int d, int e);
extern void worldplanet_updateMapLighting(int obj);
extern void setFrameCountdown_800202c4(int frames);
extern int ObjList_FindObjectById(int id);

extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern void setIsOvercast(int v);
extern void pauseMenuSetupTitle(int strId, int p2, int p3, int p4);
extern f32 lbl_803DDD00;
extern s16 gWorldPlanetReselectDelayTimer;
extern int lbl_803DDD10;
extern int gWorldPlanetObjectIdTable[3][5];
extern u8 gWorldPlanetSelectionToIndex[8];
extern u8 gWorldPlanetTitleStringIds[8];
extern u8 gWorldPlanetKrazoaControlBytes[8];
extern u8 gWorldPlanetLoadMapIndices[6];
extern u8 gWorldPlanetWarpMapIndices[6];
extern int getAngle(float y, float x);
extern int loadMapAndParent(int mapId);
extern int lockLevel(s32 val, int idx);

extern void streamFn_8000a380(int a, int b, int c);
extern void warpToMap(int idx, s8 transType);
extern float fsin16Approx(int angle);
extern float fcos16Approx(int angle);
extern f32 gWorldPlanetPfxOffsetX;
extern f32 gWorldPlanetPfxOffsetY;
extern f32 gWorldPlanetPfxOffsetZ;
extern f32 gWorldPlanetPathProgressStep;
extern f32 gWorldPlanetPathProgressMax;
extern f32 gWorldPlanetOrbitRadius;

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

void worldplanet_render(u32 obj, u32 p2, u32 p3,
                        u32 p4, u32 p5, char visible)
{
    int draw;

    draw = visible;
    if (draw != 0)
    {
        objRenderFn_8003b8f4((double)lbl_803E6618);
    }
    return;
}

void worldplanet_hitDetect(void)
{
    return;
}

void worldplanet_release(void)
{
}

void worldplanet_initialise(void)
{
}

void worldplanet_init(int obj)
{
    WorldPlanetState* state;
    int i;
    int mask;
    int layer;
    int j;
    int flag;

    state = ((GameObject*)obj)->extra;
    gWorldPlanetSelectConfirmTimer = 0;
    GameBit_Set(WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN, 1);
    mask = 0;
    for (i = 0; i < WORLDPLANET_PLANET_COUNT; i++) {
        if (GameBit_Get(gWorldPlanetGameBitTable[i]) != 0) {
            flag = 1;
            if (gWorldPlanetHintFlagTable[i] != 0) {
                if ((s32)getNextTaskHintText() > WORLDPLANET_HINT_UNLOCK_THRESHOLD) {
                    flag = 0;
                }
            }
            if ((u8)flag != 0)
            {
                mask |= 1 << i;
            }
        }
    }
    state->unlockedPlanetMask = mask;
    if (gWorldPlanetSavedSelection != -1)
    {
        state->selectedPlanet = gWorldPlanetSavedSelection;
    } else {
        for (j = 0; j < WORLDPLANET_PLANET_COUNT; j++) {
            if (GameBit_Get(gWorldPlanetGameBitTable[gWorldPlanetDefaultSelectOrder[j]]) != 0) {
                state->selectedPlanet = gWorldPlanetDefaultSelectOrder[j];
                break;
            }
        }
    }
    gWorldPlanetExitWarpTimer = 0;
    setDrawLights(0);
    audioStopByMask(0xf);
    Music_Trigger(WORLDPLANET_BOOT_MUSIC_TRIGGER, 1);
    gWorldPlanetPathProgress = lbl_803E65F8;
    setShowWorldMapHud(1);
    gWorldPlanetLoadedMapId = -1;
    unlockLevel(0, 0, 1);
    mapUnload(WORLDPLANET_MAIN_MAP_ID, WORLDPLANET_MAP_PRELOAD_FLAG);
    layer = getCurMapLayer();
    (*gMapEventInterface)->savePoint((int)&((GameObject*)obj)->anim.localPosX, 0, 0, layer);
    (*gScreenTransitionInterface)->step(0x1e, 1);
    gWorldPlanetInputLockTimer = WORLDPLANET_COUNTDOWN_FRAMES;
    GameBit_Set(gWorldPlanetGameBitTable[2], 1);
    state->foxSpawnTimer = WORLDPLANET_FOX_SPAWN_INITIAL_FRAMES;
    envFxActFn_800887f8(0);
}

#pragma peephole on
void worldplanet_readMapInput(int obj, u8* outX, u8* outY)
{
    WorldPlanetState* state = ((GameObject*)obj)->extra;
    int stickX;
    int stickY;
    s8 resX;
    s8 resY;

    stickX = padGetStickX(0);
    stickY = padGetStickY(0);
    resX = 0;
    resY = 0;
    if (getLoadedFileFlags(WORLDPLANET_SAVE_FILE_SLOT) == 0) {
        if ((s8)stickX < -WORLDPLANET_INPUT_STICK_THRESHOLD &&
            state->prevStickX >= -WORLDPLANET_INPUT_STICK_THRESHOLD) {
            resX = -1;
            state->stickXRepeatFrames = 0;
        }
        if ((s8)stickX > WORLDPLANET_INPUT_STICK_THRESHOLD &&
            state->prevStickX <= WORLDPLANET_INPUT_STICK_THRESHOLD) {
            resX = 1;
            state->stickXRepeatFrames = 0;
        }
        if ((s8)stickY < -WORLDPLANET_INPUT_STICK_THRESHOLD &&
            state->prevStickY >= -WORLDPLANET_INPUT_STICK_THRESHOLD) {
            resY = -1;
            state->stickYRepeatFrames = 0;
        }
        if ((s8)stickY > WORLDPLANET_INPUT_STICK_THRESHOLD &&
            state->prevStickY <= WORLDPLANET_INPUT_STICK_THRESHOLD) {
            resY = 1;
            state->stickYRepeatFrames = 0;
        }
        state->prevStickY = stickY;
        if (state->prevStickY < -WORLDPLANET_INPUT_STICK_THRESHOLD) {
            state->stickYRepeatFrames++;
        } else if (state->prevStickY > WORLDPLANET_INPUT_STICK_THRESHOLD) {
            state->stickYRepeatFrames++;
        }
        else
        {
            state->stickYRepeatFrames = 0;
        }
        if (state->stickYRepeatFrames > WORLDPLANET_INPUT_REPEAT_FRAMES) {
            state->prevStickY = 0;
            state->stickYRepeatFrames = 0;
        }
        state->prevStickX = stickX;
        if (state->prevStickX < -WORLDPLANET_INPUT_STICK_THRESHOLD) {
            state->stickXRepeatFrames++;
        } else if (state->prevStickX > WORLDPLANET_INPUT_STICK_THRESHOLD) {
            state->stickXRepeatFrames++;
        }
        else
        {
            state->stickXRepeatFrames = 0;
        }
        if (state->stickXRepeatFrames > WORLDPLANET_INPUT_REPEAT_FRAMES) {
            state->prevStickX = 0;
            state->stickXRepeatFrames = 0;
        }
        *(s8*)outX = resX;
        *(s8*)outY = resY;
    }
    else
    {
        *outX = 0;
        *outY = 0;
    }
}
#pragma peephole reset

void worldplanet_update(int obj)
{
    u8 prevPlanet;
    int galleon;
    int buttons;
    int (*tbl)[5];
    WorldPlanetState* state;
    u8 done;
    u8 i;
    u8 b;
    int objId;
    WorldObjEffectParams pfx;
    struct
    {
        u8 inY;
        u8 inX[3];
    } in;

    tbl = gWorldPlanetObjectIdTable;
    state = ((GameObject*)obj)->extra;
    done = 0;
    state->foxSpawnTimer -= 1;
    if (state->foxSpawnTimer == 1)
    {
        int def;
        state->foxSpawnTimer = randomGetRange(WORLDPLANET_FOX_SPAWN_MIN_FRAMES, 3000);
        def = *(int*)&((GameObject*)obj)->anim.placementData;
        if (Obj_IsLoadingLocked() != 0)
        {
            WorldObjSetup* setup = (WorldObjSetup*)Obj_AllocObjectSetup(0x20, WORLDPLANET_FOX_SPAWN_OBJECT_ID);
            *(u8*)((char*)setup + 4) = *(u8*)(def + 4);
            *(u8*)((char*)setup + 6) = *(u8*)(def + 6);
            *(u8*)((char*)setup + 5) = *(u8*)(def + 5);
            *(u8*)((char*)setup + 7) = *(u8*)(def + 7);
            ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
            ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
            ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
            Obj_SetupObject((int)setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
        }
    }
    if (state->foxSpawnTimer < 0)
    {
        state->foxSpawnTimer = 0;
    }
    worldplanet_updateMapLighting(obj);
    if (gWorldPlanetInputLockTimer != 0)
    {
        gWorldPlanetInputLockTimer -= 1;
    }
    if (gWorldPlanetExitWarpTimer != 0)
    {
        gWorldPlanetExitWarpTimer -= 1;
        if (gWorldPlanetExitWarpTimer == 0)
        {
            setIsOvercast(1);
            setDrawCloudsAndLights(1);
            setDrawLights(1);
            warpToMap(gWorldPlanetWarpMapIndices[gWorldPlanetSelectionToIndex[state->selectedPlanet]], 0);
        }
    }
    else
    {
        setFrameCountdown_800202c4(1);
        if ((state->flags & WORLDPLANET_STATE_FLAG_CAMERA_SET) == 0)
        {
            (*gCameraInterface)->setMode(0x4e, 1, 0, 0, NULL, 0, 0xff);
            (*gCameraInterface)->setFocus((void*)obj, 0);
            state->flags |= WORLDPLANET_STATE_FLAG_CAMERA_SET;
        }
        else if ((state->flags & WORLDPLANET_STATE_FLAG_INITIAL_ACTION_RELEASED) == 0)
        {
            objId = tbl[0][gWorldPlanetSelectionToIndex[state->selectedPlanet]];
            (*gCameraInterface)->releaseAction(&objId, 2);
            state->flags |= WORLDPLANET_STATE_FLAG_INITIAL_ACTION_RELEASED;
            {
                int krazoa = ObjList_FindObjectById(WORLDPLANET_KRAZOA_OBJECT_ID);
                ((WorldObjState*)((GameObject*)krazoa)->extra)->controlByte = gWorldPlanetKrazoaControlBytes[state->selectedPlanet];
            }
            AudioStream_StopCurrent();
        }
        if ((state->flags & WORLDPLANET_STATE_FLAG_ENVFX_STARTED) == 0)
        {
            state->flags |= WORLDPLANET_STATE_FLAG_ENVFX_STARTED;
            getEnvfxAct(0, 0, WORLDPLANET_ENVFX_OPEN_ID, 0);
            setIsOvercast(0);
            setDrawLights(0);
        }
        buttons = getButtonsJustPressed(0);
        pfx.dispatchTimer = 100;
        pfx.offsetX = gWorldPlanetPfxOffsetX;
        pfx.offsetY = gWorldPlanetPfxOffsetY;
        pfx.offsetZ = gWorldPlanetPfxOffsetZ;
        (*gPartfxInterface)->spawnObject((void*)obj, WORLDPLANET_SELECTION_PFX_ID, &pfx, 2, -1, NULL);
        worldplanet_readMapInput(obj, (u8*)in.inX, &in.inY);
        ((GameObject*)obj)->anim.rotZ -= 10;
        ((GameObject*)obj)->anim.rotY = 0x3448;
        ((GameObject*)obj)->anim.rotX = 0x4000;
        {
            int fox = ObjList_FindObjectById(WORLDPLANET_FOX_OBJECT_ID);
            ((GameObject*)fox)->anim.rotZ = ((GameObject*)obj)->anim.rotZ;
            ((GameObject*)fox)->anim.rotY = ((GameObject*)obj)->anim.rotY;
            ((GameObject*)fox)->anim.rotX = ((GameObject*)obj)->anim.rotX;
        }
        galleon = ObjList_FindObjectById(WORLDPLANET_GALLEON_OBJECT_ID);
        ((WorldObjState*)((GameObject*)galleon)->extra)->effectState = state->selectionLocked;
        prevPlanet = state->selectedPlanet;
        {
            u8 ok;
            u32 m = 0;
            int k = m;
            int* ids = tbl[3];
            u8* hints = gWorldPlanetHintFlagTable;
            do
            {
                if (GameBit_Get(*ids) != 0)
                {
                    ok = 1;
                    if (*hints != 0 && (s32)getNextTaskHintText() > 0xad)
                    {
                        ok = 0;
                    }
                    if (ok)
                    {
                        m |= 1 << k;
                    }
                }
                ids += 1;
                hints += 1;
                k += 1;
            }
            while (k < 5);
            state->unlockedPlanetMask = m;
        }
        if (gWorldPlanetSelectConfirmTimer == 0 && (u8)state->selectionLocked == 0)
        {
            while (!done)
            {
                state->selectedPlanet = state->selectedPlanet + in.inX[0];
                if (state->selectedPlanet < 0)
                {
                    state->selectedPlanet = 4;
                }
                else if (state->selectedPlanet >= 5)
                {
                    state->selectedPlanet = 0;
                }
                done = 1;
            }
            pauseMenuSetupTitle(WORLDPLANET_SELECT_TITLE_TEXT_ID, gWorldPlanetTitleStringIds[state->selectedPlanet], 0x19, 0);
            if (prevPlanet != state->selectedPlanet || ((GameObject*)obj)->unkF4 == 0)
            {
                if (((GameObject*)obj)->unkF4 != 0)
                {
                    objId = tbl[0][gWorldPlanetSelectionToIndex[state->selectedPlanet]];
                    (*gCameraInterface)->releaseAction(&objId, 1);
                    Sfx_PlayFromObject(0, SFXTRIG_crf_babyambi3);
                }
                gWorldPlanetPathProgress = lbl_803E65F8;
                {
                    int p = ObjList_FindObjectById(tbl[0][gWorldPlanetSelectionToIndex[prevPlanet]]);
                    ((WorldObjState*)((GameObject*)p)->extra)->effectState = 0;
                    p = ObjList_FindObjectById(tbl[0][gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
                    ((WorldObjState*)((GameObject*)p)->extra)->effectState = 1;
                }
                ((GameObject*)obj)->unkF4 = 1;
            }
        }
        gWorldPlanetPathProgress = gWorldPlanetPathProgress + gWorldPlanetPathProgressStep;
        if (gWorldPlanetPathProgress >= gWorldPlanetPathProgressMax)
        {
            gWorldPlanetPathProgress = lbl_803E65F8;
        }
        for (i = 0; i < WORLDPLANET_PLANET_COUNT; i++)
        {
            int planet = ObjList_FindObjectById(tbl[2][i]);
            WorldObjState* pstate = ((GameObject*)planet)->extra;
            ((GameObject*)planet)->anim.rotY = ((GameObject*)obj)->anim.rotY;
            ((GameObject*)planet)->anim.rotX = ((GameObject*)obj)->anim.rotX;
            if ((u8)state->selectionLocked != 0 || (((int)(u32)state->unlockedPlanetMask >> i) & 1) == 0)
            {
                pstate->effectState = 0;
                if ((int)i == state->selectedPlanet)
                {
                    ((GameObject*)galleon)->anim.flags = ((GameObject*)galleon)->anim.flags | OBJANIM_FLAG_HIDDEN;
                }
            }
            else
            {
                if ((int)i == state->selectedPlanet)
                {
                    u32 fi = (int)gWorldPlanetPathProgress & 0xff;
                    u32 ni = (fi + 2) & 0xff;
                    f32 frac = gWorldPlanetPathProgress - fi;
                    char* seg = WorldObj_GetPathPointWork(pstate, fi);
                    f32 x0 = *(f32*)(seg + 0x10);
                    f32 x1 = *(f32*)(seg + 0x28);
                    f32 y0 = *(f32*)(seg + 0x14);
                    f32 y1 = *(f32*)(seg + 0x2c);
                    f32 z0 = *(f32*)(seg + 0x18);
                    f32 z1 = *(f32*)(seg + 0x30);
                    s16 yaw;
                    s16 dyaw;
                    pstate->effectState = 2;
                    yaw = getAngle(x1 - x0, z1 - z0);
                    if (ni >= 0x16)
                    {
                        dyaw = yaw;
                    }
                    else
                    {
                        char* nseg = WorldObj_GetPathPointWork(pstate, ni);
                        dyaw = getAngle(*(f32*)(nseg + 0x10) - x1, *(f32*)(nseg + 0x18) - z1);
                    }
                    dyaw = dyaw - (u16)yaw;
                    if (dyaw > 0x8000)
                    {
                        dyaw = (s16)(dyaw - 0xffff);
                    }
                    if (dyaw < -0x8000)
                    {
                        dyaw = (s16)(dyaw + 0xffff);
                    }
                    if (fn_8012DDAC() != 0)
                    {
                        ((GameObject*)galleon)->anim.flags = ((GameObject*)galleon)->anim.flags | OBJANIM_FLAG_HIDDEN;
                    }
                    else
                    {
                        ((GameObject*)galleon)->anim.flags = ((GameObject*)galleon)->anim.flags & ~OBJANIM_FLAG_HIDDEN;
                    }
                    *(s16*)&((GameObject*)galleon)->anim.rotX = (frac * dyaw + yaw);
                    ((GameObject*)galleon)->anim.localPosX = frac * (x1 - x0) + x0;
                    ((GameObject*)galleon)->anim.localPosY = frac * (y1 - y0) + y0;
                    ((GameObject*)galleon)->anim.localPosZ = frac * (z1 - z0) + z0;
                }
                else
                {
                    pstate->effectState = 1;
                }
            }
        }
        objId = ObjList_FindObjectById(tbl[0][gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
        if (getLoadedFileFlags(0) == 0 && gWorldPlanetInputLockTimer == 0)
        {
            switch ((u8)state->selectionLocked)
            {
            case 0:
                if (gWorldPlanetReselectDelayTimer != 0)
                {
                    gWorldPlanetReselectDelayTimer -= 1;
                }
                else
                {
                    if (gWorldPlanetSelectConfirmTimer == 0 &&
                        (state->unlockedPlanetMask & (1 << state->selectedPlanet)) != 0 &&
                        (buttons & PAD_BUTTON_A) != 0)
                    {
                        gWorldPlanetSelectConfirmTimer = 10;
                        mapUnload(gWorldPlanetLoadedMapId, WORLDPLANET_MAP_SELECTED_FLAG);
                    }
                }
                if (gWorldPlanetSelectConfirmTimer != 0)
                {
                    Pause_ResetMenuFrameCounter();
                    gWorldPlanetSelectConfirmTimer -= 1;
                    if (gWorldPlanetSelectConfirmTimer <= 1)
                    {
                        gWorldPlanetSelectConfirmTimer = 0;
                        Sfx_PlayFromObject(0, SFXTRIG_wmap_swoosh);
                        (*gCameraInterface)->setFocus((void*)objId, 0x50);
                        state->selectionLocked = 1;
                        (*gCameraInterface)->releaseAction(&state->selectionLocked, 0);
                        {
                            int krazoa = ObjList_FindObjectById(WORLDPLANET_KRAZOA_OBJECT_ID);
                            ((WorldObjState*)((GameObject*)krazoa)->extra)->controlByte = gWorldPlanetKrazoaControlBytes[state->
                                selectedPlanet];
                        }
                        gWorldPlanetLoadedMapId = loadMapAndParent(gWorldPlanetLoadMapIndices[gWorldPlanetSelectionToIndex[state->selectedPlanet]]);
                        lockLevel(gWorldPlanetLoadedMapId, 1);
                        loadModelAndAnimTabs();
                        lbl_803DDD00 = lbl_803E65F8;
                        gWorldPlanetSavedSelection = state->selectedPlanet;
                    }
                }
                break;
            case 1:
                Pause_ResetMenuFrameCounter();
                {
                    int neq = lbl_803DDD00 != lbl_803E65F8;
                    neq = !neq;
                    if (neq)
                    {
                        lbl_803DDD00 = lbl_803E6618;
                    }
                }
                if ((buttons & PAD_BUTTON_B) != 0)
                {
                    AudioStream_StopCurrent();
                    Sfx_PlayFromObject(0, SFXTRIG_wmap_greatfox_lp);
                    streamFn_8000a380(2, 2, 1000);
                    (*gCameraInterface)->setFocus((void*)obj, 0x50);
                    state->selectionLocked = 0;
                    gWorldPlanetReselectDelayTimer = 0x1e;
                    (*gCameraInterface)->releaseAction(&state->selectionLocked, 0);
                    unlockLevel(gWorldPlanetLoadedMapId, 1, 0);
                    mapUnload(gWorldPlanetLoadedMapId, WORLDPLANET_MAP_SELECTED_FLAG);
                    gWorldPlanetInputLockTimer = 10;
                }
                else if ((buttons & PAD_BUTTON_A) != 0)
                {
                    (*gScreenTransitionInterface)->start(4, 1);
                    streamFn_8000a380(3, 1, 0);
                    AudioStream_StopCurrent();
                    Sfx_PlayFromObject(0, SFXTRIG_wmap_swoosh);
                    setShowWorldMapHud(0);
                    gWorldPlanetExitWarpTimer = 5;
                    lbl_803DDD10 = 0;
                    mapUnload(gWorldPlanetLoadedMapId, WORLDPLANET_MAP_PRELOAD_FLAG);
                }
                break;
            }
        }
        else
        {
            Pause_ResetMenuFrameCounter();
        }
        {
            u32 ang = -((GameObject*)obj)->anim.rotZ & 0xffff;
            f32 r;
            for (b = 0; b < WORLDPLANET_PLANET_COUNT; b++)
            {
                int p = ObjList_FindObjectById(tbl[2][b]);
                ((GameObject*)p)->anim.rotZ = -ang;
            }
            for (b = 0, r = gWorldPlanetOrbitRadius; b < WORLDPLANET_PLANET_COUNT; b++)
            {
                s16* p = (s16*)ObjList_FindObjectById(tbl[0][b]);
                if (tbl[0][b] == WORLDPLANET_SPECIAL_ORBIT_OBJECT_ID)
                {
                    *p = ang + tbl[1][b] + 0x4000;
                }
                else
                {
                    *p += 0x3c;
                }
                if (state->orbitSoundFrameCount > 2)
                {
                    Sfx_KeepAliveLoopedObjectSound((u32)p, SFXTRIG_crf_babyambi2);
                }
                *(f32*)(p + 6) = r * fsin16Approx((ang + tbl[1][b]) & 0xffff) * fcos16Approx(3000) + ((GameObject*)obj)->anim
                    .localPosX;
                *(f32*)(p + 8) = r * fsin16Approx((ang + tbl[1][b]) & 0xffff) * fsin16Approx(3000) + ((GameObject*)obj)->anim
                    .localPosY;
                *(f32*)(p + 10) = r * fcos16Approx((ang + tbl[1][b]) & 0xffff) + ((GameObject*)obj)->anim.localPosZ;
            }
        }
        state->orbitSoundFrameCount += 1;
    }
}

int gWorldPlanetObjectIdTable[3][5] = {
    { 0x00042FEA, 0x00042FE8, 0x0004300D, 0x00042FE9, 0x00042FEB },
    { 0x00000000, 0x00004000, 0x00005FA0, 0x00008000, 0x0000C000 },
    { 0x00043099, 0x00042FFF, 0x0004309A, 0x00043098, 0x00043097 },
};
