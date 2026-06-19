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

extern void objRenderFn_8003b8f4(double scale);
extern void setShowWorldMapHud(int enabled);

extern f32 lbl_803E6618;
extern void unlockLevel(int a, int b, int c);
extern int lbl_8032A1B4[5];
extern u8 lbl_803DC1B8[8];
extern u8 lbl_803DC1C0[8];
extern int lbl_803DC1F0;
extern int lbl_803DDD04;
extern u8 lbl_803DDD08;
extern s16 lbl_803DDD0A;
extern int lbl_803DDD28;
extern f32 lbl_803DDD2C;
extern f32 lbl_803E65F8;
extern u16 getNextTaskHintText(void);
extern void setDrawLights(int mode);
extern void audioStopByMask(int mask);
extern void Music_Trigger(int track, int arg2);
extern void mapUnload(int mapId, int flags);
extern int getCurMapLayer(void);
extern void envFxActFn_800887f8(int arg);
extern int padGetStickX(int controller);
extern int padGetStickY(int controller);
extern int getLoadedFileFlags(int file);

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern void Obj_SetupObject(int setup, int a, int b, int c, int d);
extern void worldplanet_updateMapLighting(int obj);
extern void setFrameCountdown_800202c4(int frames);
extern int ObjList_FindObjectById(int id);
extern void AudioStream_StopCurrent(void);
extern void getEnvfxAct(int a, int b, int c, int d);
extern void setIsOvercast(int mode);
extern u32 getButtonsJustPressed(int controller);
extern void pauseMenuSetupTitle(int strId, int p2, int p3, int p4);
extern f32 lbl_803DDD00;
extern s16 lbl_803DDD0C;
extern int lbl_803DDD10;
extern int lbl_8032A178[];
extern u8 lbl_803DC1C8[8];
extern u8 lbl_803DC1D0[8];
extern u8 lbl_803DC1E8[8];
extern u8 lbl_803DC1E0[6];
extern u8 lbl_803DC1D8[6];
extern s16 getAngle(f32 a, f32 b);
extern u8 fn_8012DDAC(void);
extern int loadMapAndParent(int mapId);
extern void lockLevel(int idx, int p2);
extern void streamFn_8000a380(int a, int b, int c);
extern void warpToMap(int map, int p2);
extern f32 fsin16Approx(int angle);
extern f32 fcos16Approx(int angle);
extern f32 lbl_803E661C;
extern f32 lbl_803E6620;
extern f32 lbl_803E6624;
extern f32 lbl_803E6628;
extern f32 lbl_803E662C;
extern f32 lbl_803E6630;

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
    int mask;
    int i;
    int flag;
    int layer;
    int j;

    state = ((GameObject*)obj)->extra;
    lbl_803DDD04 = 0;
    GameBit_Set(WORLDPLANET_GAMEBIT_WORLD_MAP_OPEN, 1);
    mask = 0;
    for (i = 0; i < WORLDPLANET_PLANET_COUNT; i++) {
        if (GameBit_Get(lbl_8032A1B4[i]) != 0) {
            flag = 1;
            if (lbl_803DC1B8[i] != 0) {
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
    if (lbl_803DC1F0 != -1)
    {
        state->selectedPlanet = lbl_803DC1F0;
    } else {
        for (j = 0; j < WORLDPLANET_PLANET_COUNT; j++) {
            if (GameBit_Get(lbl_8032A1B4[lbl_803DC1C0[j]]) != 0) {
                state->selectedPlanet = lbl_803DC1C0[j];
                break;
            }
        }
    }
    lbl_803DDD08 = 0;
    setDrawLights(0);
    audioStopByMask(0xf);
    Music_Trigger(WORLDPLANET_BOOT_MUSIC_TRIGGER, 1);
    lbl_803DDD2C = lbl_803E65F8;
    setShowWorldMapHud(1);
    lbl_803DDD28 = -1;
    unlockLevel(0, 0, 1);
    mapUnload(WORLDPLANET_MAIN_MAP_ID, WORLDPLANET_MAP_PRELOAD_FLAG);
    layer = getCurMapLayer();
    (*gMapEventInterface)->savePoint((int)&((GameObject*)obj)->anim.localPosX, 0, 0, layer);
    (*gScreenTransitionInterface)->step(0x1e, 1);
    lbl_803DDD0A = WORLDPLANET_COUNTDOWN_FRAMES;
    GameBit_Set(lbl_8032A1B4[2], 1);
    state->foxSpawnTimer = WORLDPLANET_FOX_SPAWN_INITIAL_FRAMES;
    envFxActFn_800887f8(0);
}

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

void worldplanet_update(int obj)
{
    WorldPlanetState* state;
    int* tbl;
    u8 done;
    u8 prevPlanet;
    int buttons;
    u32 mask;
    u8 i;
    u8 b;
    int objId;
    int galleon;
    WorldObjEffectParams pfx;
    s8 inX[3];
    u8 inY;

    tbl = lbl_8032A178;
    state = ((GameObject*)obj)->extra;
    done = 0;
    state->foxSpawnTimer -= 1;
    if (state->foxSpawnTimer == 1)
    {
        int def;
        state->foxSpawnTimer = randomGetRange(0x708, 3000);
        def = *(int*)&((GameObject*)obj)->anim.placementData;
        if (Obj_IsLoadingLocked() != 0)
        {
            WorldObjSetup* setup = (WorldObjSetup*)Obj_AllocObjectSetup(0x20, 0x80f);
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
    if (lbl_803DDD0A != 0)
    {
        lbl_803DDD0A -= 1;
    }
    if (lbl_803DDD08 != 0)
    {
        lbl_803DDD08 -= 1;
        if (lbl_803DDD08 == 0)
        {
            setIsOvercast(1);
            setDrawCloudsAndLights(1);
            setDrawLights(1);
            warpToMap(lbl_803DC1D8[lbl_803DC1C8[state->selectedPlanet]], 0);
        }
    }
    else
    {
        setFrameCountdown_800202c4(1);
        if ((state->flags & 4) == 0)
        {
            (*gCameraInterface)->setMode(0x4e, 1, 0, 0, NULL, 0, 0xff);
            (*gCameraInterface)->setFocus((void*)obj, 0);
            state->flags |= 4;
        }
        else if ((state->flags & 8) == 0)
        {
            objId = tbl[lbl_803DC1C8[state->selectedPlanet]];
            (*gCameraInterface)->releaseAction(&objId, 2);
            state->flags |= 8;
            {
                int krazoa = ObjList_FindObjectById(0x43077);
                ((WorldObjState*)((GameObject*)krazoa)->extra)->controlByte = lbl_803DC1E8[state->selectedPlanet];
            }
            AudioStream_StopCurrent();
        }
        if ((state->flags & 1) == 0)
        {
            state->flags |= 1;
            getEnvfxAct(0, 0, 0x21f, 0);
            setIsOvercast(0);
            setDrawLights(0);
        }
        buttons = getButtonsJustPressed(0);
        pfx.dispatchTimer = 100;
        pfx.offsetX = lbl_803E661C;
        pfx.offsetY = lbl_803E6620;
        pfx.offsetZ = lbl_803E6624;
        (*gPartfxInterface)->spawnObject((void*)obj, 0x6f2, &pfx, 2, -1, NULL);
        worldplanet_readMapInput(obj, (u8*)inX, &inY);
        ((GameObject*)obj)->anim.rotZ -= 10;
        ((GameObject*)obj)->anim.rotY = 0x3448;
        ((GameObject*)obj)->anim.rotX = 0x4000;
        {
            int fox = ObjList_FindObjectById(0x42ff5);
            ((GameObject*)fox)->anim.rotZ = ((GameObject*)obj)->anim.rotZ;
            ((GameObject*)fox)->anim.rotY = ((GameObject*)obj)->anim.rotY;
            ((GameObject*)fox)->anim.rotX = ((GameObject*)obj)->anim.rotX;
        }
        galleon = ObjList_FindObjectById(0x4300c);
        ((WorldObjState*)((GameObject*)galleon)->extra)->effectState = state->selectionLocked;
        prevPlanet = *(u8*)&state->selectedPlanet;
        {
            u32 m = 0;
            int k = m;
            int* ids = &tbl[15];
            u8* hints = lbl_803DC1B8;
            do
            {
                if (GameBit_Get(*ids) != 0)
                {
                    u8 ok = 1;
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
        if (lbl_803DDD04 == 0 && state->selectionLocked == 0)
        {
            while (!done)
            {
                state->selectedPlanet = state->selectedPlanet + inX[0];
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
            pauseMenuSetupTitle(0x2a7, lbl_803DC1D0[state->selectedPlanet], 0x19, 0);
            if (prevPlanet != state->selectedPlanet || ((GameObject*)obj)->unkF4 == 0)
            {
                if (((GameObject*)obj)->unkF4 != 0)
                {
                    objId = tbl[lbl_803DC1C8[state->selectedPlanet]];
                    (*gCameraInterface)->releaseAction(&objId, 1);
                    Sfx_PlayFromObject(0, 0x97);
                }
                lbl_803DDD2C = lbl_803E65F8;
                {
                    int p = ObjList_FindObjectById(tbl[lbl_803DC1C8[prevPlanet]]);
                    ((WorldObjState*)((GameObject*)p)->extra)->effectState = 0;
                    p = ObjList_FindObjectById(tbl[lbl_803DC1C8[state->selectedPlanet]]);
                    ((WorldObjState*)((GameObject*)p)->extra)->effectState = 1;
                }
                ((GameObject*)obj)->unkF4 = 1;
            }
        }
        lbl_803DDD2C = lbl_803DDD2C + lbl_803E6628;
        if (lbl_803E662C <= lbl_803DDD2C)
        {
            lbl_803DDD2C = lbl_803E65F8;
        }
        for (i = 0; i < 5; i++)
        {
            int planet = ObjList_FindObjectById(((struct
            {
                int ids[10];
                int objs[5];
            }*)tbl)->objs[i]);
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
                    extern int getAngle(f32, f32);
                    u32 fi = (int)lbl_803DDD2C & 0xff;
                    u32 ni = (fi + 2) & 0xff;
                    f32 frac = lbl_803DDD2C - fi;
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
                    dyaw = dyaw - yaw;
                    if (dyaw > 0x8000)
                    {
                        dyaw -= 0xffff;
                    }
                    if (dyaw < -0x8000)
                    {
                        dyaw += 0xffff;
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
        objId = ObjList_FindObjectById(tbl[lbl_803DC1C8[state->selectedPlanet]]);
        if (getLoadedFileFlags(0) == 0 && lbl_803DDD0A == 0)
        {
            switch (state->selectionLocked)
            {
            case 0:
                if (lbl_803DDD0C == 0)
                {
                    if (lbl_803DDD04 == 0 &&
                        ((u32)state->unlockedPlanetMask & (1 << state->selectedPlanet)) != 0 &&
                        (buttons & 0x100) != 0)
                    {
                        lbl_803DDD04 = 10;
                        mapUnload(lbl_803DDD28, 0x20000000);
                    }
                }
                else
                {
                    lbl_803DDD0C -= 1;
                }
                if (lbl_803DDD04 != 0)
                {
                    Pause_ResetMenuFrameCounter();
                    lbl_803DDD04 -= 1;
                    if (lbl_803DDD04 < 2)
                    {
                        lbl_803DDD04 = 0;
                        Sfx_PlayFromObject(0, 0x98);
                        (*gCameraInterface)->setFocus((void*)objId, 0x50);
                        state->selectionLocked = 1;
                        (*gCameraInterface)->releaseAction(&state->selectionLocked, 0);
                        {
                            int krazoa = ObjList_FindObjectById(0x43077);
                            ((WorldObjState*)((GameObject*)krazoa)->extra)->controlByte = lbl_803DC1E8[state->
                                selectedPlanet];
                        }
                        lbl_803DDD28 = loadMapAndParent(lbl_803DC1E0[lbl_803DC1C8[state->selectedPlanet]]);
                        lockLevel(lbl_803DDD28, 1);
                        loadModelAndAnimTabs();
                        lbl_803DDD00 = lbl_803E65F8;
                        lbl_803DC1F0 = state->selectedPlanet;
                    }
                }
                break;
            case 1:
                Pause_ResetMenuFrameCounter();
                {
                    int neq = lbl_803DDD00 != lbl_803E65F8;
                    if (!neq)
                    {
                        lbl_803DDD00 = lbl_803E6618;
                    }
                }
                if ((buttons & 0x200) != 0)
                {
                    AudioStream_StopCurrent();
                    Sfx_PlayFromObject(0, 0x99);
                    streamFn_8000a380(2, 2, 1000);
                    (*gCameraInterface)->setFocus((void*)obj, 0x50);
                    state->selectionLocked = 0;
                    lbl_803DDD0C = 0x1e;
                    (*gCameraInterface)->releaseAction(&state->selectionLocked, 0);
                    unlockLevel(lbl_803DDD28, 1, 0);
                    mapUnload(lbl_803DDD28, 0x20000000);
                    lbl_803DDD0A = 10;
                }
                else if ((buttons & 0x100) != 0)
                {
                    (*gScreenTransitionInterface)->start(4, 1);
                    streamFn_8000a380(3, 1, 0);
                    AudioStream_StopCurrent();
                    Sfx_PlayFromObject(0, 0x98);
                    setShowWorldMapHud(0);
                    lbl_803DDD08 = 5;
                    lbl_803DDD10 = 0;
                    mapUnload(lbl_803DDD28, 0x10000000);
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
            for (b = 0; b < 5; b++)
            {
                int p = ObjList_FindObjectById(tbl[b + 10]);
                ((GameObject*)p)->anim.rotZ = -ang;
            }
            r = lbl_803E6630;
            for (b = 0; b < 5; b++)
            {
                s16* p = (s16*)ObjList_FindObjectById(tbl[b]);
                int* off = &tbl[b + 5];
                if (tbl[b] == 0x4300d)
                {
                    *p = ang + tbl[b + 5] + 0x4000;
                }
                else
                {
                    *p = *p + 0x3c;
                }
                if (state->orbitSoundFrameCount > 2)
                {
                    Sfx_KeepAliveLoopedObjectSound((u32)p, 0x96);
                }
                *(f32*)(p + 6) = r * fsin16Approx((ang + *off) & 0xffff) * fcos16Approx(3000) + ((GameObject*)obj)->anim
                    .localPosX;
                *(f32*)(p + 8) = r * fsin16Approx((ang + *off) & 0xffff) * fsin16Approx(3000) + ((GameObject*)obj)->anim
                    .localPosY;
                *(f32*)(p + 10) = r * fcos16Approx((ang + *off) & 0xffff) + ((GameObject*)obj)->anim.localPosZ;
            }
        }
        state->orbitSoundFrameCount += 1;
    }
}
