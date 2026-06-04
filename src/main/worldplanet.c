#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/worldplanet.h"

extern void objRenderFn_8003b8f4(double scale);
extern void setShowWorldMapHud(int enabled);

extern f32 lbl_803E6618;
extern u32 GameBit_Get(int id);
extern int GameBit_Set(int id, int value);
extern void unlockLevel(int a, int b, int c);
extern MapEventInterface **gMapEventInterface;
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
extern int *gScreenTransitionInterface;
extern int padGetStickX(int controller);
extern int padGetStickY(int controller);
extern int getLoadedFileFlags(int file);

int worldplanet_getExtraSize(void)
{
  return sizeof(WorldPlanetState);
}

int worldplanet_getObjectTypeId(void)
{
  return 0;
}

#pragma peephole off
#pragma scheduling off
#pragma peephole off
void worldplanet_free(void)
{
  setShowWorldMapHud(0);
  return;
}

void worldplanet_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                        undefined4 param_4,undefined4 param_5,char visible)
{
  int draw;

  draw = visible;
  if (draw != 0) {
    objRenderFn_8003b8f4((double)lbl_803E6618);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

void worldplanet_hitDetect(void)
{
  return;
}

void worldplanet_release(void) {}

void worldplanet_initialise(void) {}

#pragma scheduling off
#pragma peephole off
void worldplanet_init(int obj) {
    WorldPlanetState *state;
    int mask;
    int i;
    int flag;
    int layer;
    int j;

    state = *(WorldPlanetState **)(obj + 0xb8);
    lbl_803DDD04 = 0;
    GameBit_Set(0xa63, 1);
    mask = 0;
    for (i = 0; i < 5; i++) {
        if (GameBit_Get(lbl_8032A1B4[i]) != 0) {
            flag = 1;
            if (lbl_803DC1B8[i] != 0) {
                if ((s32)getNextTaskHintText() > 0xad) {
                    flag = 0;
                }
            }
            if ((u8)flag != 0) {
                mask |= 1 << i;
            }
        }
    }
    state->unlockedPlanetMask = (u8)mask;
    if (lbl_803DC1F0 != -1) {
        state->selectedPlanet = (s8)lbl_803DC1F0;
    } else {
        for (j = 0; j < 5; j++) {
            if (GameBit_Get(lbl_8032A1B4[lbl_803DC1C0[j]]) != 0) {
                state->selectedPlanet = (s8)lbl_803DC1C0[j];
                break;
            }
        }
    }
    lbl_803DDD08 = 0;
    setDrawLights(0);
    audioStopByMask(0xf);
    Music_Trigger(0x8f, 1);
    lbl_803DDD2C = lbl_803E65F8;
    setShowWorldMapHud(1);
    lbl_803DDD28 = -1;
    unlockLevel(0, 0, 1);
    mapUnload(0x2d, 0x10000000);
    layer = getCurMapLayer();
    (*gMapEventInterface)->triggerEvent(obj + 0xc, 0, 0, layer);
    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0xc)))(0x1e, 1);
    lbl_803DDD0A = 0xa;
    GameBit_Set(lbl_8032A1B4[2], 1);
    state->foxSpawnTimer = 0x78;
    envFxActFn_800887f8(0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void worldplanet_readMapInput(int obj, u8 *outX, u8 *outY) {
    WorldPlanetState *state = *(WorldPlanetState **)(obj + 0xb8);
    int stickX;
    int stickY;
    int resX;
    int resY;

    stickX = padGetStickX(0);
    stickY = padGetStickY(0);
    resX = 0;
    resY = 0;
    if (getLoadedFileFlags(0) == 0) {
        if ((s8)stickX < -0x23 && state->prevStickX >= -0x23) {
            resX = -1;
            state->stickXRepeatFrames = 0;
        }
        if ((s8)stickX > 0x23 && state->prevStickX <= 0x23) {
            resX = 1;
            state->stickXRepeatFrames = 0;
        }
        if ((s8)stickY < -0x23 && state->prevStickY >= -0x23) {
            resY = -1;
            state->stickYRepeatFrames = 0;
        }
        if ((s8)stickY > 0x23 && state->prevStickY <= 0x23) {
            resY = 1;
            state->stickYRepeatFrames = 0;
        }
        state->prevStickY = stickY;
        if (state->prevStickY < -0x23) {
            state->stickYRepeatFrames++;
        } else if (state->prevStickY > 0x23) {
            state->stickYRepeatFrames++;
        } else {
            state->stickYRepeatFrames = 0;
        }
        if (state->stickYRepeatFrames > 0x32) {
            state->prevStickY = 0;
            state->stickYRepeatFrames = 0;
        }
        state->prevStickX = stickX;
        if (state->prevStickX < -0x23) {
            state->stickXRepeatFrames++;
        } else if (state->prevStickX > 0x23) {
            state->stickXRepeatFrames++;
        } else {
            state->stickXRepeatFrames = 0;
        }
        if (state->stickXRepeatFrames > 0x32) {
            state->prevStickX = 0;
            state->stickXRepeatFrames = 0;
        }
        *outX = resX;
        *outY = resY;
    } else {
        *outX = 0;
        *outY = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset


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
extern int *gCameraInterface;
extern int *gPartfxInterface;
extern void pauseMenuSetupTitle(int strId, int p2, int p3, int p4);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 lbl_803E65F8_pad;
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
extern void Pause_ResetMenuFrameCounter(void);
extern int getLoadedFileFlags(int file);
extern int loadMapAndParent(int mapId);
extern void lockLevel(int idx, int p2);
extern void loadModelAndAnimTabs(void);
extern void streamFn_8000a380(int a, int b, int c);
extern void warpToMap(int map, int p2);
extern void Sfx_KeepAliveLoopedObjectSound(s16 *obj, int sound);
extern f32 fsin16Approx(int angle);
extern f32 fcos16Approx(int angle);
extern f32 lbl_803E661C;
extern f32 lbl_803E6620;
extern f32 lbl_803E6624;
extern f32 lbl_803E6628;
extern f32 lbl_803E662C;
extern f32 lbl_803E6630;
extern f32 lbl_803E6618_2;

#pragma scheduling off
#pragma peephole off
void worldplanet_update(int obj) {
    WorldPlanetState *state;
    int *tbl;
    u8 done;
    u8 prevPlanet;
    int buttons;
    u32 mask;
    u32 i;
    u8 b;
    int objId;
    int galleon;
    struct { u8 pad[6]; s16 a; int pad2; f32 x, y, z; } pfx;
    s8 inX[3];
    u8 inY;

    tbl = lbl_8032A178;
    state = *(WorldPlanetState **)(obj + 0xb8);
    done = 0;
    state->foxSpawnTimer -= 1;
    if (state->foxSpawnTimer == 1) {
        int def;
        state->foxSpawnTimer = randomGetRange(0x708, 3000);
        def = *(int *)(obj + 0x4c);
        if (Obj_IsLoadingLocked() != 0) {
            int setup = Obj_AllocObjectSetup(0x20, 0x80f);
            *(u8 *)(setup + 4) = *(u8 *)(def + 4);
            *(u8 *)(setup + 6) = *(u8 *)(def + 6);
            *(u8 *)(setup + 5) = *(u8 *)(def + 5);
            *(u8 *)(setup + 7) = *(u8 *)(def + 7);
            *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc);
            *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
            *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
            Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, 0);
        }
    }
    if (state->foxSpawnTimer < 0) {
        state->foxSpawnTimer = 0;
    }
    worldplanet_updateMapLighting(obj);
    if (lbl_803DDD0A != 0) {
        lbl_803DDD0A -= 1;
    }
    if (lbl_803DDD08 != 0) {
        lbl_803DDD08 -= 1;
        if (lbl_803DDD08 == 0) {
            setIsOvercast(1);
            setDrawCloudsAndLights(1);
            setDrawLights(1);
            warpToMap(lbl_803DC1D8[lbl_803DC1C8[state->selectedPlanet]], 0);
        }
    } else {
        setFrameCountdown_800202c4(1);
        if ((state->flags & 4) == 0) {
            (*(void (*)(int, int, int, int, int, int, int))*(int *)(*gCameraInterface + 0x1c))(0x4e, 1, 0, 0, 0, 0, 0xff);
            (*(void (*)(int, int))*(int *)(*gCameraInterface + 0x28))(obj, 0);
            state->flags |= 4;
        } else if ((state->flags & 8) == 0) {
            objId = tbl[lbl_803DC1C8[state->selectedPlanet]];
            (*(void (*)(int *, int))*(int *)(*gCameraInterface + 0x60))(&objId, 2);
            state->flags |= 8;
            {
                int krazoa = ObjList_FindObjectById(0x43077);
                *(u8 *)(*(int *)(krazoa + 0xb8) + 0x27c) = lbl_803DC1E8[state->selectedPlanet];
            }
            AudioStream_StopCurrent();
        }
        if ((state->flags & 1) == 0) {
            state->flags |= 1;
            getEnvfxAct(0, 0, 0x21f, 0);
            setIsOvercast(0);
            setDrawLights(0);
        }
        buttons = getButtonsJustPressed(0);
        pfx.a = 100;
        pfx.x = lbl_803E661C;
        pfx.y = lbl_803E6620;
        pfx.z = lbl_803E6624;
        (*(void (*)(int, int, void *, int, int, int))*(int *)(*gPartfxInterface + 8))(obj, 0x6f2, &pfx, 2, -1, 0);
        worldplanet_readMapInput(obj, (u8 *)inX, &inY);
        *(s16 *)(obj + 4) -= 10;
        *(s16 *)(obj + 2) = 0x3448;
        *(s16 *)obj = 0x4000;
        {
            int fox = ObjList_FindObjectById(0x42ff5);
            *(s16 *)(fox + 4) = *(s16 *)(obj + 4);
            *(s16 *)(fox + 2) = *(s16 *)(obj + 2);
            *(s16 *)fox = *(s16 *)obj;
        }
        galleon = ObjList_FindObjectById(0x4300c);
        *(u8 *)(*(int *)(galleon + 0xb8) + 0x27d) = state->selectionLocked;
        prevPlanet = *(u8 *)((char *)state + 0x10);
        {
            u32 m = 0;
            int k = m;
            int *ids = &tbl[15];
            u8 *hints = lbl_803DC1B8;
            do {
                if (GameBit_Get(*ids) != 0) {
                    int ok = 1;
                    if (*hints != 0 && (s32)getNextTaskHintText() > 0xad) {
                        ok = 0;
                    }
                    if (ok) {
                        m |= 1 << k;
                    }
                }
                ids += 1;
                hints += 1;
                k += 1;
            } while (k < 5);
            state->unlockedPlanetMask = (u8)m;
        }
        if (lbl_803DDD04 == 0 && (u8)state->selectionLocked == 0) {
            while (!done) {
                state->selectedPlanet = state->selectedPlanet + inX[0];
                if (state->selectedPlanet < 0) {
                    state->selectedPlanet = 4;
                } else if (state->selectedPlanet >= 5) {
                    state->selectedPlanet = 0;
                }
                done = 1;
            }
            pauseMenuSetupTitle(0x2a7, lbl_803DC1D0[state->selectedPlanet], 0x19, 0);
            if (prevPlanet != state->selectedPlanet || *(int *)(obj + 0xf4) == 0) {
                if (*(int *)(obj + 0xf4) != 0) {
                    objId = tbl[lbl_803DC1C8[state->selectedPlanet]];
                    (*(void (*)(int *, int))*(int *)(*gCameraInterface + 0x60))(&objId, 1);
                    Sfx_PlayFromObject(0, 0x97);
                }
                lbl_803DDD2C = lbl_803E65F8;
                {
                    int p = ObjList_FindObjectById(tbl[lbl_803DC1C8[prevPlanet]]);
                    *(u8 *)(*(int *)(p + 0xb8) + 0x27d) = 0;
                    p = ObjList_FindObjectById(tbl[lbl_803DC1C8[state->selectedPlanet]]);
                    *(u8 *)(*(int *)(p + 0xb8) + 0x27d) = 1;
                }
                *(int *)(obj + 0xf4) = 1;
            }
        }
        lbl_803DDD2C = lbl_803DDD2C + lbl_803E6628;
        if (lbl_803E662C <= lbl_803DDD2C) {
            lbl_803DDD2C = lbl_803E65F8;
        }
        for (i = 0; (i & 0xff) < 5; i++) {
            int planet = ObjList_FindObjectById((tbl + (i & 0xff))[10]);
            int pstate = *(int *)(planet + 0xb8);
            *(s16 *)(planet + 2) = *(s16 *)(obj + 2);
            *(s16 *)planet = *(s16 *)obj;
            if ((u8)state->selectionLocked != 0 || (((int)(u32)state->unlockedPlanetMask >> (i & 0xff)) & 1) == 0) {
                *(u8 *)(pstate + 0x27d) = 0;
                if ((int)(i & 0xff) == state->selectedPlanet) {
                    *(s16 *)(galleon + 6) = *(s16 *)(galleon + 6) | 0x4000;
                }
            } else {
                if ((int)(i & 0xff) == state->selectedPlanet) {
                    u32 fi = (int)lbl_803DDD2C & 0xff;
                    u32 ni = (fi + 2) & 0xff;
                    f32 frac = lbl_803DDD2C - (f32)fi;
                    int seg = pstate + fi * 0x18;
                    f32 x0 = *(f32 *)(seg + 0x10);
                    f32 x1 = *(f32 *)(seg + 0x28);
                    f32 y0 = *(f32 *)(seg + 0x14);
                    f32 y1 = *(f32 *)(seg + 0x2c);
                    f32 z0 = *(f32 *)(seg + 0x18);
                    f32 z1 = *(f32 *)(seg + 0x30);
                    u16 yaw;
                    s16 dyaw;
                    *(u8 *)(pstate + 0x27d) = 2;
                    yaw = getAngle(x1 - x0, z1 - z0);
                    if (ni >= 0x16) {
                        dyaw = yaw;
                    } else {
                        int nseg = pstate + ni * 0x18;
                        dyaw = getAngle(*(f32 *)(nseg + 0x10) - x1, *(f32 *)(nseg + 0x18) - z1);
                    }
                    dyaw = dyaw - yaw;
                    if (dyaw > 0x8000) {
                        dyaw -= 0xffff;
                    }
                    if (dyaw < -0x8000) {
                        dyaw += 0xffff;
                    }
                    if (fn_8012DDAC() != 0) {
                        *(s16 *)(galleon + 6) = *(s16 *)(galleon + 6) | 0x4000;
                    } else {
                        *(s16 *)(galleon + 6) = *(s16 *)(galleon + 6) & ~0x4000;
                    }
                    {
                        f32 fd = frac * (f32)dyaw;
                        *(s16 *)galleon = (s16)(int)(fd + (f32)yaw);
                    }
                    *(f32 *)(galleon + 0xc) = frac * (x1 - x0) + x0;
                    *(f32 *)(galleon + 0x10) = frac * (y1 - y0) + y0;
                    *(f32 *)(galleon + 0x14) = frac * (z1 - z0) + z0;
                } else {
                    *(u8 *)(pstate + 0x27d) = 1;
                }
            }
        }
        objId = ObjList_FindObjectById(tbl[lbl_803DC1C8[state->selectedPlanet]]);
        if (getLoadedFileFlags(0) == 0 && lbl_803DDD0A == 0) {
            switch (state->selectionLocked) {
            case 0:
                if (lbl_803DDD0C == 0) {
                    if (lbl_803DDD04 == 0 &&
                        ((u32)state->unlockedPlanetMask & (1 << state->selectedPlanet)) != 0 &&
                        (buttons & 0x100) != 0) {
                        lbl_803DDD04 = 10;
                        mapUnload(lbl_803DDD28, 0x20000000);
                    }
                } else {
                    lbl_803DDD0C -= 1;
                }
                if (lbl_803DDD04 != 0) {
                    Pause_ResetMenuFrameCounter();
                    lbl_803DDD04 -= 1;
                    if (lbl_803DDD04 < 2) {
                        lbl_803DDD04 = 0;
                        Sfx_PlayFromObject(0, 0x98);
                        (*(void (*)(int, int))*(int *)(*gCameraInterface + 0x28))(objId, 0x50);
                        state->selectionLocked = 1;
                        (*(void (*)(s8 *, int))*(int *)(*gCameraInterface + 0x60))(&state->selectionLocked, 0);
                        {
                            int krazoa = ObjList_FindObjectById(0x43077);
                            *(u8 *)(*(int *)(krazoa + 0xb8) + 0x27c) = lbl_803DC1E8[state->selectedPlanet];
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
                    if (!neq) {
                        lbl_803DDD00 = lbl_803E6618;
                    }
                }
                if ((buttons & 0x200) != 0) {
                    AudioStream_StopCurrent();
                    Sfx_PlayFromObject(0, 0x99);
                    streamFn_8000a380(2, 2, 1000);
                    (*(void (*)(int, int))*(int *)(*gCameraInterface + 0x28))(obj, 0x50);
                    state->selectionLocked = 0;
                    lbl_803DDD0C = 0x1e;
                    (*(void (*)(s8 *, int))*(int *)(*gCameraInterface + 0x60))(&state->selectionLocked, 0);
                    unlockLevel(lbl_803DDD28, 1, 0);
                    mapUnload(lbl_803DDD28, 0x20000000);
                    lbl_803DDD0A = 10;
                } else if ((buttons & 0x100) != 0) {
                    (*(void (*)(int, int))*(int *)(*gScreenTransitionInterface + 8))(4, 1);
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
        } else {
            Pause_ResetMenuFrameCounter();
        }
        {
            u32 ang = -*(s16 *)(obj + 4) & 0xffff;
            f32 r;
            for (b = 0; b < 5; b++) {
                int p = ObjList_FindObjectById(tbl[b + 10]);
                *(s16 *)(p + 4) = -(s16)ang;
            }
            r = lbl_803E6630;
            for (b = 0; b < 5; b++) {
                s16 *p = (s16 *)ObjList_FindObjectById(tbl[b]);
                int *off = &tbl[b + 5];
                if (tbl[b] == 0x4300d) {
                    *p = (s16)ang + (s16)tbl[b + 5] + 0x4000;
                } else {
                    *p = *p + 0x3c;
                }
                if (*(u32 *)((char *)state + 0x14) > 2) {
                    Sfx_KeepAliveLoopedObjectSound(p, 0x96);
                }
                *(f32 *)(p + 6) = r * fsin16Approx((ang + *off) & 0xffff) * fcos16Approx(3000) + *(f32 *)(obj + 0xc);
                *(f32 *)(p + 8) = r * fsin16Approx((ang + *off) & 0xffff) * fsin16Approx(3000) + *(f32 *)(obj + 0x10);
                *(f32 *)(p + 10) = r * fcos16Approx((ang + *off) & 0xffff) + *(f32 *)(obj + 0x14);
            }
        }
        *(int *)((char *)state + 0x14) += 1;
    }
}
#pragma peephole reset
#pragma scheduling reset
