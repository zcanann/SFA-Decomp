#include "ghidra_import.h"

extern int *gExpgfxInterface;
extern void ModelLightStruct_free(int model);
extern void Obj_FreeObject(int obj);

int worldobj_getExtraSize(void) { return 0x284; }
int snowclaw_getExtraSize(void) { return 0xb0; }
int snowclaw_getObjectTypeId(void) { return 0x3; }

void worldobj_hitDetect(void) {}
void worldobj_release(void) {}
void worldobj_initialise(void) {}
void worldplanet_release(void) {}
void worldplanet_initialise(void) {}
void snowclaw_release(void) {}
void snowclaw_initialise(void) {}

#pragma scheduling off
#pragma peephole off
int worldobj_getObjectTypeId(int *obj) {
    if (*(s16 *)*(int **)((char *)obj + 0x4c) != 0x5e3) {
        return 0x0;
    }
    return 0x8;
}

void worldobj_free(int obj) {
    int *inner = *(int **)(obj + 0xb8);
    if (*(void **)inner != NULL) {
        ModelLightStruct_free(*inner);
        *inner = 0;
    }
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x14)))(obj);
}

void snowclaw_free(int obj) {
    if (*(void **)(obj + 0xc8) != NULL) {
        Obj_FreeObject(*(int *)(obj + 0xc8));
    }
}
#pragma peephole reset
#pragma scheduling reset

extern u32 GameBit_Get(int id);
extern int GameBit_Set(int id, int value);
extern void loadMapAndParent(int mapId);
extern void unlockLevel(int a, int b, int c);
extern int lockLevel(int mapDir, int flags);
extern int mapGetDirIdx(int mapId);
extern int *gMapEventInterface;
extern int Obj_GetPlayerObject(void);
extern void setMotionBlur(int mode, f32 amount);
extern u32 fn_802972A8(int obj);
extern int ObjGroup_FindNearestObject(int kind, int obj, f32 *maxDistance);
extern f32 lbl_803E6740;
extern f32 lbl_803E6744;

#pragma scheduling off
#pragma peephole off
int crcloudrace_completionCallback(int obj, int arg2, u8 *data) {
    int *inner = *(int **)(obj + 0xb8);
    int i;

    *(u8 *)((char *)inner + 9) |= 1;
    for (i = 0; i < *(u8 *)((char *)data + 0x8b); i++) {
        switch (data[i + 0x81]) {
        case 1:
            GameBit_Set(0xdca, 1);
            GameBit_Set(0x458, 0);
            loadMapAndParent(0xc);
            unlockLevel(0, 0, 1);
            lockLevel(mapGetDirIdx(0xc), 0);
            (*(void (*)(int, int, int))(*(int *)(*gMapEventInterface + 0x50)))(0xc, 1, 1);
            break;
        }
    }
    return 0;
}

#pragma dont_inline on
void crcloudrace_updateCompletionState(int obj, int *state) {
    f32 dist;
    int player;
    u32 near;

    dist = lbl_803E6740;
    player = Obj_GetPlayerObject();
    if (GameBit_Get(0x499) == 0) {
        if (GameBit_Get(0x2e8) != 0) {
            *(u8 *)((char *)state + 8) = 4;
            setMotionBlur(0, lbl_803E6744);
            GameBit_Set(0x497, 0);
            GameBit_Set(0x49d, 0);
        }
    } else {
        GameBit_Set(0x499, 1);
        setMotionBlur(0, lbl_803E6744);
        if (GameBit_Get(0x4a9) != 0 && fn_802972A8(player) == 0) {
            near = ObjGroup_FindNearestObject(0x1e, obj, &dist);
            if (near != 0) {
                (*(void (*)(int, int))(*(int *)(*(int *)(*(int *)(near + 0x68)) + 0x20)))(near, 1);
            }
            *(u8 *)((char *)state + 8) = 5;
        }
    }
}
#pragma dont_inline reset

extern int timerCountDown(void *p);
extern void s16toFloat(void *p, int duration);

void crcloudrace_updateRaceState(int obj) {
    int *inner;
    int player;

    inner = *(int **)(obj + 0xb8);
    player = Obj_GetPlayerObject();
    switch (*(u8 *)((char *)inner + 8)) {
    case 2:
        if (GameBit_Get(0x4a0) != 0) {
            GameBit_Set(0x4ba, 1);
        }
        if (fn_802972A8(player) != 0) {
            GameBit_Set(0x49d, 1);
            GameBit_Set(0x497, 1);
            *(u8 *)((char *)inner + 8) = 3;
            unlockLevel(0, 0, 1);
        }
        break;
    case 3:
        crcloudrace_updateCompletionState(obj, inner);
        break;
    case 4:
        GameBit_Set(0x4ba, 0);
        *(u8 *)((char *)inner + 8) = 7;
        s16toFloat((char *)inner + 4, 0xa);
        break;
    case 7:
        if (timerCountDown((char *)inner + 4) != 0) {
            *(u8 *)((char *)inner + 8) = 8;
        }
        break;
    case 8:
        unlockLevel(0, 0, 1);
        loadMapAndParent(0xc);
        lockLevel(mapGetDirIdx(0xc), 0);
        GameBit_Set(0xd73, 0);
        GameBit_Set(0x983, 0);
        GameBit_Set(0xe23, 0);
        GameBit_Set(0xe1d, 0);
        GameBit_Set(0xdb8, 0);
        GameBit_Set(0x984, 0);
        GameBit_Set(0x458, 0);
        *(u8 *)((char *)inner + 8) = 0;
        break;
    case 5:
        *(u8 *)((char *)inner + 8) = 2;
        break;
    case 1:
    case 6:
    default:
        *(u8 *)((char *)inner + 8) = 2;
        break;
    case 0:
        break;
    }
}

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
extern void setShowWorldMapHud(int show);
extern void mapUnload(int mapId, int flags);
extern int getCurMapLayer(void);
extern void envFxActFn_800887f8(int arg);
extern int *gScreenTransitionInterface;

void worldplanet_init(int obj) {
    int inner;
    int mask;
    int i;
    int flag;
    int layer;
    int j;

    inner = *(int *)(obj + 0xb8);
    lbl_803DDD04 = 0;
    GameBit_Set(0xa63, 1);
    mask = 0;
    for (i = 0; i < 5; i++) {
        if (GameBit_Get(lbl_8032A1B4[i]) != 0) {
            flag = 1;
            if (lbl_803DC1B8[i] != 0) {
                if (getNextTaskHintText() > 0xad) {
                    flag = 0;
                }
            }
            if ((u8)flag != 0) {
                mask |= 1 << i;
            }
        }
    }
    *(u8 *)(inner + 0x11) = (u8)mask;
    if (lbl_803DC1F0 != -1) {
        *(s8 *)(inner + 0x10) = (s8)lbl_803DC1F0;
    } else {
        for (j = 0; j < 5; j++) {
            if (GameBit_Get(lbl_8032A1B4[lbl_803DC1C0[j]]) != 0) {
                *(s8 *)(inner + 0x10) = (s8)lbl_803DC1C0[j];
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
    (*(void (*)(int, int, int, int))(*(int *)(*gMapEventInterface + 0x1c)))(obj + 0xc, 0, 0, layer);
    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0xc)))(0x1e, 1);
    lbl_803DDD0A = 0xa;
    GameBit_Set(lbl_8032A1B4[2], 1);
    *(s16 *)(inner + 0x6) = 0x78;
    envFxActFn_800887f8(0);
}

extern int padGetStickX(int controller);
extern int padGetStickY(int controller);
extern int getLoadedFileFlags(int file);

void worldplanet_readMapInput(int obj, u8 *outX, u8 *outY) {
    s8 *inner = *(s8 **)(obj + 0xb8);
    int stickX;
    int stickY;
    int resX;
    int resY;

    stickX = padGetStickX(0);
    stickY = padGetStickY(0);
    resX = 0;
    resY = 0;
    if (getLoadedFileFlags(0) == 0) {
        if ((s8)stickX < -0x23 && inner[0xa] >= -0x23) {
            resX = -1;
            inner[0xc] = 0;
        }
        if ((s8)stickX > 0x23 && inner[0xa] <= 0x23) {
            resX = 1;
            inner[0xc] = 0;
        }
        if ((s8)stickY < -0x23 && inner[0xb] >= -0x23) {
            resY = -1;
            inner[0xd] = 0;
        }
        if ((s8)stickY > 0x23 && inner[0xb] <= 0x23) {
            resY = 1;
            inner[0xd] = 0;
        }
        inner[0xb] = stickY;
        if (inner[0xb] < -0x23) {
            inner[0xd]++;
        } else if (inner[0xb] > 0x23) {
            inner[0xd]++;
        } else {
            inner[0xd] = 0;
        }
        if (inner[0xd] > 0x32) {
            inner[0xb] = 0;
            inner[0xd] = 0;
        }
        inner[0xa] = stickX;
        if (inner[0xa] < -0x23) {
            inner[0xc]++;
        } else if (inner[0xa] > 0x23) {
            inner[0xc]++;
        } else {
            inner[0xc] = 0;
        }
        if (inner[0xc] > 0x32) {
            inner[0xa] = 0;
            inner[0xc] = 0;
        }
        *outX = resX;
        *outY = resY;
    } else {
        *outX = 0;
        *outY = 0;
    }
}

extern void snowclaw_animEventCallback();
extern u8 lbl_8032A310[];
extern f32 lbl_803E66EC;
extern int lbl_803DDD38;
extern void storeZeroToFloatParam(void *p);
extern void s16toFloat(void *p, int duration);
extern void objSeqInitFn_80080078(void *table, int n);

void snowclaw_init(int *obj, u8 *init) {
    u8 *table;
    int *inner;
    int *sub;

    table = lbl_8032A310;
    *(void **)((char *)obj + 0xbc) = (void *)snowclaw_animEventCallback;
    sub = *(int **)((char *)obj + 0x64);
    if (sub != NULL) {
        *(int *)((char *)sub + 0x30) |= 0x4000;
        *(u8 *)((char *)*(int **)((char *)obj + 0x64) + 0x3a) = 0x64;
        *(u8 *)((char *)*(int **)((char *)obj + 0x64) + 0x3b) = 0x96;
    }
    inner = *(int **)((char *)obj + 0xb8);
    *(int *)inner = 0;
    *(u8 *)((char *)inner + 0xa2) = init[0x27];
    *(u8 *)((char *)inner + 0xa4) = 4;
    *(s8 *)((char *)inner + 0xa5) = -1;
    switch (*(s16 *)((char *)obj + 0x46)) {
    case 0x16d:
    case 0x170:
    default:
        *(int *)((char *)inner + 4) = (int)(table + 0x58);
        *(s16 *)((char *)inner + 0xa8) = 0x100;
        break;
    case 0x389:
    case 0x38a:
    case 0x4d3:
        *(int *)((char *)inner + 4) = (int)(table + 0x54);
        *(s16 *)((char *)inner + 0xa8) = 0x400;
        /* fall through */
    case 0x3e8:
        *(int *)((char *)inner + 4) = (int)(table + 0x5c);
        *(s16 *)((char *)inner + 0xa8) = 0x400;
        break;
    }
    *(u8 *)((char *)inner + 0xa6) = 0;
    *(int *)((char *)inner + 0x9c) = 0x64;
    *(f32 *)((char *)inner + 0x30) = lbl_803E66EC;
    storeZeroToFloatParam((char *)inner + 0x98);
    s16toFloat((char *)inner + 0x98, (s16)*(int *)(table + 0x3c));
    objSeqInitFn_80080078(table, 6);
    lbl_803DDD38 = 0x96;
    *(u8 *)((char *)inner + 0xaa) &= ~0x80;
}

extern void objRenderFn_8003b8f4(f32 e);
extern f32 lbl_803E6678;
extern int randomGetRange(int min, int max);
extern void GXSetScissor(int x, int y, int w, int h);
extern void Camera_ApplyCurrentViewport(int cam);
extern int fn_8012DDAC(void);
extern int *gScreenTransitionInterface;
extern int lbl_803DDD34;
extern int fn_8001DB64(int model);
extern void queueGlowRender(int model);
extern int *gPartfxInterface;
extern void mathFn_80021ac8(void *in, void *out);
extern f32 lbl_803E665C;

void worldobj_spawnAsteroidBatch(int obj, int xMin, int xMax, int yMin, int yMax, int count, int dispatchId) {
    struct {
        s16 f8;
        s16 fa;
        s16 fc;
        s16 pad_e;
        f32 f10;
        f32 f14;
        f32 f18;
    } dir;
    struct {
        u8 pad0[6];
        s16 f6;
        u8 pad8[4];
        f32 fc;
        f32 f10;
        f32 f14;
    } params;
    int i;
    f32 base = lbl_803E665C;

    for (i = 0; i < count; i++) {
        dir.f10 = base;
        dir.f14 = (f32)(int)randomGetRange(xMin, xMax);
        dir.f18 = (f32)(int)randomGetRange(yMin, yMax);
        dir.f8 = 0;
        dir.fa = 0;
        dir.fc = (s16)randomGetRange(-0x7fff, 0x7fff);
        mathFn_80021ac8(&dir.f8, &dir.f10);
        params.fc = dir.f10;
        params.f10 = dir.f14;
        params.f14 = dir.f18;
        params.f6 = 0x64;
        (*(void (*)(int, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(obj, dispatchId, &params, 2, -1, 0);
    }
}

void worldobj_render(int p1, int p2, int p3, int p4, int p5, s8 visible) {
    int *inner = *(int **)(p1 + 0xb8);
    int modelId = *(s16 *)*(int **)(p1 + 0x4c);

    if (modelId == 0x5f5) {
        objRenderFn_8003b8f4(lbl_803E6678);
        return;
    }
    if (visible == 0) {
        return;
    }
    if (modelId == 0x61e) {
        return;
    }
    switch (modelId) {
    case 0x5de:
        if (*(u8 *)((char *)inner + 0x27d) == 0) {
            objRenderFn_8003b8f4(lbl_803E6678);
        }
        break;
    case 0x5e3:
        if (randomGetRange(0, 0x19) != 0 && *(u8 *)((char *)inner + 0x27d) != 0) {
            GXSetScissor(0x1e0, 0x32, 0x82, 0x96);
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
            Camera_ApplyCurrentViewport(p2);
        }
        break;
    case 0x740:
        if (*(u8 *)((char *)inner + 0x27d) != 0 && (u8)fn_8012DDAC() == 0 &&
            (*(int (*)(void))(*(int *)(*gScreenTransitionInterface + 0x14)))() != 0) {
            if (lbl_803DDD34 != 0) {
                lbl_803DDD34 = lbl_803DDD34 - 1;
            } else {
                ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
            }
        } else {
            lbl_803DDD34 = 2;
        }
        break;
    case 0x80f:
        if (*(void **)inner != NULL && fn_8001DB64(*(int *)inner) != 0) {
            queueGlowRender(*(int *)inner);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
        break;
    case 0x5da:
    case 0x5dc:
    default:
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
        break;
    }
}

extern int objUpdateOpacity(int sub);
extern void ObjLink_AttachChild(int obj, int child, int c);
extern void ObjPath_GetPointWorldPosition(int obj, int idx, f32 *x, f32 *y, f32 *z, int e);
extern void objParticleFn_80099d84(int obj, f32 a, int b, f32 c, int d);
extern void snowclaw_syncMountTransform(int obj, int sub, int p2, int p3, int p4, int p5, int opacity, int a8, int a9);
extern f32 lbl_803E66F0;
extern f32 lbl_803E6708;
extern f32 lbl_803E670C;
extern f32 lbl_803E6710;

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern int getAngle(f32 dx, f32 dz);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int loadObjectAtObject(int obj, int spawn);
extern f32 lbl_803E66E0;

void snowclaw_spawnDropBomb(int obj, int a, int b, int c) {
    int player;
    int obj2;
    int spawned;

    player = Obj_GetPlayerObject();
    if (Obj_IsLoadingLocked() != 0) {
        obj2 = Obj_AllocObjectSetup(0x24, 0x5ff);
        *(s16 *)(obj2 + 0x0) = 0x5ff;
        *(u8 *)(obj2 + 0x4) = 2;
        *(u8 *)(obj2 + 0x6) = 0xff;
        *(u8 *)(obj2 + 0x5) = 1;
        *(u8 *)(obj2 + 0x7) = 0xff;
        *(s8 *)(obj2 + 0x19) = (s8)b;
        *(f32 *)(obj2 + 0x8) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj2 + 0xc) = lbl_803E66E0 + *(f32 *)(obj + 0x10);
        *(f32 *)(obj2 + 0x10) = *(f32 *)(obj + 0x14);
        *(s8 *)(obj2 + 0x18) = (s8)(u8)((((getAngle(*(f32 *)(player + 0xc) - *(f32 *)(obj + 0xc),
                                                   *(f32 *)(player + 0x14) - *(f32 *)(obj + 0x14)) & 0xffff) >> 8) + 0x8000) >> 8);
        Sfx_PlayFromObject(obj, 0x2e4);
        switch ((u8)b) {
        case 0:
            *(s16 *)(obj2 + 0x1a) = (s16)lbl_803DDD38;
            break;
        case 1:
            *(s16 *)(obj2 + 0x1a) = (s16)(getAngle(*(f32 *)(player + 0xc) - *(f32 *)(obj + 0xc),
                                                    *(f32 *)(player + 0x14) - *(f32 *)(obj + 0x14)) + 0x8000);
            break;
        }
        spawned = loadObjectAtObject(obj, obj2);
        if (spawned != 0) {
            *(int *)(spawned + 0xf4) = (u8)c;
            *(int *)(spawned + 0xc4) = a;
        }
    }
}

void snowclaw_syncMountTransform(int obj, int sub, int p2, int p3, int p4, int p5, int opacity, int a8, int a9) {
    f32 va, vb, vc;

    if (a9 != 0 && (s8)opacity != 0 && a8 > 0) {
        u8 saved = *(u8 *)(sub + 0x37);
        *(u8 *)(sub + 0x37) = (u8)a8;
        (*(void (*)(int, int, int, int, int, int))(*(int *)(*(int *)(*(int *)(sub + 0x68)) + 0x10)))(sub, p2, p3, p4, p5, -1);
        *(u8 *)(sub + 0x37) = saved;
    }
    *(f32 *)(obj + 0x8c) = *(f32 *)(obj + 0x18);
    *(f32 *)(obj + 0x90) = *(f32 *)(obj + 0x1c);
    *(f32 *)(obj + 0x94) = *(f32 *)(obj + 0x20);
    *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
    (*(void (*)(int, f32 *, f32 *, f32 *))(*(int *)(*(int *)(*(int *)(sub + 0x68)) + 0x28)))(sub, &va, &vb, &vc);
    *(f32 *)(obj + 0xc) = va;
    *(f32 *)(obj + 0x10) = vb;
    *(f32 *)(obj + 0x14) = vc;
    *(s16 *)(obj + 0x0) = *(s16 *)(sub + 0x0);
    *(s16 *)(obj + 0x2) = *(s16 *)(sub + 0x2);
    *(s16 *)(obj + 0x4) = *(s16 *)(sub + 0x4);
    *(f32 *)(obj + 0x18) = *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x1c) = *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x20) = *(f32 *)(obj + 0x14);
    *(f32 *)(obj + 0x24) = *(f32 *)(sub + 0x24);
    *(f32 *)(obj + 0x28) = *(f32 *)(sub + 0x28);
    *(f32 *)(obj + 0x2c) = *(f32 *)(sub + 0x2c);
}

void snowclaw_render(int obj, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner;
    int sub;
    int found;
    int opacity;
    int oldFlag;
    f32 dist;
    int near;

    dist = lbl_803E6708;
    inner = *(int **)(obj + 0xb8);
    sub = *(int *)inner;
    if (*(u8 *)((char *)obj + 0x36) < 5) {
        *(f32 *)((char *)inner + 0xac) = lbl_803E66F0;
    }
    found = 0;
    opacity = vis;
    if (*(s8 *)((char *)inner + 0xa4) >= 0 && sub != 0) {
        if ((*(int (*)(int))(*(int *)(*(int *)(sub + 0x68) + 0x38)))(sub) == 2) {
            found = 1;
        }
    }
    if (found != 0) {
        *(s16 *)((char *)obj + 6) |= 8;
        opacity = (s8)objUpdateOpacity(sub);
        snowclaw_syncMountTransform(obj, sub, p2, p3, p4, p5, opacity, *(u8 *)((char *)inner + 0xa0), 1);
    } else {
        *(s16 *)((char *)obj + 6) &= ~8;
    }
    if ((s8)opacity != 0 && *(u8 *)((char *)inner + 0xa0) != 0) {
        oldFlag = *(u8 *)((char *)obj + 0x37);
        if (found != 0) {
            *(u8 *)((char *)obj + 0x37) = *(u8 *)((char *)inner + 0xa0);
        }
        if (*(u8 *)((char *)obj + 0xeb) == 0 && *(s16 *)((char *)obj + 0x46) == 0x389 &&
            ((*(u8 *)((char *)inner + 0xaa) >> 7) & 1) != 0) {
            near = ObjGroup_FindNearestObject(0x1e, obj, &dist);
            if (near != 0 &&
                (*(int (*)(int))(*(int *)(*(int *)(near + 0x68) + 0x24)))(near) != 0 &&
                (*(int (*)(int, int))(*(int *)(*(int *)(near + 0x68) + 0x20)))(near, 0) != 0) {
                ObjLink_AttachChild(obj, near, 0);
            }
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E670C);
        ObjPath_GetPointWorldPosition(obj, 1, (f32 *)((char *)inner + 0x18), (f32 *)((char *)inner + 0x1c), (f32 *)((char *)inner + 0x20), 0);
        *(u8 *)((char *)obj + 0x37) = oldFlag;
        if (((*(u8 *)((char *)inner + 0xaa) >> 6) & 1) != 0) {
            if (*(f32 *)((char *)inner + 0xac) != lbl_803E66F0) {
                *(f32 *)((char *)inner + 0xac) = lbl_803E670C + (f32)(s32)(0xff - *(u8 *)((char *)obj + 0x36)) / lbl_803E6710;
            } else {
                *(u8 *)((char *)inner + 0xaa) &= ~0x40;
            }
            objParticleFn_80099d84(obj, lbl_803E670C, 3, *(f32 *)((char *)inner + 0xac), 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
