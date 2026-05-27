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
