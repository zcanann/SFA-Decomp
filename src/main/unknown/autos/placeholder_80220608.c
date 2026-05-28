#include "ghidra_import.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"

/* Pattern wrappers. */
extern byte framesThisStep;
extern int lbl_803DC380;
extern f32 lbl_803E6BB0;
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int *objFindTexture(int obj, int textureIndex, int materialIndex);
extern void mm_free(void *ptr);
extern int GameBit_Get(int id);
extern void Obj_FreeObject(int obj);
extern f32 lbl_803E6BC8;
extern void fn_8009436C(int obj);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void ObjGroup_RemoveObject(int obj, int group);
extern void ObjGroup_AddObject(int obj, int group);
extern f32 lbl_803E6C20;
extern int lbl_803DC398;
extern void storeZeroToFloatParam(void *timer);
extern void s16toFloat(void *timer, int duration);
extern void gunpowderbarrel_clearHeldState(int obj);
extern f32 lbl_803E6CE0;
extern void dll_2E_func06(int obj, int state, int flags);
extern int seqFn_800394a0(void);
extern void fn_8003AAE0(int obj, int seq, int hitId, int p4, int p5);
extern f32 lbl_803E6D38;
extern f32 lbl_803E6D54;
extern f32 lbl_803E6DA0;
extern f32 lbl_803E6DE0;
extern f32 lbl_803E6DF0;
extern f32 lbl_803E6E00;
extern f32 lbl_803E6DFC;
extern f32 lbl_803E6E10;
extern f32 lbl_803E6E14;
extern f32 lbl_803E6E18;
extern f32 lbl_803E6E20;
extern f32 lbl_803E6E24;
extern f32 timeDelta;
extern int *gMapEventInterface;
extern int *gPartfxInterface;
extern int *gObjectTriggerInterface;
extern int isGameTimerDisabled(void);
extern void GameBit_Set(int id, int value);
extern int randomGetRange(int min, int max);
extern void ObjHitbox_SetStateIndex(int obj, int hitbox, int stateIndex);
extern int Obj_GetActiveModel(int obj);
extern void ObjModel_SetPostRenderCallback(int model, void *callback);
extern void objRenderFn_80041018(int obj);
extern void fn_800284CC(void);

int drenergydisc_getExtraSize(void) { return 1; }
int drenergydisc_getObjectTypeId(void) { return 0; }
void drenergydisc_free(void) {}
void drenergydisc_render(void) {}
void drenergydisc_hitDetect(void) {}

typedef struct DrEnergyDiscState {
    u8 activated : 1;
} DrEnergyDiscState;

#pragma peephole off
#pragma scheduling off
void drenergydisc_update(int obj)
{
    int *texture;
    DrEnergyDiscState *state = *(DrEnergyDiscState **)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        if (state->activated == 0) {
            state->activated = 1;
            Sfx_PlayFromObject(obj, 0x30c);
        }

        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *texture = 0x100;
        }

        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *(s16 *)((char *)texture + 0xa) =
                *(s16 *)((char *)texture + 0xa) + lbl_803DC380 * framesThisStep;
            if (*(s16 *)((char *)texture + 0xa) < -0x1000) {
                *(s16 *)((char *)texture + 0xa) = 0;
            }
        }
    }

    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E6BB0, 0);
    }
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void drenergydisc_init(u8 *obj, u8 *setup)
{
    int *texture;
    DrEnergyDiscState *state = *(DrEnergyDiscState **)(obj + 0xb8);
    s16 objType;

    objType = (s16)((s8)setup[0x18] << 8);
    *(s16 *)obj = objType;
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        state->activated = 1;
        Sfx_PlayFromObject((int)obj, 0x30c);
        texture = objFindTexture((int)obj, 0, 0);
        if (texture != NULL) {
            *texture = 0x100;
        }
    } else {
        state->activated = 0;
        texture = objFindTexture((int)obj, 0, 0);
        if (texture != NULL) {
            *texture = 0;
        }
    }
    *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x6000);
}
#pragma scheduling on
#pragma peephole on

void drenergydisc_release(void) {}
void drenergydisc_initialise(void) {}

int drlightbea_getExtraSize(void) { return 0xc; }
int drlightbea_getObjectTypeId(void) { return 0; }
void drlightbea_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    void *buffer = *(void **)state;

    if (buffer != NULL) {
        mm_free(buffer);
        *(void **)state = NULL;
    }
}

void drlightbea_hitDetect(void) {}
void drlightbea_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if ((*(u8 *)(state + 4) & 0x40) != 0) {
        Obj_FreeObject(obj);
    }
}

void drlightbea_init(int obj)
{
    int state = *(int *)(obj + 0xb8);
    *(u8 *)(state + 4) &= 0x7f;
    *(void **)state = NULL;
    *(u8 *)(state + 4) &= 0xbf;
}

void drlightbea_release(void) {}
void drlightbea_initialise(void) {}

int drmusiccont_getExtraSize(void) { return 4; }
int drmusiccont_getObjectTypeId(void) { return 0; }
void drmusiccont_free(int obj) { fn_8009436C(obj); }
void drmusiccont_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6BC8);
    }
}
void drmusiccont_hitDetect(void) {}
void drmusiccont_release(void) {}
void drmusiccont_initialise(void) {}

int drcloudper_getExtraSize(void) { return 0x10; }
int drcloudper_getObjectTypeId(void) { return 0; }
void drcloudper_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0x13);
    ObjGroup_RemoveObject(obj, 0x39);
}
void drcloudper_render(void) {}
void drcloudper_hitDetect(void) {}
void drcloudper_update(void) {}
void drcloudper_release(void) {}
void drcloudper_initialise(void) {}

int drearthcal_setScale(void) { return 1; }
int drearthcal_getExtraSize(void) { return 1; }
int drearthcal_getObjectTypeId(void) { return 0; }
void drearthcal_free(void) {}
void drearthcal_render(void) {}
void drearthcal_hitDetect(void) {}
void drearthcal_init(int obj, int setup)
{
    *(s16 *)obj = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    *(u16 *)(obj + 0xb0) |= 0x6000;
}
void drearthcal_release(void) {}
void drearthcal_initialise(void) {}

int barrelgener_getLinkId(int obj)
{
    obj = *(int *)(obj + 0x4c);
    return (s8)*(u8 *)(obj + 0x19);
}
#pragma scheduling off
void barrelgener_queueObjectRelease(int obj, int queuedObj, int releaseFrame)
{
    int state = *(int *)(obj + 0xb8);

    *(int *)state = queuedObj;
    *(u8 *)(state + 4) = 0;
    storeZeroToFloatParam((void *)(state + 8));
    s16toFloat((void *)(state + 8), (s16)(releaseFrame - lbl_803DC398));
}
#pragma scheduling on
int barrelgener_getExtraSize(void) { return 0x10; }
int barrelgener_getObjectTypeId(void) { return 0; }
#pragma scheduling off
void barrelgener_free(int obj) { ObjGroup_RemoveObject(obj, 0x3a); }
#pragma scheduling on
#pragma peephole off
void barrelgener_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6C20);
    }
}
#pragma peephole on
void barrelgener_hitDetect(void) {}
#pragma scheduling off
void barrelgener_init(int obj)
{
    int state = *(int *)(obj + 0xb8);

    ObjGroup_AddObject(obj, 0x3a);
    *(u8 *)(state + 4) = 0;
    *(void **)state = NULL;
    storeZeroToFloatParam((void *)(state + 8));
}
#pragma scheduling on
void barrelgener_release(void) {}
void barrelgener_initialise(void) {}

int drbarrelgr_getExtraSize(void) { return 0x12c; }
int drbarrelgr_getObjectTypeId(void) { return 0; }
void drbarrelgr_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    void *heldObj = *(void **)(state + 8);

    if (heldObj != NULL) {
        u8 flags;
        int clear = 0;

        gunpowderbarrel_clearHeldState((int)heldObj);
        flags = *(u8 *)(state + 0x12a);
        flags = (flags & 0x7f) | ((clear & 1) << 7);
        *(u8 *)(state + 0x12a) = flags;
    }
}
void drbarrelgr_hitDetect(void) {}
void drbarrelgr_release(void) {}
void drbarrelgr_initialise(void) {}

int earthwalker_getExtraSize(void) { return 0x660; }
int earthwalker_getObjectTypeId(void) { return 0; }
void earthwalker_free(void) {}
#pragma scheduling off
#pragma peephole off
void earthwalker_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int *)(obj + 0xb8);

    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6CE0);
        dll_2E_func06(obj, state, 0);
    }
}
#pragma peephole on
#pragma scheduling on
#pragma scheduling off
void earthwalker_hitDetect(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(s16 *)(obj + 0xa0) == 0x203) {
        fn_8003AAE0(obj, seqFn_800394a0(), *(u8 *)(state + 0x610), 0, 0x186a0);
    }
}
#pragma scheduling on
void earthwalker_release(void) {}
void earthwalker_initialise(void) {}

int wcbouncycra_getExtraSize(void) { return 0xc; }
int wcbouncycra_getObjectTypeId(void) { return 0; }
void wcbouncycra_free(void) {}
#pragma peephole off
void wcbouncycra_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6D38);
    }
}
#pragma peephole on
void wcbouncycra_hitDetect(void) {}
#pragma scheduling off
void wcbouncycra_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    *(f32 *)state = *(f32 *)(setup + 0xc);
    *(s16 *)(state + 8) = 0x28;
}
#pragma scheduling on
void wcbouncycra_release(void) {}
void wcbouncycra_initialise(void) {}

int wcpushblock_getExtraSize(void) { return 0x288; }
#pragma scheduling off
int wcpushblock_getObjectTypeId(int obj)
{
    int modelIndex = (s8)*(u8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
}
#pragma scheduling on
void wcpushblock_free(void) {}
#pragma peephole off
void wcpushblock_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6D54);
    }
}
#pragma peephole on
void wcpushblock_hitDetect(void) {}
#pragma scheduling off
void wcpushblock_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    *(u8 *)(obj + 0x36) = 0;
    *(u8 *)(obj + 0xad) = *(u8 *)(setup + 0x19);
    if ((s8)*(u8 *)(obj + 0xad) >= (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }
    ObjHitbox_SetStateIndex(obj, *(int *)(obj + 0x54), (s8)*(u8 *)(obj + 0xad));
    *(u8 *)(state + 0x283) = (u8)*(s16 *)(setup + 0x1a);
    *(f32 *)(state + 0x274) = lbl_803E6DA0 + *(f32 *)(setup + 0xc);
}
#pragma scheduling on
void wcpushblock_release(void) {}
void wcpushblock_initialise(void) {}

#pragma scheduling off
int wcbeacon_aButtonCallback(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (isGameTimerDisabled() == 0) {
        *(u8 *)(state + 5) = 1;
        GameBit_Set(*(s16 *)(setup + 0x1e), 1);
    }
    return 1;
}
#pragma scheduling on

int wcbeacon_getExtraSize(void) { return 8; }
#pragma scheduling off
int wcbeacon_getObjectTypeId(int obj)
{
    int modelIndex = (s8)*(u8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
}
#pragma scheduling on
#pragma peephole off
void wcbeacon_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6DE0);
    }
}
#pragma peephole on
#pragma peephole off
#pragma scheduling off
void wcbeacon_init(u8 *obj, u8 *setup)
{
    u8 *state = *(u8 **)(obj + 0xb8);
    s16 objType;

    (*(void (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac));
    objType = (s16)((s8)setup[0x18] << 8);
    *(s16 *)obj = objType;
    obj[0xad] = setup[0x19];
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        obj[0xad] = 0;
    }
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
            state[4] = 3;
        } else {
            state[4] = 1;
        }
    }
}
#pragma scheduling on
#pragma peephole on

int wctile_getExtraSize(void) { return 0xc; }
#pragma scheduling off
int wctile_getObjectTypeId(int obj)
{
    int modelIndex = (s8)*(u8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
}
#pragma scheduling on
void wctile_free(void) {}
#pragma peephole off
void wctile_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6DF0);
    }
}
#pragma peephole on
void wctile_hitDetect(void) {}
#pragma peephole off
#pragma scheduling off
void wctile_init(u8 *obj, u8 *setup)
{
    u8 *state = *(u8 **)(obj + 0xb8);

    *(f32 *)(obj + 0x10) = lbl_803E6DFC + *(f32 *)(setup + 0xc);
    obj[0xad] = setup[0x19];
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        obj[0xad] = 0;
    }
    *(s16 *)(state + 8) = *(s16 *)(setup + 0x1a);
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel((int)obj), fn_800284CC);
    obj[0x36] = 0;
}
#pragma scheduling on
#pragma peephole on
void wctile_release(void) {}
void wctile_initialise(void) {}

int wcpressures_getExtraSize(void) { return 0x7c; }
#pragma scheduling off
int wcpressures_tileStateCallback(int obj, int unused, int callbackData)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    u8 i;

    if (*(u8 *)(callbackData + 0x80) == 1) {
        for (i = 0; i < 10; i++) {
            int tile = *(int *)(state + 4 + i * 4);

            if (tile != 0) {
                *(f32 *)(state + 0x2c + i * 8) = *(f32 *)(tile + 0xc);
                *(f32 *)(state + 0x30 + i * 8) = *(f32 *)(tile + 0x14);
            }
        }
        *(u8 *)(callbackData + 0x80) = 0;
    } else if (*(u8 *)(callbackData + 0x80) == 2) {
        for (i = 0; i < 10; i++) {
            *(int *)(state + 4 + i * 4) = 0;
        }
        *(f32 *)(obj + 0x14) = *(f32 *)(setup + 8);
        *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc);
        *(f32 *)(obj + 0x14) = *(f32 *)(setup + 0x10);
        GameBit_Set(*(s16 *)(setup + 0x1a), 0);
        *(u8 *)(callbackData + 0x80) = 0;
    }

    return 0;
}
#pragma scheduling on

#pragma scheduling off
int wcpressures_getObjectTypeId(int obj)
{
    int modelIndex = *(u8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
}
#pragma scheduling on
#pragma scheduling off
void wcpressures_free(int obj) { ObjGroup_RemoveObject(obj, 0x31); }
#pragma scheduling on
#pragma peephole off
void wcpressures_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E00);
    }
}
#pragma peephole on
void wcpressures_hitDetect(void) {}
#pragma peephole off
#pragma scheduling off
void wcpressures_init(u8 *obj, u8 *setup)
{
    u8 *state = *(u8 **)(obj + 0xb8);
    s16 objType;
    u16 objFlags;
    s8 modelIndex;
    int i;

    objType = (s16)(setup[0x18] << 8);
    *(s16 *)obj = objType;
    objFlags = *(u16 *)(obj + 0xb0) | 0x6000;
    *(u16 *)(obj + 0xb0) = objFlags;
    modelIndex = (s8)setup[0x19];
    *(s8 *)(obj + 0xad) = modelIndex;
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        obj[0xad] = 0;
    }

    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1a)) != 0) {
        *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc) - (f32)*(u8 *)(setup + 0x1c);
        state[0] = 0x1e;
        state[1] = 2;
    }

    ObjGroup_AddObject((int)obj, 0x31);
    for (i = 0; i < 10; i++) {
        *(int *)(state + 4 + i * 4) = 0;
    }
    *(void **)(obj + 0xbc) = wcpressures_tileStateCallback;
}
#pragma scheduling on
#pragma peephole on
void wcpressures_release(void) {}
void wcpressures_initialise(void) {}

#pragma scheduling off
int wctrexstatu_interactCallback(int obj, int unused, int callbackData)
{
    int i;

    for (i = 0; i < *(u8 *)(callbackData + 0x8b); i++) {
        if (*(u8 *)(callbackData + 0x81 + i) == 1) {
            int *texture = objFindTexture(obj, 0, 0);

            if (texture != NULL) {
                *texture = 0x100;
            }
            *(int *)(obj + 0xf4) = 1;
        }
    }

    return 0;
}
#pragma scheduling on

int wctrexstatu_getExtraSize(void) { return 0; }
#pragma scheduling off
int wctrexstatu_getObjectTypeId(int obj)
{
    int modelIndex = (s8)*(u8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
}
#pragma scheduling on
void wctrexstatu_free(void) {}
#pragma peephole off
void wctrexstatu_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E10);
    }
}
#pragma peephole on
#pragma peephole off
#pragma scheduling off
void wctrexstatu_hitDetect(u8 *obj)
{
    if (*(int *)(obj + 0xf4) != 0 && randomGetRange(0, 5) == 0) {
        if (*(s8 *)(obj + 0xad) == 0) {
            (*(void (**)(u8 *, int, int, int, int, u8 *))(*gPartfxInterface + 8))(obj, 0x73f, 0, 2, -1, obj);
        } else {
            (*(void (**)(u8 *, int, int, int, int, u8 *))(*gPartfxInterface + 8))(obj, 0x740, 0, 2, -1, obj);
        }
    }
}
#pragma scheduling on
#pragma peephole on
void wctrexstatu_update(void) {}
#pragma scheduling off
void wctrexstatu_init(int obj, int setup, int fromLoad)
{
    *(void **)(obj + 0xbc) = wctrexstatu_interactCallback;
    *(u8 *)(obj + 0xad) = *(u8 *)(setup + 0x19);
    if ((s8)*(u8 *)(obj + 0xad) >= (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }

    *(s16 *)obj = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    if (fromLoad == 0) {
        if ((u32)(*(int (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) == 2) {
            *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) + lbl_803E6E14;
        }
    }

    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        int *texture = objFindTexture(obj, 0, 0);

        if (texture != NULL) {
            *texture = 0x100;
        }
        *(int *)(obj + 0xf4) = 1;
    }
}
#pragma scheduling on
void wctrexstatu_release(void) {}
void wctrexstatu_initialise(void) {}

int suntemple_getExtraSize(void) { return 2; }
int suntemple_getObjectTypeId(void) { return 0; }
void suntemple_free(void) {}
#pragma peephole off
void suntemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E18);
    }
}
#pragma peephole on
#pragma peephole off
void suntemple_hitDetect(int obj)
{
    if ((*(u32 *)(*(int *)(obj + 0x50) + 0x44) & 1) != 0 && *(void **)(obj + 0x74) != NULL) {
        objRenderFn_80041018(obj);
    }
}
#pragma peephole on
void suntemple_release(void) {}
void suntemple_initialise(void) {}

int wctemple_getExtraSize(void) { return 8; }
int wctemple_getObjectTypeId(void) { return 0; }
void wctemple_free(void) {}
#pragma peephole off
void wctemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E20);
    }
}
#pragma peephole on
void wctemple_hitDetect(void) {}
#pragma scheduling off
#pragma peephole off
void wctemple_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    *(f32 *)state -= timeDelta;
    if (*(f32 *)state < lbl_803E6E24) {
        *(f32 *)state = lbl_803E6E24;
    }

    if (*(u8 *)(state + 4) == 0) {
        if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
            *(u8 *)(state + 4) = 1;
        }
    } else {
        if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
            *(u8 *)(state + 4) = 0;
        }
    }
}
#pragma peephole on
#pragma scheduling on
#pragma peephole off
void wctemple_init(int obj, int setup)
{
    int angle = (s8)*(u8 *)(setup + 0x18);

    *(s16 *)obj = (s16)(angle << 8);
}
#pragma peephole on
void wctemple_release(void) {}
void wctemple_initialise(void) {}

int fn_80223BBC(void) { return 0x2; }
int fn_80223D10(void) { return 0x2; }
int dll_28B_getExtraSize_ret_2756(void) { return 0xac4; }
int dll_28B_getObjectTypeId(void) { return 0x0; }
void dll_28B_hitDetect_nop(void) {}
void dll_28B_release_nop(void) {}
int dll_299_getExtraSize_ret_2(void) { return 0x2; }
int dll_299_getObjectTypeId(void) { return 0x0; }
void dll_299_render_nop(void) {}
void dll_299_hitDetect_nop(void) {}
void dll_299_release_nop(void) {}
void dll_299_initialise_nop(void) {}
int Dummy29E_getExtraSize(void) { return 0x0; }
int Dummy29E_getObjectTypeId(void) { return 0x0; }
void Dummy29E_free(void) {}
void Dummy29E_render(void) {}
void Dummy29E_hitDetect(void) {}
void Dummy29E_update(void) {}
void Dummy29E_init(void) {}
void Dummy29E_release(void) {}
void Dummy29E_initialise(void) {}
int dll_2A3_getExtraSize_ret_12(void) { return 0xc; }
int dll_2A3_getObjectTypeId(void) { return 0x0; }
void dll_2A3_release_nop(void) {}
void dll_2A3_initialise_nop(void) {}
int dll_2A4_getExtraSize_ret_12(void) { return 0xc; }
int dll_2A4_getObjectTypeId(void) { return 0x0; }
void dll_2A4_free_nop(void) {}
void dll_2A4_hitDetect_nop(void) {}
void dll_2A4_release_nop(void) {}
void dll_2A4_initialise_nop(void) {}

extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int lbl_803DDD90;
extern int lbl_803DDD94;
extern f32 lbl_803E7118;
extern f32 lbl_803E711C;
extern f32 lbl_803E7120;
extern f32 lbl_803E7124;

void dll_2A3_free(void) { lbl_803DDD90 = lbl_803DDD90 - 1; }

void dll_2A3_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7118);
}

void dll_2A3_hitDetect(void) { lbl_803DDD94 = 0; }

#pragma peephole off
#pragma scheduling off
void dll_2A3_update(int obj)
{
    f32 v;
    int state = *(int *)(obj + 0xb8);

    if (*(f32 *)state > lbl_803E711C) {
        *(f32 *)state -= timeDelta;
        if (*(f32 *)state <= lbl_803E711C) {
            *(f32 *)state = lbl_803E711C;
            Obj_FreeObject(obj);
            return;
        }
    }

    v = (f32)(u32) * (u8 *)(obj + 0x36) + lbl_803E7120 * timeDelta;
    if (v > lbl_803E7124) {
        v = lbl_803E7124;
    }
    *(u8 *)(obj + 0x36) = (u8)v;

    *(s16 *)(obj + 0) = (s16)((f32) * (s16 *)(state + 4) * timeDelta + (f32) * (s16 *)(obj + 0));
    *(s16 *)(obj + 2) = (s16)((f32) * (s16 *)(state + 6) * timeDelta + (f32) * (s16 *)(obj + 2));
    *(s16 *)(obj + 4) = (s16)((f32) * (s16 *)(state + 8) * timeDelta + (f32) * (s16 *)(obj + 4));

    objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
            *(f32 *)(obj + 0x2c) * timeDelta);

    if (lbl_803DDD94 == 0) {
        lbl_803DDD94 = 1;
    }
}

void dll_2A3_init(int obj)
{
    int state = *(int *)(obj + 0xb8);

    *(u8 *)(obj + 0x36) = 0;
    *(s16 *)(obj + 0) = randomGetRange(0, 0xffff);
    *(s16 *)(obj + 2) = randomGetRange(0, 0xffff);
    *(s16 *)(obj + 4) = randomGetRange(0, 0xffff);
    *(s16 *)(state + 4) = randomGetRange(-0x32, 0x32);
    *(s16 *)(state + 6) = randomGetRange(-0x32, 0x32);
    *(s16 *)(state + 8) = randomGetRange(-0x32, 0x32);
    lbl_803DDD90 = lbl_803DDD90 + 1;
}
#pragma scheduling on
#pragma peephole on

extern f32 lbl_803E7138;
extern f32 lbl_803E713C;

void dll_2A4_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7138);
}

#pragma peephole off
#pragma scheduling off
void dll_2A4_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(f32 *)state > lbl_803E713C) {
        *(f32 *)state -= timeDelta;
        if (*(f32 *)state <= lbl_803E713C) {
            *(f32 *)state = lbl_803E713C;
            Obj_FreeObject(obj);
            return;
        }
    }

    *(s16 *)(obj + 0) = (s16)((f32) * (s16 *)(state + 4) * timeDelta + (f32) * (s16 *)(obj + 0));
    *(s16 *)(obj + 2) = (s16)((f32) * (s16 *)(state + 6) * timeDelta + (f32) * (s16 *)(obj + 2));
    *(s16 *)(obj + 4) = (s16)((f32) * (s16 *)(state + 8) * timeDelta + (f32) * (s16 *)(obj + 4));

    objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
            *(f32 *)(obj + 0x2c) * timeDelta);
}

void dll_2A4_init(int obj)
{
    int state = *(int *)(obj + 0xb8);

    *(s16 *)(obj + 0) = randomGetRange(0, 0xffff);
    *(s16 *)(obj + 2) = randomGetRange(0, 0xffff);
    *(s16 *)(obj + 4) = randomGetRange(0, 0xffff);
    *(s16 *)(state + 4) = randomGetRange(-0x14, 0x14);
    *(s16 *)(state + 6) = randomGetRange(-0x14, 0x14);
    *(s16 *)(state + 8) = randomGetRange(-0x14, 0x14);
}
#pragma scheduling on
#pragma peephole on

typedef struct PointLightVec { f32 x, y, z; } PointLightVec;

extern f32 lbl_802C25F8[];
extern f32 lbl_803E7230;
extern f32 lbl_803E7234;
extern f32 lbl_803E7240;
extern void ModelLightStruct_free(void *light);
extern void lightFn_8001db6c(void *light, int flag, f32 val);
extern void queueGlowRender(void *light);
extern void getAmbientColor(int id, u8 *r, u8 *g, u8 *b);
extern void modelLightStruct_setColorsA8AC(void *light, u8 r, u8 g, u8 b, int a);
extern void lightSetFieldB0(void *light, u8 r, u8 g, u8 b, int a);
extern void lightFn_8001d6b0(void *light);
extern void *objCreateLight(int obj, int kind);
extern void modelLightStruct_setField50(void *light, int v);
extern void objSetEventName(void *light, int name);
extern void lightVecFn_8001dd88(void *light, f32 x, f32 y, f32 z);
extern void lightDistAttenFn_8001dc38(void *light, f32 near, f32 far);
extern void fn_8001DA60(void *light, f32 v, int x);
extern void lightFn_8001d620(void *light, int a, s16 b);
extern void modelStruct2_setVectors(void *light, f32 x, f32 y, f32 z);
extern void Obj_SetActiveModelIndex(int obj, int index);
extern void fn_8001D730(void *light, u16 a, u8 b, u8 c, u8 d, u8 e, f32 f);
extern void fn_8001D714(void *light, f32 v);
extern void lightSetField2FB(void *light, int v);
extern void fn_8001DB5C(void *light);

int pointlight_getExtraSize(void) { return 8; }
int pointlight_getObjectTypeId(void) { return 0; }

#pragma dont_inline on
void pointlight_setEffectState(int obj, int flag)
{
    void *light = *(void **)*(int *)(obj + 0xb8);
    if (light != NULL) {
        lightFn_8001db6c(light, flag, lbl_803E7230);
    }
}
#pragma dont_inline reset

void pointlight_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)state != NULL) {
        ModelLightStruct_free(*(void **)state);
    }
    ObjGroup_RemoveObject(obj, 0x35);
}

void pointlight_render(int obj)
{
    void *light = *(void **)*(int *)(obj + 0xb8);
    if (light != NULL && *(u8 *)((char *)light + 0x2f8) != 0 &&
        *(u8 *)((char *)light + 0x4c) != 0) {
        queueGlowRender(light);
    }
}

void pointlight_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void pointlight_update(int obj)
{
    u8 colorR, colorG, colorB;
    int setup = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);

    if (*(void **)state == NULL) {
        return;
    }

    *(s16 *)(obj + 0) =
        (s16)((f32)*(s16 *)(setup + 0x32) * timeDelta + (f32)*(s16 *)(obj + 0));
    *(s16 *)(obj + 2) =
        (s16)((f32)*(s16 *)(setup + 0x34) * timeDelta + (f32)*(s16 *)(obj + 2));

    if (*(u8 *)(state + 4) != 0) {
        s16 bit = *(s16 *)(setup + 0x1e);
        if (bit > 0 && (u32)GameBit_Get(bit) == 0) {
            *(u8 *)(state + 4) = 0;
            lightFn_8001db6c(*(void **)state, 0, lbl_803E7234);
        }
        if ((*(u8 *)(setup + 0x2a) & 1) != 0) {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setColorsA8AC(*(void **)state, colorR, colorG, colorB, 0xff);
            lightSetFieldB0(*(void **)state, colorR, colorG, colorB, 0xff);
        }
    } else {
        s16 bit = *(s16 *)(setup + 0x1e);
        if (bit > 0 && (u32)GameBit_Get(bit) != 0) {
            *(u8 *)(state + 4) = 1;
            lightFn_8001db6c(*(void **)state, 1, lbl_803E7234);
        }
    }

    if (*(void **)state != NULL) {
        lightFn_8001d6b0(*(void **)state);
    }
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void pointlight_init(int obj, int setup)
{
    u8 colorR, colorG, colorB;
    PointLightVec vec;
    int state = *(int *)(obj + 0xb8);

    vec = *(PointLightVec *)lbl_802C25F8;

    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);

    if (*(void **)state == NULL) {
        *(void **)state = objCreateLight(obj, 1);
    }

    if (*(void **)state != NULL) {
        modelLightStruct_setField50(*(void **)state, 2);
        objSetEventName(*(void **)state, *(u8 *)(setup + 0x1d));
        lightVecFn_8001dd88(*(void **)state, lbl_803E7230, lbl_803E7230, lbl_803E7230);

        if ((*(u8 *)(setup + 0x2a) & 1) != 0) {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setColorsA8AC(*(void **)state, colorR, colorG, colorB, 0xff);
            lightSetFieldB0(*(void **)state, colorR, colorG, colorB, 0xff);
        } else {
            modelLightStruct_setColorsA8AC(*(void **)state, *(u8 *)(setup + 0x1a),
                *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c), 0xff);
            lightSetFieldB0(*(void **)state, *(u8 *)(setup + 0x27),
                *(u8 *)(setup + 0x28), *(u8 *)(setup + 0x29), 0xff);
        }

        lightDistAttenFn_8001dc38(*(void **)state, (f32)(u32)*(u16 *)(setup + 0x22),
            (f32)(u32)*(u16 *)(setup + 0x24));

        {
            u8 brightness = *(u8 *)(setup + 0x20);
            if (brightness >= 0x5a) {
                brightness = 0x5a;
            }
            fn_8001DA60(*(void **)state, (f32)brightness, *(u8 *)(setup + 0x21));
        }

        lightFn_8001db6c(*(void **)state, *(u8 *)(setup + 0x30), lbl_803E7230);
        *(u8 *)(state + 4) = *(u8 *)(setup + 0x30);
        lightFn_8001d620(*(void **)state, *(u8 *)(setup + 0x26), *(s16 *)(setup + 0x2e));
        modelStruct2_setVectors(*(void **)state, vec.x, vec.y, vec.z);

        if (*(u8 *)(setup + 0x21) != 0) {
            Obj_SetActiveModelIndex(obj, 1);
        } else {
            Obj_SetActiveModelIndex(obj, 0);
        }

        if (*(u8 *)(setup + 0x3e) != 0) {
            fn_8001D730(*(void **)state, *(u16 *)(setup + 0x38), *(u8 *)(setup + 0x3a),
                *(u8 *)(setup + 0x3b), *(u8 *)(setup + 0x3c), *(u8 *)(setup + 0x3d),
                (f32)(u32)*(u16 *)(setup + 0x36));
            fn_8001D714(*(void **)state, lbl_803E7240);
        }

        if (*(u8 *)(setup + 0x3f) != 0) {
            lightSetField2FB(*(void **)state, 1);
        }

        if (*(u8 *)(setup + 0x2c) != 0) {
            fn_8001DB5C(*(void **)state);
        }
    }

    ObjGroup_AddObject(obj, 0x35);
}
#pragma scheduling on
#pragma peephole on

void pointlight_release(void) {}
void pointlight_initialise(void) {}

extern f32 lbl_802C2608[];
extern f32 lbl_803E7250;
extern f32 lbl_803E7254;
extern u8 gDirectionalLightObjDescriptor[];
extern int getButtonsJustPressed(int controller);
extern void fn_80137948(void *fmt, ...);

int directionallight_getExtraSize(void) { return 0x10; }
int directionallight_getObjectTypeId(void) { return 0; }

void directionallight_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 8) != NULL) {
        ModelLightStruct_free(*(void **)(state + 8));
    }
}

void directionallight_hitDetect(void) {}

void directionallight_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7254);
}

#pragma peephole off
#pragma scheduling off
void directionallight_debugEdit(int obj, int state)
{
    u8 *desc = gDirectionalLightObjDescriptor;
    u16 buttons = (u16)getButtonsJustPressed(0);

    if ((buttons & 0x10) != 0) {
        *(u8 *)(state + 0xc) ^= 1;
    }
    if (*(u8 *)(state + 0xc) == 0) {
        return;
    }
    if ((buttons & 8) != 0) {
        *(u8 *)(state + 0xd) += 1;
    }
    if ((buttons & 4) != 0) {
        *(u8 *)(state + 0xd) -= 1;
    }
    if ((s8)*(u8 *)(state + 0xd) >= 8) {
        *(u8 *)(state + 0xd) = 0;
    }
    if ((s8)*(u8 *)(state + 0xd) < 0) {
        *(u8 *)(state + 0xd) = 7;
    }

    switch ((s8)*(u8 *)(state + 0xd)) {
    case 0:
        if ((buttons & 1) != 0) {
            *(s16 *)(obj + 0) -= 0x3e8;
        }
        if ((buttons & 2) != 0) {
            *(s16 *)(obj + 0) += 0x3e8;
        }
        fn_80137948(desc + 0x38);
        fn_80137948(desc + 0x44, *(s16 *)(obj + 0));
        break;
    case 1:
        if ((buttons & 1) != 0) {
            *(s16 *)(obj + 2) -= 0x3e8;
        }
        if ((buttons & 2) != 0) {
            *(s16 *)(obj + 2) += 0x3e8;
        }
        fn_80137948(desc + 0x50);
        fn_80137948(desc + 0x44, *(s16 *)(obj + 2));
        break;
    case 2:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 0) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 0) += 5;
        }
        fn_80137948(desc + 0x60);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 0));
        break;
    case 3:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 1) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 1) += 5;
        }
        fn_80137948(desc + 0x88);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 1));
        break;
    case 4:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 2) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 2) += 5;
        }
        fn_80137948(desc + 0xa4);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 2));
        break;
    case 5:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 4) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 4) += 5;
        }
        fn_80137948(desc + 0xc0);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 4));
        break;
    case 6:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 5) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 5) += 5;
        }
        fn_80137948(desc + 0xdc);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 5));
        break;
    case 7:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 6) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 6) += 5;
        }
        fn_80137948(desc + 0xfc);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 6));
        break;
    }
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void directionallight_init(int obj, int setup)
{
    u8 colorR, colorG, colorB;
    PointLightVec vec;
    int state = *(int *)(obj + 0xb8);

    vec = *(PointLightVec *)lbl_802C2608;

    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);

    if (*(void **)(state + 8) == NULL) {
        *(void **)(state + 8) = objCreateLight(obj, 1);
    }

    if (*(void **)(state + 8) != NULL) {
        modelLightStruct_setField50(*(void **)(state + 8), 4);
        objSetEventName(*(void **)(state + 8), *(u8 *)(setup + 0x1d));
        modelStruct2_setVectors(*(void **)(state + 8), vec.x, vec.y, vec.z);

        if ((*(u8 *)(setup + 0x2a) & 1) != 0) {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setColorsA8AC(*(void **)(state + 8), colorR, colorG, colorB, 0xff);
            lightSetFieldB0(*(void **)(state + 8), colorR, colorG, colorB, 0xff);
        } else {
            modelLightStruct_setColorsA8AC(*(void **)(state + 8), *(u8 *)(setup + 0x1a),
                *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c), 0xff);
            lightSetFieldB0(*(void **)(state + 8), *(u8 *)(setup + 0x27),
                *(u8 *)(setup + 0x28), *(u8 *)(setup + 0x29), 0xff);
        }

        lightFn_8001db6c(*(void **)(state + 8), *(u8 *)(setup + 0x30), lbl_803E7250);
        *(u8 *)(state + 0xe) = *(u8 *)(setup + 0x30);
        lightFn_8001d620(*(void **)(state + 8), *(u8 *)(setup + 0x26), *(s16 *)(setup + 0x2e));

        if (*(u8 *)(setup + 0x2c) != 0) {
            fn_8001DB5C(*(void **)(state + 8));
        }
    }
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void directionallight_update(int obj)
{
    u8 colorR, colorG, colorB;
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (*(void **)(state + 8) == NULL) {
        return;
    }

    *(s16 *)(obj + 0) =
        (s16)((f32)*(s16 *)(setup + 0x32) * timeDelta + (f32)*(s16 *)(obj + 0));
    *(s16 *)(obj + 2) =
        (s16)((f32)*(s16 *)(setup + 0x34) * timeDelta + (f32)*(s16 *)(obj + 2));

    if (*(u8 *)(state + 0xe) != 0) {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) == 0) {
            *(u8 *)(state + 0xe) = 0;
            lightFn_8001db6c(*(void **)(state + 8), 0, lbl_803E7254);
        }
        if ((*(u8 *)(setup + 0x2a) & 1) != 0) {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setColorsA8AC(*(void **)(state + 8), colorR, colorG, colorB, 0xff);
        }
    } else {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
            *(u8 *)(state + 0xe) = 1;
            lightFn_8001db6c(*(void **)(state + 8), 1, lbl_803E7254);
        }
    }

    directionallight_debugEdit(obj, state);
}
#pragma scheduling on
#pragma peephole on

void directionallight_release(void) {}
void directionallight_initialise(void) {}

extern f32 lbl_802C2618[];
extern f32 lbl_803E7270;
extern f32 lbl_803E7274;
extern f32 lbl_803E7260;
extern void textureFree(void *tex);
extern void *textureLoadAsset(int id);
extern void fn_8001DB24(void *light, int v);
extern void fn_8001D98C(void *light, void *tex);
extern void fn_8001D8F0(void *light, f32 a, f32 b, f32 c, f32 d, f32 e, f32 f);
extern void fn_8001D878(void *light, f32 a, f32 b);
extern void fn_8001D80C(void *light, int a, int b);
extern void fn_8001D84C(void *light, f32 v);
extern void fn_8001D820(void *light, f32 v);

int projectedlight_getExtraSize(void) { return 8; }
int projectedlight_getObjectTypeId(void) { return 0; }

void projectedlight_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)state != NULL) {
        ModelLightStruct_free(*(void **)state);
    }
    if (*(void **)(state + 4) != NULL) {
        textureFree(*(void **)(state + 4));
    }
}

void projectedlight_hitDetect(void) {}
void projectedlight_render(void) {}

#pragma peephole off
#pragma scheduling off
void projectedlight_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);

    *(s16 *)(obj + 0) =
        (s16)((f32)*(s16 *)(setup + 0x20) * timeDelta + (f32)*(s16 *)(obj + 0));
    *(s16 *)(obj + 2) =
        (s16)((f32)*(s16 *)(setup + 0x22) * timeDelta + (f32)*(s16 *)(obj + 2));
    *(s16 *)(obj + 4) =
        (s16)((f32)(*(s8 *)(setup + 0x35) << 4) * timeDelta + (f32)*(s16 *)(obj + 4));
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void projectedlight_init(int obj, int setup)
{
    PointLightVec vec;
    int state = *(int *)(obj + 0xb8);

    vec = *(PointLightVec *)lbl_802C2618;

    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);
    *(s16 *)(obj + 4) = (s16)(*(u8 *)(setup + 0x34) << 8);

    if (*(void **)state == NULL) {
        *(void **)state = objCreateLight(obj, 1);
    }

    if (*(void **)state != NULL) {
        modelLightStruct_setField50(*(void **)state, 8);
        lightVecFn_8001dd88(*(void **)state, lbl_803E7270, lbl_803E7270, lbl_803E7270);
        modelStruct2_setVectors(*(void **)state, vec.x, vec.y, vec.z);
        modelLightStruct_setColorsA8AC(*(void **)state, *(u8 *)(setup + 0x2d),
            *(u8 *)(setup + 0x2e), *(u8 *)(setup + 0x2f), *(u8 *)(setup + 0x37));
        lightDistAttenFn_8001dc38(*(void **)state, (f32)(u32)*(u16 *)(setup + 0x1a),
            (f32)(u32)*(u16 *)(setup + 0x1c));
        fn_8001DB24(*(void **)state, *(u8 *)(setup + 0x39));
        lightFn_8001db6c(*(void **)state, *(u8 *)(setup + 0x3a), lbl_803E7270);

        if (*(void **)(state + 4) == NULL) {
            if (*(u16 *)(setup + 0x24) != 0) {
                *(void **)(state + 4) = textureLoadAsset(*(u16 *)(setup + 0x24));
            } else {
                *(void **)(state + 4) = textureLoadAsset(0x5dc);
            }
            fn_8001D98C(*(void **)state, *(void **)(state + 4));
        }

        if (*(u8 *)(setup + 0x26) == 0) {
            f32 a = (f32)(u32)*(u16 *)(setup + 0x28) / lbl_803E7274;
            f32 b;
            f32 lo, hi;
            if (a < lbl_803E7260) {
                a = lbl_803E7260;
            }
            b = (f32)(u32)*(u16 *)(setup + 0x2a) / lbl_803E7274;
            if (b < lbl_803E7260) {
                b = lbl_803E7260;
            }
            if (*(u8 *)(setup + 0x3f) != 0) {
                u8 v = *(u8 *)(setup + 0x3f);
                lo = (f32)(v & 0xf);
                hi = (f32)((v >> 4) & 0xf);
            } else {
                lo = lbl_803E7260;
                hi = lo;
            }
            fn_8001D8F0(*(void **)state, b, -b, -a, a, lo, hi);
        } else {
            f32 c = (f32)(u32)*(u16 *)(setup + 0x28) / lbl_803E7274;
            f32 d;
            if (c < lbl_803E7260) {
                c = lbl_803E7260;
            }
            d = (f32)(u32)*(u16 *)(setup + 0x2a) / lbl_803E7274;
            if (d < lbl_803E7260) {
                d = lbl_803E7260;
            }
            fn_8001D878(*(void **)state, (f32)(u32)*(u8 *)(setup + 0x27), c / d);
        }

        fn_8001D80C(*(void **)state, *(u8 *)(setup + 0x36), *(u8 *)(setup + 0x3e));
        fn_8001D84C(*(void **)state, (f32)(u32)*(u8 *)(setup + 0x3b));
        fn_8001D820(*(void **)state, (f32)(u32)*(u16 *)(setup + 0x3c));
        lightFn_8001d620(*(void **)state, *(u8 *)(setup + 0x33), *(s16 *)(setup + 0x1e));
        lightSetFieldB0(*(void **)state, *(u8 *)(setup + 0x30), *(u8 *)(setup + 0x31),
            *(u8 *)(setup + 0x32), *(u8 *)(setup + 0x38));
    }
}
#pragma scheduling on
#pragma peephole on

void projectedlight_release(void) {}
void projectedlight_initialise(void) {}

extern int *ObjGroup_GetObjects(int group, int *count);
extern f32 Vec_distance(int a, int b);

int controllight_getExtraSize(void) { return 0xc; }
int controllight_getObjectTypeId(void) { return 0; }
void controllight_free(void) {}
void controllight_hitDetect(void) {}
void controllight_render(void) {}

#pragma peephole off
#pragma scheduling off
void controllight_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    *(s16 *)(state + 0) = *(s16 *)(setup + 0x1e);
    *(f32 *)(state + 4) = (f32)*(s16 *)(setup + 0x1a);
    *(u8 *)(state + 8) = *(s8 *)(setup + 0x19) % 2;
    *(u8 *)(state + 9) = 0xff;
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void controllight_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    u8 bit = (u8)GameBit_Get(*(s16 *)(state + 0));

    if (bit != *(u8 *)(state + 9)) {
        switch (*(u8 *)(state + 8)) {
        case 0: {
            f32 radius = *(f32 *)(state + 4);
            int count;
            int *objs = ObjGroup_GetObjects(0x35, &count);
            int *p = objs;
            int i;
            for (i = 0; i < count; i++) {
                int o = *p;
                if (Vec_distance(obj + 0x18, o + 0x18) < radius) {
                    pointlight_setEffectState(o, bit);
                }
                p++;
            }
            break;
        }
        case 1: {
            f32 radius = *(f32 *)(state + 4);
            int count;
            int *objs = ObjGroup_GetObjects(0x35, &count);
            int *p = objs;
            int i;
            for (i = 0; i < count; i++) {
                int o = *p;
                if (Vec_distance(obj + 0x18, o + 0x18) < radius) {
                    pointlight_setEffectState(o, !bit);
                }
                p++;
            }
            break;
        }
        }
    }

    *(u8 *)(state + 9) = bit;
}
#pragma scheduling on
#pragma peephole on

void controllight_release(void) {}
void controllight_initialise(void) {}

typedef struct TimerFlags {
    u8 expired : 1;
    u8 manual : 1;
    u8 flag20 : 1;
    u8 pad : 5;
} TimerFlags;

extern f32 lbl_803E7408;
extern f32 lbl_803E7418;
extern f32 lbl_803E7424;
extern void fn_8001CB3C(int p);
extern void gameTimerStop(void);
extern int fn_80080150(int state);
extern void gameTimerInit(int a, int b);
extern void timerSetToCountUp(void);

int timer_getExtraSize(void) { return 0x20; }

void timer_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    ObjGroup_RemoveObject(obj, 0x4c);
    if (*(void **)(state + 4) != NULL) {
        fn_8001CB3C(state + 4);
    }
    gameTimerStop();
}

int timer_hasExpired(int obj)
{
    int state = *(int *)(obj + 0xb8);
    return ((TimerFlags *)(state + 0xd))->expired;
}

int timer_isEffectMode(int obj)
{
    int state = *(int *)(obj + 0xb8);
    return *(u8 *)(state + 0xc) == 2;
}

void timer_clearManualFlags(int obj)
{
    int state = *(int *)(obj + 0xb8);
    ((TimerFlags *)(state + 0xd))->manual = 0;
    ((TimerFlags *)(state + 0xd))->expired = 0;
}

void timer_forceStart(int obj)
{
    int state = *(int *)(obj + 0xb8);
    ((TimerFlags *)(state + 0xd))->manual = 1;
}

#pragma peephole off
#pragma scheduling off
void timer_addDuration(int obj, int duration)
{
    int state = *(int *)(obj + 0xb8);
    if (fn_80080150(state) != 0) {
        *(f32 *)(state + 0) = *(f32 *)(state + 0) + (f32)duration;
        if (*(u8 *)(state + 0xc) == 1) {
            gameTimerInit(0x1d, (int)(*(f32 *)(state + 0) / lbl_803E7408));
            timerSetToCountUp();
        }
    }
}
#pragma scheduling on
#pragma peephole on

void timer_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    void *light = *(void **)(*(int *)(obj + 0xb8) + 4);
    if (light != NULL && *(u8 *)((char *)light + 0x2f8) != 0 &&
        *(u8 *)((char *)light + 0x4c) != 0) {
        queueGlowRender(light);
    }
    if (*(void **)(obj + 0xc4) == NULL) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7418);
    }
}

#pragma peephole off
#pragma scheduling off
void timer_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    storeZeroToFloatParam((void *)state);
    *(u8 *)(state + 0xc) = *(u8 *)(setup + 0x19);
    *(f32 *)(state + 8) = lbl_803E7424;
    ((TimerFlags *)(state + 0xd))->expired = 0;
    ((TimerFlags *)(state + 0xd))->manual = 0;
    *(int *)(state + 4) = 0;
    ObjGroup_AddObject(obj, 0x4c);
    ((TimerFlags *)(state + 0xd))->flag20 = 0;
}
#pragma scheduling on
#pragma peephole on

extern void set_hudNumber_803db278(int n);

int cntcounter_getExtraSize(void) { return 8; }
int cntcounter_getObjectTypeId(void) { return 0; }

void cntcounter_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(u8 *)(state + 4) != 0) {
        set_hudNumber_803db278(-1);
    }
}

void cntcounter_hitDetect(void) {}
void cntcounter_render(void) {}

void cntcounter_init(int obj)
{
    int state = *(int *)(obj + 0xb8);
    *(u8 *)(state + 4) = 0;
    *(int *)(state + 0) = 0;
}

#pragma peephole off
#pragma scheduling off
void cntcounter_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (*(int *)(state + 0) != 0) {
        int bit;
        if (*(u8 *)(state + 4) != 0) {
            set_hudNumber_803db278(*(int *)(state + 0));
        }
        bit = GameBit_Get(*(s16 *)(setup + 0x20));
        if (bit != 0) {
            GameBit_Set(*(s16 *)(setup + 0x20), 0);
            *(int *)(state + 0) -= bit;
            if (*(int *)(state + 0) <= 0) {
                *(int *)(state + 0) = 0;
                GameBit_Set(*(s16 *)(setup + 0x1e), 1);
                if (*(u8 *)(state + 4) != 0) {
                    set_hudNumber_803db278(-1);
                }
                *(u8 *)(state + 4) = 0;
            }
        }
    } else {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
            *(u8 *)(state + 4) = *(u8 *)(setup + 0x19);
            *(int *)(state + 0) = *(s16 *)(setup + 0x1a);
        }
    }
}
#pragma scheduling on
#pragma peephole on

void cntcounter_release(void) {}
void cntcounter_initialise(void) {}

typedef struct VortexFlags {
    u8 active : 1;
    u8 pad : 7;
} VortexFlags;

extern int *gExpgfxInterface;
extern f32 lbl_803E73E0;
extern f32 lbl_803E73D0;
extern f32 lbl_803E7400;

int vortex_getExtraSize(void) { return 0x28; }
int vortex_getObjectTypeId(void) { return 0; }

void vortex_free(int obj)
{
    (*(void (**)(int))(*gExpgfxInterface + 0x18))(obj);
}

void vortex_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void vortex_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    ((VortexFlags *)(state + 0x26))->active = 0;
    if (*(s16 *)(setup + 0x20) != -1) {
        ((VortexFlags *)(state + 0x26))->active = (u8)GameBit_Get(*(s16 *)(setup + 0x20));
    }

    if (*(s16 *)(obj + 0x46) == 0x29a || *(s16 *)(obj + 0x46) == 0x829) {
        if (((VortexFlags *)(state + 0x26))->active != 0) {
            if (*(s16 *)(setup + 0x1e) != -1) {
                ((VortexFlags *)(state + 0x26))->active = !GameBit_Get(*(s16 *)(setup + 0x1e));
            }
        }
    }

    if (((VortexFlags *)(state + 0x26))->active != 0) {
        f32 lim = lbl_803E73E0;
        if (*(f32 *)(state + 0) < lim) {
            *(f32 *)(state + 0) = lbl_803E7400 * timeDelta + *(f32 *)(state + 0);
            if (*(f32 *)(state + 0) > lim) {
                *(f32 *)(state + 0) = lim;
            }
        }
    } else {
        f32 lim = lbl_803E73D0;
        if (*(f32 *)(state + 0) > lim) {
            *(f32 *)(state + 0) = *(f32 *)(state + 0) - lbl_803E7400 * timeDelta;
            if (*(f32 *)(state + 0) < lim) {
                *(f32 *)(state + 0) = lim;
            }
        }
    }
}
#pragma scheduling on
#pragma peephole on

void vortex_release(void) {}
void vortex_initialise(void) {}

extern int fn_8001DB64(void *light);
extern f32 lbl_803E70B0;

int ring_getExtraSize(void) { return 0x24; }
int ring_getObjectTypeId(void) { return 0; }

void ring_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 0x20) != NULL) {
        ModelLightStruct_free(*(void **)(state + 0x20));
        *(void **)(state + 0x20) = NULL;
    }
}

void ring_hitDetect(void) {}

void ring_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 0x20) != NULL && fn_8001DB64(*(void **)(state + 0x20)) != 0) {
        queueGlowRender(*(void **)(state + 0x20));
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E70B0);
}

void ring_release(void) {}
void ring_initialise(void) {}

typedef struct CntHitFlags {
    u8 disabled : 1;
    u8 pad : 7;
} CntHitFlags;

extern f32 lbl_803E7430;
extern void spawnExplosion(int obj, f32 v, int a, int b, int c, int d, int e, int f, int g);
extern void ObjHits_DisableObject(int obj);
extern void ObjHits_EnableObject(int obj);
extern void ObjHitbox_SetSphereRadius(int obj, int radius);

int cnthitobjec_getExtraSize(void) { return 0xc; }
int cnthitobjec_getObjectTypeId(void) { return 0; }
void cnthitobjec_free(void) {}
void cnthitobjec_release(void) {}
void cnthitobjec_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void cnthitobjec_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    if (*(u8 *)(setup + 0x19) == 2 && ((CntHitFlags *)(state + 9))->disabled == 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7430);
    }
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
int cnthitobjec_emitHitEvents(int obj, int p2, int p3)
{
    int i;
    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        spawnExplosion(obj, (f32)(u32)*(u8 *)(p3 + (i + 0x81)), 1, 1, 1, 1, 0, 1, 0);
    }
    return 0;
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void cnthitobjec_update(int obj)
{
    int setup;
    int state = *(int *)(obj + 0xb8);
    setup = *(int *)(obj + 0x4c);

    if (((CntHitFlags *)(state + 9))->disabled == 0) {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
            ((CntHitFlags *)(state + 9))->disabled = 1;
            ObjHits_DisableObject(obj);
        }
    }

    if (((CntHitFlags *)(state + 9))->disabled == 0 && *(int *)(state + 0) == 0 &&
        (u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        ObjHits_EnableObject(obj);
        *(int *)(state + 0) = *(s16 *)(setup + 0x1a);
        if (*(u8 *)(setup + 0x19) != 2) {
            ObjHitbox_SetSphereRadius(obj, *(s16 *)(setup + 0x1c));
        }
    }
}
#pragma scheduling on
#pragma peephole on

int dustmotesou_getExtraSize(void) { return 0; }
int dustmotesou_getObjectTypeId(void) { return 0; }

void dustmotesou_free(int obj)
{
    (*(void (**)(int))(*gExpgfxInterface + 0x18))(obj);
}

void dustmotesou_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void dustmotesou_init(int obj, int setup)
{
    *(s16 *)(obj + 4) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);
    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x1a) << 8);
    *(u16 *)(obj + 0xb0) |= 0x2000;
}
#pragma scheduling on
#pragma peephole on

void dustmotesou_release(void) {}
void dustmotesou_initialise(void) {}

extern f32 lbl_803E7338;
extern f32 lbl_803E733C;
extern f32 lbl_803E7340;
extern int ObjHits_PollPriorityHitEffectWithCooldown(int obj, int a, int b, int c, int d, int e, int state);

int brokenpipe_getExtraSize(void) { return 4; }

#pragma peephole off
#pragma scheduling off
void brokenpipe_init(int obj, int setup)
{
    *(s16 *)(obj + 4) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);
    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x1a) << 8);
    if (*(u8 *)(setup + 0x1b) != 0) {
        *(f32 *)(obj + 8) = (f32)(u32)*(u8 *)(setup + 0x1b) / lbl_803E7338;
        if (*(f32 *)(obj + 8) == lbl_803E733C) {
            *(f32 *)(obj + 8) = lbl_803E7340;
        }
        ObjHitbox_SetSphereRadius(obj,
            (int)((f32)*(s16 *)(*(int *)(obj + 0x54) + 0x5a) * *(f32 *)(obj + 8)));
        *(f32 *)(obj + 8) = *(f32 *)(obj + 8) * *(f32 *)(*(int *)(obj + 0x50) + 4);
    }
    *(u16 *)(obj + 0xb0) |= 0x4000;
}
#pragma scheduling on
#pragma peephole on

#pragma scheduling off
void brokenpipe_update(int obj)
{
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f,
        *(int *)(obj + 0xb8));
}
#pragma scheduling on

extern void *lbl_803DDD98;
extern f32 lbl_803DDD9C;
extern f32 lbl_803DDDA0;
extern f32 lbl_803E7288;
extern f32 lbl_803E728C;
extern f32 lbl_803E7290;
extern f32 lbl_803E7294;
extern f32 lbl_803E7298;

int softbody_getExtraSize(void) { return 0; }
int softbody_getObjectTypeId(void) { return 0; }

void softbody_free(int obj)
{
    if ((void *)obj == lbl_803DDD98) {
        lbl_803DDD98 = NULL;
    }
}

#pragma peephole off
void softbody_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7288);
    }
}
#pragma peephole on

void softbody_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void softbody_init(int obj, int setup)
{
    *(s16 *)(obj + 4) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);
    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x1a) << 8);
    if (*(u8 *)(setup + 0x1b) != 0) {
        *(f32 *)(obj + 8) = (f32)(u32)*(u8 *)(setup + 0x1b) / lbl_803E7294;
        if (*(f32 *)(obj + 8) == lbl_803E7298) {
            *(f32 *)(obj + 8) = lbl_803E7288;
        }
        *(f32 *)(obj + 8) = *(f32 *)(obj + 8) * *(f32 *)(*(int *)(obj + 0x50) + 4);
    }
    *(u16 *)(obj + 0xb0) |= 0x2000;
    ObjAnim_SetCurrentMove(obj, 0, lbl_803E7298, 0);
    if (*(int *)(obj + 0x54) != 0) {
        ObjHitbox_SetSphereRadius(obj,
            (s16)((f32)*(s16 *)(*(int *)(obj + 0x54) + 0x5a) * *(f32 *)(obj + 8)));
    }
}
#pragma scheduling on
#pragma peephole on

void softbody_release(void) {}

#pragma scheduling off
void softbody_initialise(void)
{
    lbl_803DDD98 = NULL;
    lbl_803DDDA0 = lbl_803E7298;
    lbl_803DDD9C = lbl_803E7298;
}
#pragma scheduling on

#pragma peephole off
#pragma scheduling off
void softbody_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);

    if (lbl_803DDD98 == NULL && *(u8 *)(setup + 0x1f) == 0) {
        lbl_803DDD98 = (void *)obj;
    }

    if ((void *)obj == lbl_803DDD98) {
        lbl_803DDDA0 = lbl_803E728C * timeDelta + lbl_803DDDA0;
        while (lbl_803DDDA0 > lbl_803E7288) {
            lbl_803DDDA0 -= lbl_803E7288;
        }
        lbl_803DDD9C = lbl_803E7290 * timeDelta + lbl_803DDD9C;
        while (lbl_803DDD9C > lbl_803E7288) {
            lbl_803DDD9C -= lbl_803E7288;
        }
    }

    if (*(s16 *)(obj + 0x46) >= 0x6af && *(s16 *)(obj + 0x46) < 0x6b2) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803DDDA0, 0);
    } else {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803DDD9C, 0);
    }
}
#pragma scheduling on
#pragma peephole on

extern f32 lbl_803E7078;
extern f32 lbl_803E7150;

int arwbombcoll_getExtraSize(void) { return 8; }
int arwbombcoll_getObjectTypeId(void) { return 0; }
void arwbombcoll_free(void) {}
void arwbombcoll_hitDetect(void) {}

void arwbombcoll_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7078);
}

#pragma peephole off
#pragma scheduling off
void arwbombcoll_init(int obj, int setup)
{
    *(s16 *)(obj + 0) = (s16)(*(s8 *)(setup + 0x18) << 8);
    *(u8 *)(obj + 0x36) = 0;
}
#pragma scheduling on
#pragma peephole on

void arwbombcoll_release(void) {}
void arwbombcoll_initialise(void) {}

int arwgenerato_getExtraSize(void) { return 4; }
int arwgenerato_getObjectTypeId(void) { return 0; }
void arwgenerato_free(void) {}
void arwgenerato_hitDetect(void) {}

void arwgenerato_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7150);
}

#pragma peephole off
#pragma scheduling off
void arwgenerato_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);
    *(f32 *)(state + 0) = (f32)(u32)*(u16 *)(setup + 0x18);
}
#pragma scheduling on
#pragma peephole on

void arwgenerato_release(void) {}
void arwgenerato_initialise(void) {}

extern f32 lbl_803E7218;
extern f32 lbl_803E7100;
extern f32 lbl_803E71E4;
extern f32 lbl_803E704C;
extern void ObjHits_MarkObjectPositionDirty(int obj);

#pragma peephole off
#pragma scheduling off
int arwblocker_getBlockState(int obj)
{
    int state = *(int *)(obj + 0xb8);
    switch (*(u8 *)(state + 0)) {
    case 1:
        if (*(u8 *)(state + 1) != 0) {
            return 0;
        }
        return 1;
    case 0:
        return 0;
    }
    return 0;
}
#pragma scheduling on
#pragma peephole on

int arwblocker_getExtraSize(void) { return 2; }
int arwblocker_getObjectTypeId(void) { return 0; }
void arwblocker_free(void) {}
void arwblocker_hitDetect(void) {}

void arwblocker_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7218);
}

#pragma peephole off
#pragma scheduling off
void arwblocker_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);
    *(s16 *)(obj + 0) = -0x8000;
    *(s16 *)(obj + 4) = (s16)(*(s8 *)(setup + 0x18) << 8);
    *(void **)(obj + 0xbc) = (void *)arwblocker_getBlockState;
    *(u8 *)(state + 0) = *(u8 *)(setup + 0x19);
    *(s16 *)(obj + 6) |= 0x4000;
    *(u8 *)(obj + 0x36) = 0;
    ObjHits_DisableObject(obj);
}
#pragma scheduling on
#pragma peephole on

void arwblocker_release(void) {}
void arwblocker_initialise(void) {}

int arwspeedstr_getExtraSize(void) { return 0x1c; }
int arwspeedstr_getObjectTypeId(void) { return 0; }
void arwspeedstr_free(void) {}
void arwspeedstr_hitDetect(void) {}

void arwspeedstr_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7100);
}

void arwspeedstr_init(int obj, int setup)
{
    *(u8 *)(obj + 0x36) = 0;
}

void arwspeedstr_release(void) {}
void arwspeedstr_initialise(void) {}

int arwproximit_getExtraSize(void) { return 0x18; }
int arwproximit_getObjectTypeId(void) { return 0; }

void arwproximit_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 4) != NULL) {
        ModelLightStruct_free(*(void **)(state + 4));
        *(void **)(state + 4) = NULL;
    }
}

void arwproximit_hitDetect(void) {}

void arwproximit_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 4) != NULL && fn_8001DB64(*(void **)(state + 4)) != 0) {
        queueGlowRender(*(void **)(state + 4));
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E71E4);
}

#pragma peephole off
#pragma scheduling off
void arwproximit_init(int obj, int setup, int p3)
{
    int state = *(int *)(obj + 0xb8);

    *(s16 *)(state + 0) = (s16)randomGetRange(0x64, 0x12c);
    *(u8 *)(state + 0x15) = *(u8 *)(setup + 0x31);
    if (p3 == 0) {
        *(s16 *)(obj + 2) = (s16)randomGetRange(0, 0xffff);
        *(s16 *)(obj + 4) = (s16)randomGetRange(0, 0xffff);
        *(s16 *)(obj + 0) = (s16)randomGetRange(0, 0xffff);
        *(s16 *)(obj + 6) |= 0x4000;
        *(u8 *)(obj + 0x36) = 0;
    }
    storeZeroToFloatParam((void *)(state + 0xc));
    storeZeroToFloatParam((void *)(state + 0x10));
    ObjHits_DisableObject(obj);
    ObjHits_MarkObjectPositionDirty(obj);
}
#pragma scheduling on
#pragma peephole on

void arwproximit_release(void) {}
void arwproximit_initialise(void) {}

int arwarwingbo_getExtraSize(void) { return 0xc; }
int arwarwingbo_getObjectTypeId(void) { return 0; }

void arwarwingbo_free(int obj)
{
    (*(void (**)(int))(*gExpgfxInterface + 0x14))(obj);
    ObjGroup_RemoveObject(obj, 0x52);
}

void arwarwingbo_hitDetect(void) {}

#pragma peephole off
void arwarwingbo_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E704C);
    }
}
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void arwarwingbo_init(int obj, int setup)
{
    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x1a) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);
    *(s16 *)(obj + 4) = (s16)(*(u8 *)(setup + 0x18) << 8);
    ObjGroup_AddObject(obj, 0x52);
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void arwarwingbo_setActiveVisible(int obj, u8 active, u8 visible)
{
    int state = *(int *)(obj + 0xb8);
    if (active != 0) {
        Obj_SetActiveModelIndex(obj, visible != 0 ? 1 : 0);
        *(u8 *)(state + 0) = 1;
        *(s16 *)(obj + 6) &= ~0x4000;
    } else {
        *(u8 *)(state + 0) = 0;
        *(s16 *)(obj + 6) |= 0x4000;
    }
}
#pragma scheduling on
#pragma peephole on

void arwarwingbo_release(void) {}
void arwarwingbo_initialise(void) {}

/* Arwing family (untouched: arwarwing, arwarwinggu, arwingandrossstuff, arwlevelcon, arwsquadron). */
extern int lbl_803DDD88;
extern f32 lbl_803E701C;
extern f32 lbl_803E7058;
extern f32 lbl_803E70E0;
extern f32 lbl_803E7188;
extern void arwingHudSetVisible(int mode);
extern void fn_80125D04(void);
extern void setIsOvercast(int value);
extern void Music_Trigger(int id, int p2);

int getArwing(void) { return lbl_803DDD88; }

int arwarwing_getExtraSize(void) { return 0x498; }
int arwarwing_getObjectTypeId(void) { return 0; }
void arwarwing_free(int obj)
{
    int state = *(int *)(obj + 0xb8);

    ObjGroup_RemoveObject(obj, 0x26);
    lbl_803DDD88 = 0;
    if (*(void **)(state + 0x450) != NULL) {
        ModelLightStruct_free(*(void **)(state + 0x450));
    }
}
void arwarwing_release(void) {}
void arwarwing_initialise(void) {}

int arwarwinggu_getExtraSize(int obj)
{
    switch (*(s16 *)(obj + 0x46)) {
    case 0x606:
        return 8;
    case 0x610:
    case 0x615:
        return 4;
    case 0x611:
        return 1;
    default:
        return 0;
    }
}
int arwarwinggu_getObjectTypeId(void) { return 0; }
void arwarwinggu_free(void) {}
void arwarwinggu_render(void) {}
void arwarwinggu_hitDetect(void) {}
void arwarwinggu_init(int obj)
{
    if (*(s16 *)(obj + 0x46) == 0x606) {
        return;
    }
    *(s16 *)(obj + 6) |= 0x4000;
    *(u8 *)(obj + 0x36) = 0;
}
#pragma peephole off
#pragma scheduling off
void arwarwinggu_setActiveVisible(int obj, u8 active, u8 visible)
{
    int state = *(int *)(obj + 0xb8);

    if (active != 0) {
        Obj_SetActiveModelIndex(obj, visible != 0 ? 1 : 0);
        *(s16 *)(obj + 6) &= ~0x4000;
        *(u8 *)(obj + 0x36) = 0xff;
        *(f32 *)state = lbl_803E7058;
    } else {
        *(s16 *)(obj + 6) |= 0x4000;
        *(u8 *)(obj + 0x36) = 0;
    }
}
#pragma scheduling on
#pragma peephole on
void arwarwinggu_release(void) {}
void arwarwinggu_initialise(void) {}

int arwingandrossstuff_getExtraSize(void) { return 0x20; }
int arwingandrossstuff_getObjectTypeId(void) { return 0; }
void arwingandrossstuff_free(int obj)
{
    int state = *(int *)(obj + 0xb8);

    ObjGroup_RemoveObject(obj, 0x2);
    if (*(void **)(state + 0x14) != NULL) {
        ModelLightStruct_free(*(void **)(state + 0x14));
    }
}
#pragma peephole off
void arwingandrossstuff_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E701C);
    }
}
#pragma peephole on
void arwingandrossstuff_release(void) {}
void arwingandrossstuff_initialise(void) {}

int arwlevelcon_getExtraSize(void) { return 0x24; }
int arwlevelcon_getObjectTypeId(void) { return 0; }
void arwlevelcon_free(void)
{
    arwingHudSetVisible(2);
    fn_80125D04();
    setIsOvercast(1);
}
void arwlevelcon_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E70E0);
}
void arwlevelcon_hitDetect(void) {}
void arwlevelcon_commitRingChoice(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(u8 *)(state + 0x1b) != 0) {
        Music_Trigger(0xf3, 1);
    } else {
        Music_Trigger(2, 1);
    }
    arwingHudSetVisible(1);
}
void arwlevelcon_release(void) {}
void arwlevelcon_initialise(void) {}

int arwsquadron_getExtraSize(void) { return 0x164; }
int arwsquadron_getObjectTypeId(void) { return 0; }
void arwsquadron_free(void) {}
void arwsquadron_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7188);
}
void arwsquadron_hitDetect(void) {}

void arwprojectile_setLifetime(int obj, int lifetime)
{
    int state = *(int *)(obj + 0xb8);

    *(f32 *)(state + 4) = (f32)lifetime;
}

extern f32 lbl_803E7008;
extern f32 lbl_803E70EC;
extern f32 lbl_803E70F0;
extern f32 lbl_803E70F4;
extern void ObjHits_SetTargetMask(int obj, int mask);
extern void setMatrixFromObjectPos(void *mtx, void *src);
extern void Matrix_TransformPoint(void *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern void gameTextFn_80125ba4(int id);
extern void pauseMenuCreateHeads(void);

typedef struct ArwProjPosSrc {
    s16 rot[3];
    f32 scale;
    f32 pos[3];
} ArwProjPosSrc;

void arwprojectile_placeForward(int obj, f32 dist)
{
    int state = *(int *)(obj + 0xb8);
    f32 mtx[12];
    ArwProjPosSrc src;

    *(f32 *)(state + 8) = dist;
    src.pos[0] = lbl_803E7008;
    src.pos[1] = lbl_803E7008;
    src.pos[2] = lbl_803E7008;
    src.rot[0] = *(s16 *)obj;
    src.rot[1] = *(s16 *)(obj + 2);
    src.rot[2] = 0;
    src.scale = lbl_803E701C;
    setMatrixFromObjectPos(mtx, &src);
    Matrix_TransformPoint(mtx, lbl_803E7008, lbl_803E7008, *(f32 *)(state + 8),
                          (f32 *)(obj + 0x24), (f32 *)(obj + 0x28), (f32 *)(obj + 0x2c));
    *(s16 *)obj += 0x8000;
    *(s16 *)(obj + 2) = -*(s16 *)(obj + 2);
}

void arwingandrossstuff_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    int linked;

    *(s16 *)obj = (s16)(setup[0x1a] << 8);
    *(s16 *)(obj + 2) = (s16)(setup[0x19] << 8);
    *(u8 *)(obj + 0x36) = 1;
    switch (*(s16 *)(obj + 0x46)) {
    case 0x80d:
        *(s16 *)(state + 0x1a) = randomGetRange(-0x1f4, 0x1f4);
        *(s16 *)(state + 0x1c) = randomGetRange(-0x1f4, 0x1f4);
        /* fallthrough */
    case 0x6ae:
    case 0x7e4:
        ObjHits_SetTargetMask(obj, 4);
        *(u8 *)state = 4;
        *(u8 *)(state + 0x18) = 2;
        break;
    case 0x655:
        ObjHits_SetTargetMask(obj, 1);
        *(u8 *)state = 0;
        *(u8 *)(state + 0x18) = 1;
        break;
    case 0x604:
        ObjHits_SetTargetMask(obj, 1);
        if (*(s8 *)(obj + 0xad) != 0) {
            *(u8 *)state = 2;
            *(u8 *)(state + 0x18) = 2;
        } else {
            *(u8 *)state = 1;
            *(u8 *)(state + 0x18) = 2;
        }
        break;
    default:
        ObjHits_SetTargetMask(obj, 1);
        *(u8 *)state = 2;
        break;
    }
    linked = *(int *)(obj + 0x54);
    if (linked != 0) {
        *(s16 *)(linked + 0xb2) = 1;
    }
    ObjGroup_AddObject(obj, 2);
}

int arwlevelcon_ringEventCallback(int obj, int p2, int data);

void arwlevelcon_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);

    *(int *)(obj + 0xbc) = (int)arwlevelcon_ringEventCallback;
    *(s16 *)(state + 0x14) = 1;
    *(s16 *)(state + 0x16) = 0x50;
    *(f32 *)(state + 0) = lbl_803E70EC;
    *(f32 *)(state + 4) = lbl_803E70EC;
    *(f32 *)(state + 8) = lbl_803E70F0;
    *(f32 *)(state + 0xc) = lbl_803E70F4;
    if (*(int *)(setup + 0x14) == 0x48f7e) {
        *(u8 *)(state + 0x1b) = 1;
    }
    if (*(u8 *)(state + 0x19) == 0) {
        GameBit_Set(0x9d6, 0);
        GameBit_Set(0x9d8, 0);
        GameBit_Set(0x9d7, 0);
        GameBit_Set(0xe74, 0);
        arwingHudSetVisible(2);
        pauseMenuCreateHeads();
    }
    switch (*(s8 *)(obj + 0xac)) {
    case 0x3a:
        *(int *)(state + 0x1c) = 0x51bc;
        *(s16 *)(state + 0x20) = 0x6e3;
        break;
    case 0x3b:
        *(int *)(state + 0x1c) = 0x51bd;
        *(s16 *)(state + 0x20) = 0x6df;
        break;
    case 0x3d:
        *(int *)(state + 0x1c) = 0x51bf;
        *(s16 *)(state + 0x20) = 0x6e2;
        break;
    case 0x3c:
        *(int *)(state + 0x1c) = 0x51be;
        *(s16 *)(state + 0x20) = 0x6e1;
        break;
    case 0x3e:
    default:
        *(int *)(state + 0x1c) = 0x51c0;
        *(s16 *)(state + 0x20) = 0x6e0;
        break;
    }
}

int arwlevelcon_ringEventCallback(int obj, int p2, int data)
{
    int i;
    int textId;

    *(int *)(data + 0xe8) = (int)arwlevelcon_commitRingChoice;
    for (i = 0; i < *(u8 *)(data + 0x8b); i++) {
        u8 v = *(u8 *)(data + i + 0x81);
        if (v == 1) {
            (*(void (**)(int, int, int, int))(*gObjectTriggerInterface + 0x50))(0x56, 0, 0, 0);
        } else if (v == 4) {
            switch (*(s8 *)(obj + 0xac)) {
            case 0x3a:
                textId = 0;
                break;
            case 0x3b:
                textId = 1;
                break;
            case 0x3c:
                textId = 2;
                break;
            case 0x3e:
                textId = 3;
                break;
            case 0x3d:
                textId = 4;
                break;
            }
            gameTextFn_80125ba4(textId);
        }
    }
    return 0;
}

extern f32 lbl_803E6ED0;
extern f32 lbl_803E6EE8;
extern f32 lbl_803E6EFC;
extern f32 lbl_803E6F00;
extern f32 lbl_803E6F5C;
extern f32 lbl_803E6FF4;
extern f32 lbl_803E6FF8;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 fn_80293E80(f32 x);
extern void Obj_BuildWorldTransformMatrix(int obj, void *mtx, int p3);
extern void PSMTXMultVec(void *mtx, void *src, void *dst);
extern void fn_8008020C(int rx, int ry, int rz, f32 x, f32 y, f32 z, f32 p7);

#pragma peephole off
#pragma scheduling off
void arwarwing_render(int obj, int p2, int p3, int p4, int p5)
{
    int state = *(int *)(obj + 0xb8);
    int dx, dy;

    if (*(u8 *)(state + 0x338) != 0) {
        dx = (int)(lbl_803E6FF4 *
                   fn_80293E80(lbl_803E6EFC * (f32)(u32) * (u16 *)(state + 0x33c) / lbl_803E6F00));
        dy = (int)(lbl_803E6F5C *
                   fn_80293E80(lbl_803E6EFC * (f32)(u32) * (u16 *)(state + 0x33a) / lbl_803E6F00));
        *(s16 *)(obj + 2) = (s16)(*(s16 *)(obj + 2) + dx);
        *(s16 *)(obj + 4) = (s16)(*(s16 *)(obj + 4) + dy);
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6ED0);
    if (*(u8 *)(state + 0x338) != 0) {
        *(s16 *)(obj + 2) = (s16)(*(s16 *)(obj + 2) - dx);
        *(s16 *)(obj + 4) = (s16)(*(s16 *)(obj + 4) - dy);
    }
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void arwarwing_hitDetect(int obj)
{
    int state = *(int *)(obj + 0xb8);
    f32 pos[3];
    f32 mtx[12];

    if ((*(u16 *)(obj + 0xb0) & 0x1000) != 0 && *(u8 *)(state + 0x47f) != 0) {
        Obj_BuildWorldTransformMatrix(obj, mtx, 0);
        PSMTXMultVec(mtx, (void *)(state + 0x484), pos);
        pos[0] += playerMapOffsetX;
        pos[2] += playerMapOffsetZ;
        fn_8008020C((s16)(0x8000 - *(s16 *)obj + *(s16 *)(state + 0x490)),
                    (s16)(*(s16 *)(obj + 2) + *(s16 *)(state + 0x492)),
                    (s16)(*(s16 *)(obj + 4) + *(s16 *)(state + 0x494)),
                    pos[0], pos[1], pos[2], lbl_803E6FF8);
    }
}
#pragma scheduling on
#pragma peephole on

extern f32 lbl_803E7028;
extern f32 lbl_803E705C;
extern f32 lbl_803E7060;
extern f32 lbl_803DC3D0;
extern f32 lbl_803DC3D4;
extern f32 lbl_803DC3D8;
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern void Sfx_PlayFromObjectLimited(int obj, int sfxId, int limit);
extern void ObjHits_SetHitVolumeSlot(int obj, int p2, int p3, int p4);
extern void projectileParticleFxFn_80099660(int obj, f32 p2, int p3);
extern int fn_800283E8(int p1, int p2);
extern void fn_800541A4(int p1, int p2);
extern void textureAnimFn_80053f2c(int p1, int p2, int p3);

#pragma peephole off
#pragma scheduling off
void arwarwinggu_update(int obj)
{
    switch (*(s16 *)(obj + 0x46)) {
    case 0x606: {
        int state = *(int *)(obj + 0xb8);
        int model = Obj_GetActiveModel(obj);
        int texture = (int)objFindTexture(obj, 0, 0);
        int anim = fn_800283E8(*(int *)model, 0);
        fn_800541A4(anim, (u16)*(int *)(state + 4));
        textureAnimFn_80053f2c(anim, state, texture);
        break;
    }
    case 0x610:
    case 0x615: {
        int state = *(int *)(obj + 0xb8);
        if (*(f32 *)state > lbl_803E7060) {
            *(f32 *)state -= timeDelta;
            if (*(f32 *)state <= lbl_803E7060) {
                *(f32 *)state = lbl_803E7060;
                *(u8 *)(obj + 0x36) = 0;
            }
        }
        break;
    }
    case 0x611: {
        int state = *(int *)(obj + 0xb8);
        f32 v;
        if (*(u8 *)state != 0) {
            v = lbl_803E705C * timeDelta + (f32)(u32)*(u8 *)(obj + 0x36);
        } else {
            v = (f32)(u32)*(u8 *)(obj + 0x36) - lbl_803E705C * timeDelta;
        }
        if (v < lbl_803E7060) {
            v = lbl_803E7060;
        } else if (v > lbl_803E705C) {
            v = lbl_803E705C;
        }
        *(u8 *)(obj + 0x36) = (int)v;
        break;
    }
    }
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void arwingandrossstuff_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int arwing = getArwing();

    if (arwing != 0 && (*(u16 *)(arwing + 0xb0) & 0x1000) != 0) {
        Obj_FreeObject(obj);
        return;
    }
    if (*(f32 *)(state + 0x10) > lbl_803E7008) {
        *(f32 *)(state + 0x10) -= timeDelta;
        if (*(f32 *)(state + 0x10) <= lbl_803E7008) {
            Obj_FreeObject(obj);
        }
        return;
    }
    ObjHits_SetHitVolumeSlot(obj, 0xf, *(u8 *)(state + 0x18), 0);
    *(u8 *)(obj + 0x36) = 0xff;
    if (*(f32 *)(state + 4) > lbl_803E7008) {
        *(f32 *)(state + 4) -= timeDelta;
        if (*(f32 *)(state + 4) <= lbl_803E7008) {
            *(f32 *)(state + 4) = lbl_803E7008;
            Obj_FreeObject(obj);
            return;
        }
        if (*(s8 *)(*(int *)(obj + 0x54) + 0xad) != 0) {
            if (*(s16 *)(obj + 0x46) != 0x6ae) {
                Sfx_PlayFromObjectLimited(obj, 0x2b3, 4);
            }
            *(f32 *)(state + 0x10) = lbl_803E7028;
            *(u8 *)(obj + 0x36) = 0;
            projectileParticleFxFn_80099660(obj, lbl_803E701C, *(u8 *)state);
            if (*(int *)(state + 0x14) != 0) {
                ModelLightStruct_free(*(void **)(state + 0x14));
                *(int *)(state + 0x14) = 0;
            }
        }
        objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
                *(f32 *)(obj + 0x2c) * timeDelta);
        if (*(s16 *)(obj + 0x46) == 0x80d) {
            *(s16 *)(obj + 4) += *(s16 *)(state + 0x1a);
            *(s16 *)(obj + 2) += *(s16 *)(state + 0x1c);
        }
        if (*(s16 *)(obj + 0x46) == 0x7e4) {
            *(f32 *)(obj + 8) += lbl_803DC3D0;
            ObjHitbox_SetSphereRadius(obj, (int)(*(f32 *)(obj + 8) * lbl_803DC3D8));
            *(s16 *)(obj + 4) = (int)((f32)*(s16 *)(obj + 4) + lbl_803DC3D4);
        }
    }
}
#pragma scheduling on
#pragma peephole on

extern f32 lbl_803E70E4;
extern f32 lbl_803E70E8;
extern void skyFn_80089710(int p1, int p2, int p3);
extern void skyFn_800895e0(int p1, int p2, int p3, int p4, int p5, int p6);
extern void skyFn_800894a8(int p1, f32 p2, f32 p3, f32 p4);
extern void getEnvfxAct(int p1, int p2, int p3, int p4);
extern void setDrawLights(int value);
extern int AudioStream_IsPreparing(void);
extern void AudioStream_StartPrepared(void);
extern void AudioStream_Play(int stream, void (*cb)(void));
extern int mapBlockFn_800592e4(void);
extern int fn_8022D750(int arwing);
extern int fn_8022D710(int arwing);
extern int fn_8022D508(int arwing);
extern int fn_8022D514(int arwing);

#pragma peephole off
#pragma scheduling off
void arwlevelcon_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int arwing = getArwing();

    if (*(u8 *)(state + 0x18) == 0) {
        skyFn_80089710(7, 1, 0);
        if (*(u8 *)(state + 0x1b) != 0) {
            skyFn_800895e0(7, 0xaa, 0x78, 0xff, 0x69, 0x40);
        } else {
            skyFn_800895e0(7, 0x96, 0x64, 0xf0, 0, 0);
        }
        skyFn_800894a8(7, lbl_803E70E4, lbl_803E70E4, lbl_803E70E0);
        getEnvfxAct(0, 0, 0x21f, 0);
        getEnvfxAct(0, 0, 0x22b, 0);
        setIsOvercast(0);
        *(u8 *)(state + 0x18) = 1;
        setDrawLights(0);
    }
    if (*(u8 *)(state + 0x19) == 0) {
        int mode;
        if (*(u8 *)(state + 0x1b) != 0) {
            mode = 3;
        } else {
            if (AudioStream_IsPreparing() == 0) {
                AudioStream_Play(*(int *)(state + 0x1c), AudioStream_StartPrepared);
            }
            mode = 0;
        }
        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(mode, obj, -1);
        *(u8 *)(state + 0x19) = 1;
        GameBit_Set(0x9d6, 0);
        GameBit_Set(0x9d8, 0);
        GameBit_Set(0x9d7, 0);
    }
    if (*(u8 *)(state + 0x1a) == 0) {
        int mb = mapBlockFn_800592e4();
        if (*(f32 *)(arwing + 0x14) - *(f32 *)(mb + 0x28) > lbl_803E70E8 &&
            fn_8022D750(arwing) == 0 && fn_8022D710(arwing) == 0) {
            int a, b;
            arwingHudSetVisible(2);
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x7c))(*(u16 *)(state + 0x20), 0, 0);
            a = fn_8022D508(arwing);
            b = fn_8022D514(arwing);
            if (b >= a) {
                GameBit_Set(0x9d8, 1);
            } else {
                GameBit_Set(0x9d7, 1);
            }
            *(u8 *)(state + 0x1a) = 1;
            Music_Trigger(2, 0);
            Music_Trigger(0xf3, 0);
        }
    }
}
#pragma scheduling on
#pragma peephole on

extern f32 lbl_803E7154;
extern void fn_802317A8(int obj, int state, int setup);
extern void fn_802315EC(int obj, int state, int setup);

void arwgenerato_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (*(f32 *)state > lbl_803E7154) {
        *(f32 *)state -= timeDelta;
        if (*(f32 *)state <= lbl_803E7154) {
            switch (*(u8 *)(setup + 0x25)) {
            case 0:
                fn_802317A8(obj, state, setup);
                break;
            case 1:
                fn_802315EC(obj, state, setup);
                break;
            }
            *(f32 *)state = (f32)(u32)*(u16 *)(setup + 0x18);
        }
    }
}

extern void fn_8006CB24(int obj);
extern void Rcp_DisableDistortionFilter(void);
extern void renderFn_8008f904(void *p);
extern f32 lbl_803E74DC;
extern f32 lbl_803E75B0;
extern f32 lbl_803E7600;

int andross_getExtraSize(void) { return 0xec; }
int andross_getObjectTypeId(void) { return 0; }
void andross_free(int obj)
{
    fn_8006CB24(obj);
    Rcp_DisableDistortionFilter();
}
void andross_hitDetect(void) {}
void andross_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E74DC);
}
#pragma dont_inline on
void andross_setPartSignal(int obj, int signal)
{
    int state;

    if ((void *)obj == NULL) {
        return;
    }
    state = *(int *)(obj + 0xb8);
    *(u8 *)(state + 0xad) |= signal;
}
#pragma dont_inline reset

int androsshand_getExtraSize(void) { return 0x2c; }
int androsshand_getObjectTypeId(void) { return 0; }
void androsshand_free(void) {}
void androsshand_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E75B0);
}

int androssligh_getExtraSize(void) { return 0x10; }
int androssligh_getObjectTypeId(void) { return 0; }
void androssligh_free(void) {}
void androssligh_render(int obj)
{
    void *p = *(void **)(*(int *)(obj + 0xb8) + 4);

    if (p != NULL) {
        renderFn_8008f904(p);
    }
}
#pragma peephole off
void androssligh_setState(int obj, int newState, u8 force)
{
    int state;

    if ((void *)obj == NULL) {
        return;
    }
    state = *(int *)(obj + 0xb8);
    if (*(s8 *)(state + 0xc) == 2) {
        if (force == 0) {
            return;
        }
    }
    *(s8 *)(state + 0xc) = (s8)newState;
}
#pragma peephole on

extern void fn_8006CB50(void);
extern void unlockLevel(int a, int b, int c);
extern int ObjModel_GetRenderOp(int model, int idx);
extern f32 lbl_803E74B4;
extern f32 lbl_803E74D4;
extern f32 lbl_803E7530;
extern f32 lbl_803E7590;
extern f32 lbl_803E7594;
extern f32 lbl_803E7598;

#pragma scheduling off
int andross_updateModelAlpha(int obj)
{
    int state = *(int *)(obj + 0xb8);
    f32 v;
    int model;
    int i;
    int alpha;

    *(f32 *)(state + 0x68) = lbl_803E74D4;
    v = *(f32 *)(state + 0x68);
    model = *(int *)Obj_GetActiveModel(obj);
    alpha = (int)(lbl_803E74B4 * v);
    for (i = 0; i < *(u8 *)(model + 0xf8); i++) {
        *(u8 *)(ObjModel_GetRenderOp(model, i) + 0x43) = alpha;
    }
    return 0;
}

void andross_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    int i;
    int model;

    *(f32 *)(state + 0x58) = *(f32 *)(setup + 8);
    *(f32 *)(state + 0x5c) = *(f32 *)(setup + 0xc);
    *(f32 *)(state + 0x60) = *(f32 *)(setup + 0x10);
    *(s16 *)(state + 0x98) = 0;
    *(int *)(state + 0x88) = 0;
    *(int *)(state + 0x8c) = -1;
    *(f32 *)(state + 0x64) = lbl_803E7590;
    *(u8 *)(state + 0xb6) = 5;
    *(int *)(state + 0x7c) = 1;
    *(int *)(state + 0x80) = -1;
    *(s16 *)(state + 0xa0) = -0x8000;
    *(s16 *)obj = -0x8000;
    *(f32 *)(state + 0x6c) = lbl_803E7594;
    *(f32 *)(state + 0xa8) = lbl_803E74D4;
    *(f32 *)(state + 0x74) = lbl_803E7598;
    *(f32 *)(state + 0x78) = lbl_803E7530;
    *(u8 *)(state + 0xbc) = 1;
    ObjHits_SetTargetMask(obj, 4);
    *(void **)(obj + 0xbc) = (void *)andross_updateModelAlpha;
    fn_8006CB50();
    model = *(int *)Obj_GetActiveModel(obj);
    for (i = 0; i < *(u8 *)(model + 0xf8); i++) {
        *(u8 *)(ObjModel_GetRenderOp(model, i) + 0x43) = 0;
    }
    GameBit_Set(0xd, 0);
    unlockLevel(0, 0, 1);
}
#pragma scheduling on

int androssbrain_getExtraSize(void) { return 0x28; }
int androssbrain_getObjectTypeId(void) { return 0; }
void androssbrain_free(void) {}
void androssbrain_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7600);
}

void androsshand_hitDetect(void) {}
void androssligh_hitDetect(void) {}
void androssbrain_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void androsshand_setState(int obj, int newState, u8 force)
{
    int state;

    if ((void *)obj == NULL) {
        return;
    }
    state = *(int *)(obj + 0xb8);
    if (*(s8 *)(state + 0x23) != 9 || force != 0) {
        *(s8 *)(state + 0x23) = (s8)newState;
        if (force != 0) {
            if (force == 2) {
                *(u8 *)(state + 0x25) = 0x12;
            } else {
                *(u8 *)(state + 0x25) = 0xf;
            }
        }
    } else {
        if ((u8)newState != 0) {
            andross_setPartSignal(*(int *)state, 1);
        }
    }
}

void androssbrain_setState(int obj, int newState, u8 force)
{
    int state;

    if ((void *)obj == NULL) {
        return;
    }
    state = *(int *)(obj + 0xb8);
    if (*(s8 *)(state + 0x1c) != 2 || force != 0) {
        *(s8 *)(state + 0x1c) = (s8)newState;
        if (force != 0) {
            *(u8 *)(state + 0x1e) = 0x50;
        }
    } else {
        andross_setPartSignal(*(int *)state, 1);
    }
}
#pragma scheduling on
#pragma peephole on

extern int ObjHits_GetPriorityHit(int obj, int *outHit, int *outIdx, int *outVol);
extern void ObjPath_GetPointWorldPosition(int obj, int idx, f32 *x, f32 *y, f32 *z, int p6);
extern void DIMexplosionFn_8009a96c(int obj, f32 a, f32 b, f32 c, f32 d, int e, int f,
                                    int g, int h, int i, int j, int k);
extern int lbl_803DC508;
extern f32 lbl_803E75A8;

#pragma peephole off
#pragma scheduling off
void androsshand_handleDamage(int obj, int hand)
{
    int hitVol;
    int sphereIdx;
    int hitObj;
    f32 x;
    f32 y;
    f32 z;
    int t;

    t = *(u8 *)(hand + 0x26) - framesThisStep;
    if (t < 0) {
        t = 0;
    }
    *(u8 *)(hand + 0x26) = (u8)t;
    if (ObjHits_GetPriorityHit(obj, &hitObj, &sphereIdx, &hitVol) != 0 &&
        *(u8 *)(hand + 0x26) == 0 && sphereIdx == 0) {
        *(u8 *)(hand + 0x25) -= 1;
        *(u8 *)(hand + 0x26) = 6;
        *(f32 *)(hand + 0x1c) = (f32)lbl_803DC508;
        Sfx_PlayFromObject(obj, 0x484);
        if (*(u8 *)(hand + 0x25) == 0) {
            *(s8 *)(hand + 0x23) = 9;
            andross_setPartSignal(*(int *)hand, 1);
            Sfx_PlayFromObject(obj, 0x485);
            ObjPath_GetPointWorldPosition(obj, 0, &x, &y, &z, 0);
            DIMexplosionFn_8009a96c(obj, x, y, z, lbl_803E75A8, 1, 1, 1, 1, 0, 1, 0);
        }
    }
    if (*(u8 *)(hand + 0x25) != 0) {
        if (*(u8 *)(hand + 0x26) != 0) {
            *(u8 *)(hand + 0x28) = 1;
        } else {
            *(u8 *)(hand + 0x28) = 0;
        }
    } else {
        *(u8 *)(hand + 0x28) = 2;
    }
    *(int *)objFindTexture(obj, 0, 0) = *(u8 *)(hand + 0x28) << 8;
}
#pragma scheduling on
#pragma peephole on

extern int ObjAnim_SetCurrentMove(int obj, int moveId, f32 blend, int flag);
extern f32 lbl_803E75AC;
extern f32 lbl_8032C270[];

void androssligh_init(void) {}

#pragma scheduling off
void androssbrain_init(int obj)
{
    int state = *(int *)(obj + 0xb8);

    *(u8 *)(state + 0x1e) = 0x50;
    ObjHits_SetTargetMask(obj, 4);
}

void androsshand_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);

    *(u8 *)(state + 0x22) = setup[0x1b];
    *(u8 *)(state + 0x24) = -1;
    *(u8 *)(state + 0x25) = 0xf;
    *(u8 *)(state + 0x27) = 5;
    *(u8 *)(state + 0x23) = 3;
    *(u8 *)(state + 0x24) = 3;
    ObjAnim_SetCurrentMove(obj, 4, lbl_803E75AC, 0);
    *(f32 *)(*(int *)(obj + 0xb8) + 0x14) = lbl_8032C270[4];
    *(f32 *)(obj + 0x98) = lbl_803E75B0;
    ObjHits_SetTargetMask(obj, 4);
}
#pragma scheduling on

extern int ObjList_FindObjectById(int id);
extern void androssligh_updateBeam(int obj, int state);

void androssligh_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(void **)state == NULL) {
        *(int *)state = ObjList_FindObjectById(0x47dd9);
    }
    if (*(void **)state != NULL) {
        *(f32 *)(obj + 0xc) = *(f32 *)(*(int *)state + 0xc);
        *(f32 *)(obj + 0x10) = *(f32 *)(*(int *)state + 0x10);
        *(f32 *)(obj + 0x14) = *(f32 *)(*(int *)state + 0x14);
    }
    *(u8 *)(state + 0xd) = *(u8 *)(state + 0xc);
    switch (*(s8 *)(state + 0xc)) {
    case 0:
        break;
    case 1:
        androssligh_updateBeam(obj, state);
        break;
    case 2:
        break;
    case 3:
        break;
    }
}

extern int *gGameUIInterface;
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);

#pragma peephole off
#pragma scheduling off
void androssbrain_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    u8 flag = 0;
    int hitObj;
    int sphereIdx;
    int hitVol;
    int hit;
    int t;

    if (*(void **)state == NULL) {
        *(int *)state = ObjList_FindObjectById(0x47b77);
    }
    if (*(void **)(state + 4) == NULL) {
        *(int *)(state + 4) = ObjList_FindObjectById(0x4c611);
    }
    ObjHits_SetHitVolumeSlot(obj, 5, 2, -1);
    ObjHits_EnableObject(obj);
    if (*(void **)state != NULL) {
        *(f32 *)(obj + 0xc) = *(f32 *)(*(int *)state + 0xc);
        *(f32 *)(obj + 0x10) = *(f32 *)(*(int *)state + 0x10);
        *(f32 *)(obj + 0x14) = *(f32 *)(*(int *)state + 0x14);
    }
    if (*(s8 *)(state + 0x1c) != *(s8 *)(state + 0x1d)) {
        flag = 1;
    }
    *(u8 *)(state + 0x1d) = *(u8 *)(state + 0x1c);
    switch (*(s8 *)(state + 0x1c)) {
    case 0:
        if (flag != 0) {
            (*(void (**)(void))(*gGameUIInterface + 0x64))();
        }
        *(s16 *)obj = *(s16 *)(*(int *)state);
        *(s16 *)(obj + 6) |= 0x4000;
        break;
    case 1:
        if (flag != 0) {
            *(u8 *)(state + 0x1f) = 0x3c;
            (*(void (**)(int, int))(*gGameUIInterface + 0x58))(0x50, 0x643);
        }
        (*(void (**)(int))(*gGameUIInterface + 0x5c))(*(u8 *)(state + 0x1e));
        hit = ObjHits_GetPriorityHit(obj, &hitObj, &sphereIdx, &hitVol);
        t = *(u8 *)(state + 0x1f) - framesThisStep;
        if (t < 0) {
            t = 0;
        }
        *(u8 *)(state + 0x1f) = (u8)t;
        if (hit != 0) {
            if (*(u8 *)(state + 0x1f) == 0) {
                Obj_SetModelColorFadeRecursive(obj, 0x19, 0xc8, 0, 0, 1);
                *(u8 *)(state + 0x1f) = 6;
                *(u8 *)(state + 0x1e) -= 1;
                if (*(u8 *)(state + 0x1e) == 0) {
                    *(u8 *)(state + 0x1c) = 2;
                    andross_setPartSignal(*(int *)state, 1);
                    Sfx_PlayFromObject(obj, 0x485);
                } else {
                    Sfx_PlayFromObject(obj, 0x484);
                }
            }
        }
        *(s16 *)(obj + 6) &= ~0x4000;
        break;
    case 2:
        if (flag != 0) {
            androssligh_setState(*(int *)(state + 4), 2, 0);
            (*(void (**)(void))(*gGameUIInterface + 0x64))();
        }
        *(s16 *)(obj + 6) |= 0x4000;
        andross_setPartSignal(*(int *)state, 8);
        break;
    }
}
#pragma scheduling on
#pragma peephole on

extern int *gScreenTransitionInterface;
extern f32 lbl_803E7480;
extern void gf_levelcon_handleScriptEvents(int obj);

int gf_levelcon_getExtraSize(void) { return 0x10; }
int gf_levelcon_getObjectTypeId(void) { return 0; }
void gf_levelcon_hitDetect(void) {}
void gf_levelcon_initialise(void) {}
void gf_levelcon_release(void) {}
#pragma scheduling off
void gf_levelcon_free(void)
{
    setIsOvercast(1);
}
void gf_levelcon_update(int obj)
{
    *(void **)(obj + 0xbc) = (void *)gf_levelcon_handleScriptEvents;
}
#pragma peephole off
void gf_levelcon_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7480);
    }
}
#pragma peephole on
void gf_levelcon_init(int obj)
{
    setIsOvercast(0);
    (*(void (**)(int, int))(*gScreenTransitionInterface + 0xc))(0x258, 1);
}
#pragma scheduling on

int tree_getExtraSize(void) { return 0x5c; }

extern f32 lbl_803E745C;
extern void mclightning_handleScriptEvents(int obj);

typedef struct McLightningFlags {
    u8 hi : 4;
    u8 lo : 4;
} McLightningFlags;

int mclightning_getExtraSize(void) { return 0x1c; }
#pragma peephole off
#pragma scheduling off
void mclightning_free(int obj)
{
    int state = *(int *)(obj + 0xb8);

    ObjGroup_RemoveObject(obj, 0x48);
    if (*(void **)state != NULL) {
        mm_free(*(void **)state);
    }
}
void mclightning_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(void **)state != NULL) {
        mm_free(*(void **)state);
        *(int *)state = 0;
    }
    ((McLightningFlags *)(state + 0x1b))->hi = 0;
    *(s16 *)(obj + 6) |= 0x4000;
}
void mclightning_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    f32 v;

    *(s16 *)(obj + 6) |= 0x4000;
    *(void **)(obj + 0xbc) = (void *)mclightning_handleScriptEvents;
    ObjGroup_AddObject(obj, 0x48);
    ((McLightningFlags *)(state + 0x1b))->lo = setup[0x1a];
    v = lbl_803E745C;
    *(f32 *)(state + 0x10) = v;
    *(f32 *)(state + 0x14) = v;
}
#pragma scheduling on
#pragma peephole on

extern void Sfx_StopObjectChannel(int obj, int channel);
extern f32 lbl_803E738C;
extern int cmbsrc_update(int obj);

int cmbsrc_getExtraSize(void) { return 0x28; }
int cmbsrc_getObjectTypeId(void) { return 0; }
void cmbsrc_initialise(void) {}
void cmbsrc_release(void) {}
#pragma scheduling off
int cmbsrc_updateAndReturnZero(int obj)
{
    cmbsrc_update(obj);
    return 0;
}
int cmbsrc_getColorIndex(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (*(u8 *)(setup + 0x1b) == 0xf) {
        return *(s8 *)(state + 0x23);
    }
    return -1;
}
#pragma peephole off
void cmbsrc_setExternalActive(int obj, u8 active)
{
    int state = *(int *)(obj + 0xb8);

    if (active != 0) {
        *(u8 *)(state + 0x22) |= 0x2;
    } else {
        *(u8 *)(state + 0x22) &= ~0x2;
    }
}
#pragma peephole on
void cmbsrc_free(int obj)
{
    int state = *(int *)(obj + 0xb8);

    (*(void (**)(int))(*gExpgfxInterface + 0x14))(obj);
    if (*(void **)state != NULL) {
        ModelLightStruct_free(*(void **)state);
    }
    Sfx_StopObjectChannel(obj, 0x40);
}
#pragma peephole off
void cmbsrc_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (visible != 0) {
        *(u8 *)(state + 0x22) |= 0x1;
        if (*(void **)state != NULL && *(u8 *)(*(int *)state + 0x2f8) != 0 &&
            *(u8 *)(*(int *)state + 0x4c) != 0) {
            queueGlowRender(*(void **)state);
        }
        if ((*(u8 *)(setup + 0x29) & 0x8) != 0) {
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E738C);
        }
    }
}
#pragma peephole on
#pragma scheduling on

extern void modelLightStruct_setColors100104(void *light, u8 r, u8 g, u8 b, int a);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sound);
extern int *gSHthorntailAnimationInterface;
extern f32 lbl_803E7360;
extern f32 lbl_803E7364;
extern f32 lbl_803E7368;
extern f32 lbl_803E736C;
extern f32 lbl_803E7370;
extern f32 lbl_803E7374;
extern f32 lbl_803E7384;
extern u8 lbl_803DC3E0[];
extern u8 lbl_8032BD00[];
extern u8 lbl_8032BD50[];
extern f32 lbl_803E7378;
extern f32 lbl_803E737C;
extern f32 lbl_803E7380;
extern f32 lbl_803E7388;
extern f32 lbl_803E738C;
extern f32 lbl_803E7390;
extern f32 lbl_803E7394;
extern f32 lbl_803E7398;
extern int Camera_GetCurrentViewSlot(void);
extern f32 interpolate(f32 a, f32 b, f32 c);
extern void fn_8009837C(int obj, f32 brightness, int b, int c, int d, f32 e, int f);
extern void fn_80098B18(int obj, f32 brightness, int b, int c, int d, void *vec);
extern void lightSetField4D(void *light, int v);
extern void ObjHits_SyncObjectPositionIfDirty(int obj);
extern f32 lbl_8032BD10[];
extern f32 lbl_803E73A8;
extern f32 lbl_803E73AC;
extern f32 lbl_803E73B0;
extern f32 lbl_803E73B4;
extern f32 lbl_803E73B8;
extern f32 lbl_803E73BC;
extern f32 lbl_803E73C0;

typedef struct CmbsrcHitFlag {
    u8 disabled : 1;
} CmbsrcHitFlag;

#pragma dont_inline on
#pragma peephole off
#pragma scheduling off
int cmbsrc_shouldActivate(int obj, int state, int setup)
{
    int result = 0;
    int hitOut;

    if (*(void **)state != NULL && fn_8001DB64(*(void **)state) != 0) {
        return 0;
    }
    if (*(s16 *)(setup + 0x24) != -1 && GameBit_Get(*(s16 *)(setup + 0x24)) != 0) {
        result = 1;
    } else if ((*(u8 *)(state + 0x22) & 0x4) != 0 &&
               (*(int (**)(int *))(*gSHthorntailAnimationInterface + 0x24))(&hitOut) != 0) {
        result = 1;
    }
    if ((*(u8 *)(setup + 0x2a) & 0x30) == 0x10) {
        if (*(f32 *)(state + 0x14) != lbl_803E7360) {
            *(f32 *)(state + 0x14) -= timeDelta;
            if (*(f32 *)(state + 0x14) <= lbl_803E7360) {
                result = 1;
            }
        }
    }
    return result;
}

int cmbsrc_shouldDeactivate(int obj, int state, int setup)
{
    int result = 0;
    int hitOut;

    if (*(void **)state != NULL && fn_8001DB64(*(void **)state) != 2) {
        return 0;
    }
    if (*(s16 *)(setup + 0x24) != -1 && GameBit_Get(*(s16 *)(setup + 0x24)) == 0) {
        result = 1;
    } else if ((*(u8 *)(state + 0x22) & 0x4) != 0 &&
               (*(int (**)(int *))(*gSHthorntailAnimationInterface + 0x24))(&hitOut) == 0) {
        result = 1;
    } else if (*(s8 *)(state + 0x26) == 0) {
        *(f32 *)(state + 0x14) = (f32)(u32)*(u16 *)(state + 0x20);
        result = 1;
    }
    return result;
}

void cmbsrc_hitDetect(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int v;

    *(u8 *)(state + 0x24) = 0;
    if ((*(u8 *)(setup + 0x2a) & 0x30) != 0) {
        *(u8 *)(state + 0x24) = (u8)ObjHits_GetPriorityHit(obj, 0, 0, 0);
        if (*(u8 *)(state + 0x24) == 0x10) {
            *(u8 *)(state + 0x26) -= 1;
            *(f32 *)(state + 0x1c) = lbl_803E7384;
        }
        if (*(f32 *)(state + 0x1c) != lbl_803E7360) {
            *(f32 *)(state + 0x1c) -= timeDelta;
            if (*(f32 *)(state + 0x1c) <= lbl_803E7360) {
                *(u8 *)(state + 0x26) += 1;
                *(f32 *)(state + 0x1c) = lbl_803E7384;
            }
        }
        v = *(s8 *)(state + 0x26);
        if (v < 0) {
            v = 0;
        } else if (v > 0xf) {
            v = 0xf;
        }
        *(s8 *)(state + 0x26) = (s8)v;
    }
}

int cmbsrc_cycleColor(int obj, int state)
{
    int setup = *(int *)(obj + 0x4c);
    int idx;

    *(f32 *)(state + 0x10) -= timeDelta;
    if (*(f32 *)(state + 0x10) <= lbl_803E7360) {
        *(f32 *)(state + 0x10) = lbl_803E7364;
        *(u8 *)(state + 0x23) += 1;
        if (*(u8 *)(state + 0x23) >= 3) {
            *(u8 *)(state + 0x23) = 0;
        }
        idx = lbl_803DC3E0[*(u8 *)(state + 0x23)];
        if (*(void **)state != NULL) {
            int base = idx * 3;
            modelLightStruct_setColorsA8AC(*(void **)state, lbl_8032BD50[base],
                                           lbl_8032BD50[base + 1], lbl_8032BD50[base + 2], 0xff);
            modelLightStruct_setColors100104(*(void **)state, lbl_8032BD50[base],
                                             lbl_8032BD50[base + 1], lbl_8032BD50[base + 2], 0xff);
            lightSetFieldB0(*(void **)state,
                            (int)(lbl_803E7368 * (f32)(u32)lbl_8032BD50[base]),
                            (int)(lbl_803E7368 * (f32)(u32)lbl_8032BD50[base + 1]),
                            (int)(lbl_803E7368 * (f32)(u32)lbl_8032BD50[base + 2]), 0xff);
            if (*(u8 *)(setup + 0x29) & 0x40) {
                if (*(u8 *)(setup + 0x29) & 0x80) {
                    fn_8001D730(*(void **)state, 0, lbl_8032BD50[base], lbl_8032BD50[base + 1],
                                lbl_8032BD50[base + 2], 0x87, lbl_803E736C * *(f32 *)(obj + 8));
                } else {
                    fn_8001D730(*(void **)state, 0, lbl_8032BD50[base], lbl_8032BD50[base + 1],
                                lbl_8032BD50[base + 2], 0x87, lbl_803E7370 * *(f32 *)(obj + 8));
                }
            }
        }
    } else {
        idx = lbl_803DC3E0[*(u8 *)(state + 0x23)];
    }
    return idx;
}

void cmbsrc_updateVisuals(int obj, int state)
{
    int setup = *(int *)(obj + 0x4c);
    int colorIdx = 0;
    int effectMode = 0;
    int subMode = 0;
    int viewSlot;
    f32 dist;
    f32 vec[3];
    f32 param[3];

    viewSlot = Camera_GetCurrentViewSlot();
    if (*(u8 *)(state + 0x25) == 0) {
        *(f32 *)(state + 0x18) = lbl_803E7374 * *(f32 *)(setup + 0x20);
    } else {
        *(f32 *)(state + 0x18) += interpolate(
            (f32)*(s8 *)(state + 0x26) / lbl_803E7378 *
                    (lbl_803E7374 * *(f32 *)(setup + 0x20) -
                     *(f32 *)(setup + 0x20) * lbl_803E737C) +
                *(f32 *)(setup + 0x20) * lbl_803E737C - *(f32 *)(state + 0x18),
            lbl_803E7380, timeDelta);
    }
    dist = Vec_distance(viewSlot + 0x44, obj + 0x18);
    if (*(u8 *)(state + 0x25) == 1) {
        if (dist <= (f32)(u32)(*(u8 *)(setup + 0x26) << 3)) {
            if (*(u8 *)(setup + 0x1b) == 0xf) {
                colorIdx = (u8)cmbsrc_cycleColor(obj, state);
            } else {
                colorIdx = *(u8 *)(setup + 0x1b);
            }
        }
    }
    *(f32 *)(state + 0x4) -= timeDelta;
    *(f32 *)(state + 0x8) -= timeDelta;
    if (*(f32 *)(state + 0x4) <= lbl_803E7360) {
        if (*(u8 *)(setup + 0x1c) < 9) {
            if (dist <= (f32)(u32)(*(u8 *)(setup + 0x27) << 3)) {
                effectMode = *(u8 *)(setup + 0x1c);
            }
        }
        if (*(u8 *)(state + 0x25) == 0) {
            if (dist <= (f32)(u32)(*(u8 *)(setup + 0x26) << 3) &&
                (*(u8 *)(state + 0x22) & 0x8) == 0) {
                effectMode = *(u8 *)(setup + 0x1c);
                if (*(u8 *)(setup + 0x1c) == 0) {
                    effectMode = 2;
                }
            } else {
                effectMode = 0;
            }
        }
        if (*(u8 *)(state + 0x25) == 1) {
            *(f32 *)(state + 0x4) += lbl_803E7384;
        } else {
            *(f32 *)(state + 0x4) += lbl_803E7378;
        }
    }
    if ((*(u16 *)(obj + 0xb0) & 0x800) || (*(u8 *)(state + 0x22) & 0x2)) {
        switch (*(s16 *)(obj + 0x46)) {
        case 0x758:
            if (*(u8 *)(state + 0x25) == 1) {
                if (dist <= (f32)(u32)(*(u8 *)(setup + 0x26) << 3)) {
                    subMode = *(u8 *)(setup + 0x1d);
                }
            }
            fn_8009837C(obj, *(f32 *)(state + 0x18), colorIdx, effectMode, subMode,
                        (f32)(u32)*(u8 *)(setup + 0x28) / lbl_803E7388, 0);
            break;
        case 0x6e8:
        default:
            if (*(u8 *)(state + 0x25) == 1) {
                if (*(f32 *)(state + 0x8) <= lbl_803E7360) {
                    if (*(u8 *)(setup + 0x1d) < 4) {
                        if (dist <= (f32)(u32)(*(u8 *)(setup + 0x28) << 3)) {
                            subMode = *(u8 *)(setup + 0x1d);
                        }
                    }
                    *(f32 *)(state + 0x8) += lbl_803E738C;
                }
            }
            vec[0] = lbl_803E7360;
            if (*(s16 *)(obj + 0x46) == 0x853) {
                if (*(u8 *)(state + 0x25) == 0) {
                    vec[1] = lbl_803E7390;
                } else {
                    vec[1] = lbl_803E7394;
                }
            } else {
                if (*(u8 *)(state + 0x25) == 0) {
                    vec[1] = lbl_803E7390;
                } else {
                    vec[1] = lbl_803E7360;
                }
            }
            vec[2] = lbl_803E7360;
            fn_80098B18(obj, *(f32 *)(state + 0x18), colorIdx, effectMode, subMode, vec);
            break;
        }
    }
    if (*(u8 *)(state + 0x25) == 1 && (*(u8 *)(setup + 0x2a) & 0x2)) {
        *(f32 *)(state + 0xc) -= timeDelta;
        if (*(f32 *)(state + 0xc) <= lbl_803E7360) {
            if (*(u16 *)(obj + 0xb0) & 0x800) {
                param[2] = *(f32 *)(state + 0x18);
                (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 0x8))(
                    obj, 0x7cb, param, 2, -1, 0);
            }
            *(f32 *)(state + 0xc) += lbl_803E7398;
        }
    }
}

int cmbsrc_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    switch (*(u8 *)(state + 0x25)) {
    case 1:
        if (cmbsrc_shouldDeactivate(obj, state, setup)) {
            *(u8 *)(state + 0x25) = 0;
            if (*(void **)state != NULL) {
                lightFn_8001db6c(*(void **)state, 0, lbl_803E7374);
            }
            if (*(u8 *)(setup + 0x29) & 0x2) {
                Sfx_StopObjectChannel(obj, 0x40);
            }
            ObjHits_DisableObject(obj);
            if (*(s16 *)(setup + 0x24) != -1) {
                GameBit_Set(*(s16 *)(setup + 0x24), 0);
            }
        } else {
            if (*(u8 *)(setup + 0x29) & 0x2) {
                Sfx_KeepAliveLoopedObjectSound(obj,
                    lbl_8032BD00[*(u8 *)(*(int *)(obj + 0x4c) + 0x1b)]);
            }
            if (*(void **)state != NULL && *(u8 *)(*(int *)state + 0x2f8) != 0 &&
                *(u8 *)(*(int *)state + 0x4c) != 0) {
                s16 v = (s16)(*(u8 *)(*(int *)state + 0x2f9) + *(s8 *)(*(int *)state + 0x2fa));
                if (v < 0) {
                    v = 0;
                    *(u8 *)(*(int *)state + 0x2fa) = 0;
                } else if (v > 0xc) {
                    v = (s16)(v + randomGetRange(-0xc, 0xc));
                    if (v > 0xff) {
                        v = 0xff;
                        *(u8 *)(*(int *)state + 0x2fa) = 0;
                    }
                }
                *(u8 *)(*(int *)state + 0x2f9) = (u8)v;
            }
        }
        break;
    case 0:
        if (cmbsrc_shouldActivate(obj, state, setup)) {
            *(u8 *)(state + 0x25) = 1;
            if (*(void **)state != NULL) {
                lightFn_8001db6c(*(void **)state, 1, lbl_803E7374);
            }
            if (!((CmbsrcHitFlag *)(state + 0x27))->disabled) {
                ObjHits_EnableObject(obj);
            }
            if (*(s16 *)(setup + 0x24) != -1) {
                GameBit_Set(*(s16 *)(setup + 0x24), 1);
            }
            *(u8 *)(state + 0x26) = 0xf;
            *(f32 *)(state + 0x14) = lbl_803E7360;
        }
        break;
    }
    cmbsrc_updateVisuals(obj, state);
}

void cmbsrc_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    int lightVariant;

    switch (*(s16 *)(obj + 0x46)) {
    case 0x758:
        lightVariant = 1;
        break;
    case 0x6e8:
    default:
        lightVariant = 0;
        break;
    }
    *(s16 *)(obj + 4) = (s16)(setup[0x18] << 8);
    *(s16 *)(obj + 2) = (s16)(setup[0x19] << 8);
    *(s16 *)(obj + 0) = (s16)(setup[0x1a] << 8);
    *(u8 *)(state + 0x25) = 1;
    *(u8 *)(state + 0x26) = 0xf;
    if (setup[0x2b] == 0) {
        *(u16 *)(state + 0x20) = 0x258;
    } else {
        *(u16 *)(state + 0x20) = setup[0x2b] * 0x3c;
    }
    if (setup[0x29] & 0x1) {
        *(u8 *)(state + 0x22) |= 0x2;
    }
    if (setup[0x2a] & 0x1) {
        *(u8 *)(state + 0x22) |= 0x4;
    }
    if (setup[0x2a] & 0x80) {
        *(u8 *)(state + 0x22) |= 0x8;
    }
    if (setup[0x29] & 0x10) {
        u8 *colorTbl;
        int ci;
        int local;

        if (*(void **)state == NULL) {
            *(void **)state = objCreateLight(obj, 1);
        }
        if (*(void **)state != NULL) {
            modelLightStruct_setField50(*(void **)state, 2);
            if (*(s16 *)(obj + 0x46) == 0x758) {
                lightVecFn_8001dd88(*(void **)state, lbl_803E7360, lbl_803E7360, lbl_803E7360);
            } else {
                lightVecFn_8001dd88(*(void **)state, lbl_803E7360, lbl_803E73A8, lbl_803E7360);
            }
            colorTbl = &lbl_8032BD50[lightVariant * 0x30];
            ci = setup[0x1b] * 3;
            modelLightStruct_setColorsA8AC(*(void **)state, colorTbl[ci], colorTbl[ci + 1],
                                           colorTbl[ci + 2], 0xff);
            modelLightStruct_setColors100104(*(void **)state, colorTbl[ci], colorTbl[ci + 1],
                                             colorTbl[ci + 2], 0xff);
            {
                int n = (int)((setup[0x2a] & 0x8 ? lbl_803E73AC : lbl_803E73B0) *
                              *(f32 *)(obj + 8));
                lightDistAttenFn_8001dc38(*(void **)state, (f32)n, lbl_803E73B4 + (f32)n);
            }
            if (*(u8 *)(state + 0x22) & 0x4) {
                if ((*(int (**)(void *))(*gSHthorntailAnimationInterface + 0x24))(&local) != 0) {
                    lightFn_8001db6c(*(void **)state, 1, lbl_803E7374);
                } else {
                    lightFn_8001db6c(*(void **)state, 0, lbl_803E7374);
                    *(u8 *)(state + 0x25) = 0;
                }
            }
            lightFn_8001d620(*(void **)state, 1, 3);
            lightSetFieldB0(*(void **)state,
                            (int)(lbl_803E7368 * (f32)(u32)colorTbl[ci]),
                            (int)(lbl_803E7368 * (f32)(u32)colorTbl[ci + 1]),
                            (int)(lbl_803E7368 * (f32)(u32)colorTbl[ci + 2]), 0xff);
            if (setup[0x29] & 0x20) {
                lightSetField2FB(*(void **)state, 1);
            }
            if (setup[0x29] & 0x40) {
                if (setup[0x29] & 0x80) {
                    fn_8001D730(*(void **)state, 0, colorTbl[ci], colorTbl[ci + 1],
                                colorTbl[ci + 2], 0x87, lbl_803E73B8 * *(f32 *)(obj + 8));
                } else {
                    fn_8001D730(*(void **)state, 0, colorTbl[ci], colorTbl[ci + 1],
                                colorTbl[ci + 2], 0x87, lbl_803E7370 * *(f32 *)(obj + 8));
                }
            }
            {
                int m = setup[0x2c] & 0x3;
                if (m == 0) {
                    fn_8001D714(*(void **)state, lbl_803E73BC);
                } else if (m == 1) {
                    fn_8001D714(*(void **)state, lbl_803E7384);
                } else if (m == 2) {
                    fn_8001D714(*(void **)state, lbl_803E73C0);
                } else {
                    fn_8001D714(*(void **)state, lbl_803E7360);
                }
            }
            if (setup[0x2a] & 0x4) {
                lightSetField4D(*(void **)state, 0);
            } else {
                lightSetField4D(*(void **)state, 1);
            }
        }
    }
    if (*(void **)(obj + 0x54) != NULL) {
        ((CmbsrcHitFlag *)(state + 0x27))->disabled = 1;
        ObjHitbox_SetSphereRadius(obj,
            (int)(lbl_803E7374 *
                  (*(f32 *)(setup + 0x20) * (*(f32 *)(obj + 8) * lbl_8032BD10[setup[0x1b]]))));
        if (setup[0x29] & 0x4) {
            ObjHits_SetHitVolumeSlot(obj, 0x1f, 1, 0);
            ((CmbsrcHitFlag *)(state + 0x27))->disabled = 0;
        } else {
            ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
        }
        if (setup[0x2a] & 0x40) {
            ObjHits_SyncObjectPositionIfDirty(obj);
            ((CmbsrcHitFlag *)(state + 0x27))->disabled = 0;
        } else {
            ObjHits_MarkObjectPositionDirty(obj);
        }
        if (setup[0x2a] & 0x30) {
            ((CmbsrcHitFlag *)(state + 0x27))->disabled = 0;
        }
        if (((CmbsrcHitFlag *)(state + 0x27))->disabled) {
            ObjHits_DisableObject(obj);
        }
    }
    *(f32 *)(state + 0x10) = (f32)randomGetRange(0, 0x64);
    *(f32 *)(state + 0x18) = lbl_803E7374 * *(f32 *)(setup + 0x20);
    *(void **)(obj + 0xbc) = (void *)cmbsrc_updateAndReturnZero;
}
#pragma peephole on
#pragma scheduling on
#pragma dont_inline reset

extern void fn_8003B608(int r, int g, int b);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int newObj, int a, int b, int c, int d);
extern f32 lbl_803E72F8;
extern f32 lbl_803E7308;
extern void ObjHitbox_SetCapsuleBounds(int obj, int radius, int a, int b);
extern void mathFn_80021ac8(int obj, f32 *vec);
extern void fn_80096C94(int obj, int mode, int p3, void *vec, f32 f, int flag);
extern void objLightFn_8009a1dc(int obj, f32 a, void *pos, int count, int p5);
extern int ObjHits_GetPriorityHitWithPosition(int obj, f32 *a, f32 *b, f32 *c, f32 *x, f32 *y, f32 *z);
extern void ObjHits_RecordObjectHit(int handle, int obj, int a, int b, int c);
extern int Obj_GetPlayerObject(void);
extern f32 sqrtf(f32 x);
extern f32 lbl_8032BBE0[];
extern f32 lbl_803E730C;
extern f32 lbl_803E7310;
extern f32 lbl_803E7314;
extern f32 lbl_803E7318;
extern f32 lbl_803E731C;
extern f32 lbl_803E7320;
extern f32 lbl_803E7324;
extern f32 lbl_803E7328;
extern f32 lbl_803E732C;

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void tree_spawnAmbientEffect(int obj, int p2, s8 index)
{
    int setup = *(int *)(obj + 0x4c);
    int idx;
    int newObj;

    if (Obj_IsLoadingLocked()) {
        newObj = Obj_AllocObjectSetup(0x28, 0x210);
        *(u8 *)(newObj + 0x4) = *(u8 *)(setup + 0x4);
        *(u8 *)(newObj + 0x6) = *(u8 *)(setup + 0x6);
        *(u8 *)(newObj + 0x5) = *(u8 *)(setup + 0x5);
        *(u8 *)(newObj + 0x7) = *(u8 *)(setup + 0x7) - 0xa;
        idx = index;
        *(f32 *)(newObj + 0x8) = *(f32 *)(p2 + idx * 0xc + 0xc);
        *(f32 *)(newObj + 0xc) = *(f32 *)(p2 + idx * 0xc + 0x10);
        *(f32 *)(newObj + 0x10) = *(f32 *)(p2 + idx * 0xc + 0x14);
        *(u16 *)(newObj + 0x1c) = randomGetRange(0x708, 0x1770);
        *(s16 *)(newObj + 0x1e) = 0;
        *(u8 *)(newObj + 0x20) = 0xa;
        *(u8 *)(newObj + 0x21) = 0x28;
        *(u8 *)(newObj + 0x22) = 0x32;
        *(u8 *)(newObj + 0x23) = 0xa;
        *(u8 *)(newObj + 0x24) = 0x28;
        *(s8 *)(newObj + 0x25) = -0x28;
        *(s16 *)(newObj + 0x26) = -1;
        *(int *)(newObj + 0x18) = 0;
        *(int *)(p2 + idx * 4) =
            Obj_SetupObject(newObj, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
    }
}

void tree_updateAmbientEffects(int obj, int p2)
{
    int i;
    int handlePtr;
    int posPtr;

    if (*(int *)(obj + 0xf8) != 0) {
        handlePtr = p2;
        posPtr = p2;
        for (i = 0; i < 3; i++) {
            if (*(int *)handlePtr == 0) {
                *(f32 *)(handlePtr + 0x30) -= timeDelta;
                if (*(f32 *)(handlePtr + 0x30) <= lbl_803E72F8) {
                    *(f32 *)(handlePtr + 0x30) = (f32)randomGetRange(0x3c, 0x12c);
                    tree_spawnAmbientEffect(obj, p2, i);
                }
            } else {
                if ((*(int (**)(int))(*(int *)(*(int *)handlePtr + 0x68) + 0x28))(
                        *(int *)handlePtr) > 3) {
                    *(int *)handlePtr = 0;
                } else {
                    (*(void (**)(int, int))(*(int *)(*(int *)handlePtr + 0x68) + 0x24))(
                        *(int *)handlePtr, posPtr + 0xc);
                }
            }
            handlePtr += 4;
            posPtr += 0xc;
        }
    }
}

void tree_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int setup = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int i;

    if (visible != 0) {
        fn_8003B608(*(u8 *)(setup + 0x20), *(u8 *)(setup + 0x21), *(u8 *)(setup + 0x22));
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7308);
        if (*(u16 *)(state + 0x58) & 0x80) {
            for (i = 0; i < 3; i++) {
                ObjPath_GetPointWorldPosition(obj, i, (f32 *)(state + 0xc),
                    (f32 *)(state + 0x10), (f32 *)(state + 0x14), 0);
                state += 0xc;
            }
        }
        *(int *)(obj + 0xf8) = 1;
    }
}

void tree_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    ObjAnimEventList animOut;

    *(f32 *)(state + 0x44) = lbl_803E730C;
    *(f32 *)(state + 0x40) = lbl_803E72F8;
    *(u16 *)(state + 0x54) = setup[0x1d] << 1;
    *(u16 *)(state + 0x58) = setup[0x1e];
    *(u16 *)(state + 0x58) = *(u16 *)(state + 0x58) << 8;
    *(u16 *)(state + 0x58) |= setup[0x1c];
    *(f32 *)(state + 0x3c) = lbl_803E72F8;
    *(s16 *)(obj + 4) = (s16)(setup[0x18] << 8);
    *(s16 *)(obj + 2) = (s16)(setup[0x19] << 8);
    *(s16 *)(obj + 0) = (s16)(setup[0x1a] << 8);
    *(u8 *)(obj + 0xaf) |= 0x8;
    *(u16 *)(obj + 0xb0) |= 0x2000;
    *(int *)(obj + 0xf8) = 0;
    if (setup[0x1b] != 0) {
        *(f32 *)(state + 0x48) = (f32)(u32)setup[0x1b] / lbl_803E7328;
        *(f32 *)(obj + 8) = *(f32 *)(state + 0x48);
        if (*(f32 *)(obj + 8) == lbl_803E72F8) {
            *(f32 *)(obj + 8) = lbl_803E7308;
        }
        *(f32 *)(obj + 8) = *(f32 *)(obj + 8) * *(f32 *)(*(int *)(obj + 0x50) + 4);
    } else {
        *(f32 *)(state + 0x48) = lbl_803E7308;
    }
    ObjAnim_SetCurrentMove(obj, 0, lbl_803E72F8, 0);
    ObjAnim_AdvanceCurrentMove(lbl_803E7308, lbl_803E7308, obj, &animOut);
    if (*(u16 *)(state + 0x58) & 0x80) {
        *(u16 *)(state + 0x58) |= 0x20;
    }
    switch (*(s16 *)(obj + 0x46)) {
    case 0x798:
        *(u16 *)(state + 0x5a) = 0xa;
        break;
    case 0x799:
        *(u16 *)(state + 0x5a) = 0x9;
        break;
    case 0x70d:
        *(u16 *)(state + 0x5a) = 0x8;
        break;
    case 0x70c:
        *(u16 *)(state + 0x5a) = 0x7;
        ObjHitbox_SetCapsuleBounds(obj, (int)(lbl_803E732C * *(f32 *)(obj + 8)), -0x5, 0x64);
        break;
    case 0x625:
        *(u16 *)(state + 0x5a) = 0x6;
        break;
    case 0x77a:
        *(u16 *)(state + 0x5a) = 0x5;
        break;
    case 0x624:
        *(u16 *)(state + 0x5a) = 0x4;
        break;
    case 0x39:
        *(u16 *)(state + 0x5a) = 0x3;
        break;
    case 0x10b:
        *(u16 *)(state + 0x5a) = 0x2;
        break;
    case 0x5d1:
        *(u16 *)(state + 0x5a) = 0x1;
        break;
    default:
        *(u16 *)(state + 0x5a) = 0x0;
        break;
    }
    if (!(*(u16 *)(state + 0x58) & 0x20)) {
        ObjHits_DisableObject(obj);
    }
}

void tree_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int hit;
    int player;
    int i;
    int hp;
    f32 dx, dz, dist;
    f32 out8, outc, out10;
    f32 vec14[3];
    f32 colorVec[3];
    f32 intensity;
    f32 *ctbl;
    ObjAnimEventList animOut;

    ObjAnim_AdvanceCurrentMove(*(f32 *)(state + 0x44), timeDelta, obj, &animOut);
    if (*(u16 *)(state + 0x58) != 0) {
        if (*(f32 *)(state + 0x3c) > lbl_803E72F8) {
            *(f32 *)(state + 0x3c) -= timeDelta;
        }
        if (*(f32 *)(state + 0x44) > lbl_803E730C) {
            *(f32 *)(state + 0x44) -= lbl_803E7310;
        }
        if (*(u16 *)(state + 0x58) & 0x80) {
            tree_updateAmbientEffects(obj, state);
        }
        if (*(u16 *)(state + 0x58) & 0x20) {
            if (*(u16 *)(state + 0x58) & 0xc0) {
                hit = ObjHits_GetPriorityHitWithPosition(obj, &out10, &outc, &out8,
                                                         &colorVec[0], &colorVec[1], &colorVec[2]);
            } else {
                hit = ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129,
                                                                state + 0x50);
            }
            if (*(f32 *)(state + 0x4c) >= lbl_803E72F8) {
                *(f32 *)(state + 0x4c) -= timeDelta;
            }
            if (hit != 0 && hit != 0x11 && *(f32 *)(state + 0x4c) <= lbl_803E72F8) {
                if (*(u16 *)(state + 0x58) & 0xc0) {
                    colorVec[0] += playerMapOffsetX;
                    colorVec[2] += playerMapOffsetZ;
                    objLightFn_8009a1dc(obj, lbl_803E7314, vec14, 1, 0);
                    Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
                }
                if (*(u16 *)(state + 0x58) & 0xf) {
                    intensity = *(f32 *)(state + 0x48);
                    ctbl = &lbl_8032BBE0[*(u16 *)(state + 0x5a) * 4];
                    colorVec[0] = intensity * ctbl[0];
                    colorVec[1] = intensity * ctbl[1];
                    colorVec[2] = intensity * ctbl[2];
                    mathFn_80021ac8(obj, colorVec);
                    fn_80096C94(obj, *(u16 *)(state + 0x58) & 0xf, 0x14, vec14,
                                *(f32 *)(state + 0x48) * ctbl[3], 0);
                }
                *(f32 *)(state + 0x44) = lbl_803E7318;
                *(f32 *)(state + 0x4c) = lbl_803E731C;
                if (*(u16 *)(state + 0x58) & 0x80) {
                    if (hit != 0) {
                        hp = state;
                        for (i = 0; i < 3; i++) {
                            if (*(int *)hp != 0) {
                                if ((*(int (**)(int))(*(int *)(*(int *)hp + 0x68) + 0x28))(
                                        *(int *)hp) > 1) {
                                    ObjHits_RecordObjectHit(*(int *)(state + i * 4), obj, 0xe, 1, 0);
                                    break;
                                }
                            }
                            hp += 4;
                        }
                    }
                }
            }
        }
        player = Obj_GetPlayerObject();
        if (player != 0 && !(*(u16 *)(state + 0x58) & 0x100) && (*(u16 *)(state + 0x58) & 0xf)) {
            dx = *(f32 *)(obj + 0xc) - *(f32 *)(player + 0xc);
            dz = *(f32 *)(obj + 0x14) - *(f32 *)(player + 0x14);
            dist = sqrtf(dx * dx + dz * dz);
            hit = (int)dist;
            if ((u16)hit < *(u16 *)(state + 0x54)) {
                if ((*(u16 *)(state + 0x58) & 0x10) &&
                    *(u16 *)(state + 0x56) >= *(u16 *)(state + 0x54) &&
                    *(f32 *)(state + 0x3c) <= lbl_803E72F8) {
                    intensity = *(f32 *)(state + 0x48);
                    ctbl = &lbl_8032BBE0[*(u16 *)(state + 0x5a) * 4];
                    colorVec[0] = intensity * ctbl[0];
                    colorVec[1] = intensity * ctbl[1];
                    colorVec[2] = intensity * ctbl[2];
                    mathFn_80021ac8(obj, colorVec);
                    fn_80096C94(obj, *(u16 *)(state + 0x58) & 0xf, 0x14, vec14,
                                *(f32 *)(state + 0x48) * ctbl[3], 1);
                    *(f32 *)(state + 0x3c) = lbl_803E7320;
                }
                *(f32 *)(state + 0x40) -= timeDelta;
                if (*(f32 *)(state + 0x40) <= lbl_803E72F8) {
                    intensity = *(f32 *)(state + 0x48);
                    ctbl = &lbl_8032BBE0[*(u16 *)(state + 0x5a) * 4];
                    colorVec[0] = intensity * ctbl[0];
                    colorVec[1] = intensity * ctbl[1];
                    colorVec[2] = intensity * ctbl[2];
                    mathFn_80021ac8(obj, colorVec);
                    fn_80096C94(obj, *(u16 *)(state + 0x58) & 0xf, 1, vec14,
                                *(f32 *)(state + 0x48) * ctbl[3], 0);
                    *(f32 *)(state + 0x40) += lbl_803E7324;
                }
            }
            *(u16 *)(state + 0x56) = hit;
        }
    }
}
#pragma peephole on
#pragma scheduling on
#pragma dont_inline reset

extern int *ObjList_GetObjects(int *startIndex, int *objectCount);

#pragma scheduling off
#pragma peephole off
void gf_levelcon_findLinkedObjects(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int *objects;
    int objectCount;
    int objectIndex;
    int o;

    *(int *)(state + 0) = 0;
    *(int *)(state + 4) = 0;
    *(int *)(state + 8) = 0;
    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    for (; objectIndex < objectCount; objectIndex++) {
        o = objects[objectIndex];
        if ((u32)o != (u32)obj && *(void **)(o + 0x4c) != NULL) {
            switch (*(int *)(*(int *)(o + 0x4c) + 0x14)) {
            case 0x477E3:
                *(int *)(state + 0) = o;
                break;
            case 0x4A946:
                *(int *)(state + 4) = o;
                break;
            case 0x4A947:
                *(int *)(state + 8) = o;
                break;
            }
        }
    }
}
#pragma peephole on
#pragma scheduling on

extern int *gPlayerInterface;
extern int *gRomCurveInterface;
extern int curveFn_80010320(int curve, f32 val);
extern int getAngle(f32 dx, f32 dz);
extern f32 oneOverTimeDelta;
extern f32 Vec_xzDistance(int a, int b);
extern void characterDoEyeAnims(int obj, int p2);
extern void doNothing_80062A50(int obj, f32 x, f32 y, f32 z);
extern void dll_2E_func03(int obj, int p2);
extern void dll_2E_func05(int obj, int p2, int p3, int p4, int p5);
extern void dll_2E_func09(int p1, void *p2, void *p3, int p4);
extern int lbl_802C25B8[];
extern int lbl_802C25C8[];
extern void *lbl_803AD278[];
extern void *lbl_803AD288[];
extern f32 lbl_803E6CF0;
extern f32 lbl_803E6CF4;
extern f32 lbl_803E6CF8;
extern f32 lbl_803E6D08;
extern f32 lbl_803E6D0C;
extern f32 lbl_803E6D10;
extern f32 lbl_803E6D14;
extern f32 lbl_803E6D18;
extern f32 lbl_803E6D1C;

typedef struct Blob16 { int a, b, c, d; } Blob16;
typedef struct ObjXform {
    s16 rx, ry, rz;
    f32 scale;
    f32 x, y, z;
} ObjXform;

#pragma peephole off
#pragma scheduling off
void dll_28B_free(int obj) { ObjGroup_RemoveObject(obj, 3); }

void dll_28B_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int *)(obj + 0xb8);
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6D18);
        dll_2E_func06(obj, state + 0x35c, 0);
    }
}

int fn_802239A4(int obj, int ai)
{
    int state = *(int *)(obj + 0xb8);
    int result;

    if (*(s8 *)(ai + 0x27b) != 0) {
        *(u8 *)(state + 0xac0) &= ~1;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, ai, 3);
        result = 0;
    } else if (*(s8 *)(ai + 0x346) != 0) {
        result = 3;
    } else {
        result = 0;
    }
    return result;
}

int fn_80223A1C(int obj, int ai)
{
    int state = *(int *)(obj + 0xb8);
    f32 dist;

    if (*(s8 *)(ai + 0x27b) != 0) {
        *(u8 *)(state + 0xac0) |= 1;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, ai, 1);
    }
    *(f32 *)(state + 0xabc) -= timeDelta;
    dist = *(f32 *)(state + 0xab8);
    if (dist > lbl_803E6CF0) {
        return 2;
    }
    if (dist >= lbl_803E6CF4) {
        return 0;
    }
    if (*(f32 *)(state + 0xabc) <= lbl_803E6CF8) {
        *(f32 *)(state + 0xabc) = (f32)randomGetRange(0x78, 0xfa);
        return 4;
    }
    return 0;
}

int fn_80223AFC(int obj, int ai)
{
    int state = *(int *)(obj + 0xb8);
    int curve = state + 0x9b0;

    if (*(s8 *)(ai + 0x27b) != 0) {
        *(u8 *)(state + 0xac0) &= ~1;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, ai, 2);
    }
    if (curveFn_80010320(curve, lbl_803E6D08) != 0 || *(int *)(curve + 0x10) != 0) {
        (*(void (**)(int))(*gRomCurveInterface + 0x90))(curve);
    }
    if (*(f32 *)(state + 0xab8) < lbl_803E6D0C) {
        return 3;
    }
    return 0;
}

int fn_80223BC4(int obj, int ai)
{
    int player = Obj_GetPlayerObject();

    if (*(s8 *)(ai + 0x27a) != 0) {
        *(f32 *)(ai + 0x2a0) = lbl_803E6D10;
        getAngle(*(f32 *)(obj + 0xc) - *(f32 *)(player + 0xc),
                 *(f32 *)(obj + 0x14) - *(f32 *)(player + 0x14));
    }
    return 0;
}

int fn_80223C34(int obj, int ai)
{
    int state = *(int *)(obj + 0xb8);

    *(f32 *)(obj + 0x24) = oneOverTimeDelta * (*(f32 *)(state + 0xa18) - *(f32 *)(obj + 0xc));
    *(f32 *)(obj + 0x2c) = oneOverTimeDelta * (*(f32 *)(state + 0xa20) - *(f32 *)(obj + 0x14));
    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0xa18);
    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0xa20);
    *(s16 *)obj = getAngle(-*(f32 *)(state + 0xa24), -*(f32 *)(state + 0xa2c));
    ObjAnim_SampleRootCurvePhase(
        sqrtf(*(f32 *)(obj + 0x24) * *(f32 *)(obj + 0x24) +
              *(f32 *)(obj + 0x2c) * *(f32 *)(obj + 0x2c)),
        (ObjAnimComponent *)obj, (f32 *)(ai + 0x2a0));
    return 0;
}

int fn_80223CF0(int obj, int ai)
{
    if (*(s8 *)(ai + 0x27a) != 0) {
        *(f32 *)(ai + 0x2a0) = lbl_803E6D14;
    }
    return 0;
}

void dll_28B_update(int obj)
{
    f32 ox, oy, oz;
    ObjXform xform;
    f32 mtx[12];
    int state = *(int *)(obj + 0xb8);
    int player = Obj_GetPlayerObject();

    *(f32 *)(state + 0xab8) = Vec_xzDistance(obj + 0x18, player + 0x18);
    *(int *)state |= 0x2000000;
    (*(void (**)(int, int, f32, f32, void *, void *))(*gPlayerInterface + 0x8))(
        obj, state, timeDelta, timeDelta, lbl_803AD288, lbl_803AD278);
    if ((*(u8 *)(state + 0xac0) & 1) != 0) {
        *(u8 *)(state + 0x96d) &= ~1;
    } else {
        *(u8 *)(state + 0x96d) |= 1;
    }
    dll_2E_func03(obj, state + 0x35c);
    characterDoEyeAnims(obj, state + 0x980);
    xform.x = *(f32 *)(obj + 0xc);
    xform.y = *(f32 *)(obj + 0x10);
    xform.z = *(f32 *)(obj + 0x14);
    xform.rx = *(s16 *)(obj + 0);
    xform.ry = *(s16 *)(obj + 2);
    xform.rz = *(s16 *)(obj + 4);
    xform.scale = lbl_803E6D18;
    setMatrixFromObjectPos(mtx, &xform);
    Matrix_TransformPoint(mtx, lbl_803E6CF8, lbl_803E6CF8, lbl_803E6CF8, &ox, &oy, &oz);
    doNothing_80062A50(obj, ox, oy, oz);
}

void dll_28B_init(int obj)
{
    int two;
    Blob16 blockB;
    Blob16 blockA;
    int state = *(int *)(obj + 0xb8);

    blockA = *(Blob16 *)lbl_802C25B8;
    blockB = *(Blob16 *)lbl_802C25C8;
    two = 2;
    dll_2E_func05(obj, state + 0x35c, -0x2aaa, 0x638e, 8);
    dll_2E_func09(state + 0x35c, &blockB, &blockA, 8);
    *(u8 *)(state + 0x96d) |= 0x22;
    (*(void (**)(int, int, f32, int *, int))(*gRomCurveInterface + 0x8c))(
        state + 0x9b0, obj, lbl_803E6D1C, &two, -1);
    (*(void (**)(int, int, int, int))(*gPlayerInterface + 0x4))(obj, state, 4, 4);
    ObjGroup_AddObject(obj, 3);
}

void dll_28B_initialise(void)
{
    lbl_803AD288[0] = (void *)fn_80223D10;
    lbl_803AD288[1] = (void *)fn_80223CF0;
    lbl_803AD288[2] = (void *)fn_80223C34;
    lbl_803AD288[3] = (void *)fn_80223BC4;
    lbl_803AD278[0] = (void *)fn_80223BBC;
    lbl_803AD278[1] = (void *)fn_80223AFC;
    lbl_803AD278[2] = (void *)fn_80223A1C;
    lbl_803AD278[3] = (void *)fn_802239A4;
}
#pragma scheduling on
#pragma peephole on
