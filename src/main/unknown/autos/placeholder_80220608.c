#include "ghidra_import.h"
#include "main/objanim.h"

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
