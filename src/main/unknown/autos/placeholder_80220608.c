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

void drenergydisc_update(int obj)
{
    int *texture;
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        if ((*(s8 *)state) >= 0) {
            *(u8 *)state |= 0x80;
            Sfx_PlayFromObject(obj, 0x30c);
        }

        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *texture = 0x100;
        }

        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *(s16 *)((char *)texture + 0xa) =
                *(s16 *)((char *)texture + 0xa) + (s16)(lbl_803DC380 * framesThisStep);
            if (*(s16 *)((char *)texture + 0xa) < -0x1000) {
                *(s16 *)((char *)texture + 0xa) = 0;
            }
        }
    }

    if (GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E6BB0, 0);
    }
}

void drenergydisc_init(int obj, int setup)
{
    int *texture;
    int state = *(int *)(obj + 0xb8);

    *(s16 *)obj = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    if (GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        *(u8 *)state |= 0x80;
        Sfx_PlayFromObject(obj, 0x30c);
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *texture = 0x100;
        }
    } else {
        *(u8 *)state &= 0x7f;
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *texture = 0;
        }
    }
    *(u16 *)(obj + 0xb0) |= 0x6000;
}

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
#pragma scheduling off
void wcbeacon_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    (*(void (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac));
    *(s16 *)obj = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    *(u8 *)(obj + 0xad) = *(u8 *)(setup + 0x19);
    if ((s8)*(u8 *)(obj + 0xad) >= (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
            *(u8 *)(state + 4) = 3;
        } else {
            *(u8 *)(state + 4) = 1;
        }
    }
}
#pragma scheduling on

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
#pragma scheduling off
void wctile_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    *(f32 *)(obj + 0x10) = lbl_803E6DFC + *(f32 *)(setup + 0xc);
    *(u8 *)(obj + 0xad) = *(u8 *)(setup + 0x19);
    if ((s8)*(u8 *)(obj + 0xad) >= (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }
    *(s16 *)(state + 8) = *(s16 *)(setup + 0x1a);
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), fn_800284CC);
    *(u8 *)(obj + 0x36) = 0;
}
#pragma scheduling on
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
#pragma scheduling off
void wcpressures_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    *(s16 *)obj = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(u16 *)(obj + 0xb0) |= 0x6000;
    *(u8 *)(obj + 0xad) = (s8)*(u8 *)(setup + 0x19);
    if ((s8)*(u8 *)(obj + 0xad) >= (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }

    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1a)) != 0) {
        *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc) - (f32)*(u8 *)(setup + 0x1c);
        *(u8 *)state = 0x1e;
        *(u8 *)(state + 1) = 2;
    }

    ObjGroup_AddObject(obj, 0x31);
    for (i = 0; i < 10; i++) {
        *(int *)(state + 4 + i * 4) = 0;
    }
    *(void **)(obj + 0xbc) = wcpressures_tileStateCallback;
}
#pragma scheduling on
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
#pragma scheduling off
void wctrexstatu_hitDetect(int obj)
{
    if (*(int *)(obj + 0xf4) != 0 && randomGetRange(0, 5) == 0) {
        if ((s8)*(u8 *)(obj + 0xad) == 0) {
            (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(obj, 0x73f, 0, 2, -1, obj);
        } else {
            (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(obj, 0x740, 0, 2, -1, obj);
        }
    }
}
#pragma scheduling on
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
