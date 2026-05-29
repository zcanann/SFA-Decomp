#include "ghidra_import.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objHitReact.h"

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

typedef struct DrLightBeaFlags {
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 pad : 6;
} DrLightBeaFlags;

int drlightbea_getExtraSize(void) { return 0xc; }
int drlightbea_getObjectTypeId(void) { return 0; }
#pragma scheduling off
void drlightbea_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    void *buffer = *(void **)state;

    if (buffer != NULL) {
        mm_free(buffer);
        *(void **)state = NULL;
    }
}
#pragma scheduling reset

void drlightbea_hitDetect(void) {}
#pragma peephole off
void drlightbea_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (((DrLightBeaFlags *)(state + 4))->bit40) {
        Obj_FreeObject(obj);
    }
}
#pragma peephole reset

void drlightbea_init(int obj)
{
    int state = *(int *)(obj + 0xb8);
    ((DrLightBeaFlags *)(state + 4))->bit80 = 0;
    *(void **)state = NULL;
    ((DrLightBeaFlags *)(state + 4))->bit40 = 0;
}

void drlightbea_release(void) {}
void drlightbea_initialise(void) {}

int drmusiccont_getExtraSize(void) { return 4; }
int drmusiccont_getObjectTypeId(void) { return 0; }
void drmusiccont_free(int obj) { fn_8009436C(obj); }
#pragma peephole off
void drmusiccont_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6BC8);
    }
}
#pragma peephole reset
void drmusiccont_hitDetect(void) {}
void drmusiccont_release(void) {}
void drmusiccont_initialise(void) {}

int drcloudper_getExtraSize(void) { return 0x10; }
int drcloudper_getObjectTypeId(void) { return 0; }
#pragma scheduling off
void drcloudper_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0x13);
    ObjGroup_RemoveObject(obj, 0x39);
}
#pragma scheduling reset
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
    return *(s8 *)(obj + 0x19);
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

typedef struct DrBarrelGrFlags {
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 pad : 6;
} DrBarrelGrFlags;

int drbarrelgr_getExtraSize(void) { return 0x12c; }
int drbarrelgr_getObjectTypeId(void) { return 0; }
#pragma scheduling off
void drbarrelgr_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    void *heldObj = *(void **)(state + 8);

    if (heldObj != NULL) {
        gunpowderbarrel_clearHeldState((int)heldObj);
        ((DrBarrelGrFlags *)(state + 0x12a))->bit80 = 0;
    }
}
#pragma scheduling reset
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

extern void dll_2E_func03(int obj, int p2);
extern void characterDoEyeAnims(int obj, int p2);
extern void buttonDisable(int a, int b);
extern ObjHitReactEntry lbl_8032AEC0[];
extern f32 lbl_803E6CE4;
extern f32 lbl_803E6CDC;

#pragma peephole off
#pragma scheduling off
void earthwalker_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int prevAnim;
    int hitOut;

    hitOut = objHitReact_update(obj, lbl_8032AEC0, 1, *(u8 *)(state + 0x65a), (f32 *)(state + 0x654));
    *(u8 *)(state + 0x65a) = hitOut;
    if ((u8)hitOut != 0) {
        return;
    }

    if (*(u8 *)(state + 0x65b) >= 4 && *(u8 *)(state + 0x65b) <= 8) {
        if (*(s16 *)(obj + 0xa0) != 0x203) {
            ObjAnim_SetCurrentMove(obj, 0x203, lbl_803E6CE4, 0);
        }
    } else {
        if (*(s16 *)(obj + 0xa0) != 2) {
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E6CE4, 0);
        }
    }

    prevAnim = *(u8 *)(state + 0x600);
    dll_2E_func03(obj, state);
    if (*(u8 *)(state + 0x65b) >= 4 && *(u8 *)(state + 0x65b) <= 7 && prevAnim != 1 &&
        *(u8 *)(state + 0x600) == 1) {
        Sfx_PlayFromObject(obj, 0x3e6);
    }

    characterDoEyeAnims(obj, state + 0x624);
    if (*(u8 *)(state + 0x659) & 1) {
        return;
    }

    switch (*(u8 *)(state + 0x658)) {
    case 0:
        if (*(u8 *)(obj + 0xaf) & 1) {
            buttonDisable(0, 0x100);
            GameBit_Set(0x7fb, 1);
            *(u8 *)(state + 0x658) = 2;
            *(u8 *)(state + 0x659) |= 1;
        }
        break;
    case 1:
        break;
    case 2:
        if (*(u8 *)(obj + 0xaf) & 1) {
            int newState;
            switch (*(u8 *)(state + 0x65b)) {
            case 0:
                if ((*(u8 (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) == 2) {
                    if (*(s8 *)(state + 0x65c) == 0x14) {
                        newState = 0x15;
                    } else {
                        newState = 0x14;
                    }
                } else if (GameBit_Get(0xc90) != 0) {
                    newState = 5;
                } else if (GameBit_Get(0xc36) != 0) {
                    newState = 4;
                } else if (GameBit_Get(0xc55) != 0) {
                    newState = 3;
                } else if (GameBit_Get(0x7fc) != 0) {
                    newState = 3;
                } else if (*(s8 *)(state + 0x65c) == 0) {
                    newState = 1;
                } else if (*(s8 *)(state + 0x65c) == 1) {
                    newState = 2;
                } else {
                    newState = 0;
                }
                break;
            case 9:
                if ((*(u8 (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) == 2) {
                    if (*(s8 *)(state + 0x65c) == 0x16) {
                        newState = 0x17;
                    } else {
                        newState = 0x16;
                    }
                } else if (GameBit_Get(0xc90) != 0) {
                    newState = 0xa;
                } else if (GameBit_Get(0xc36) != 0) {
                    newState = 9;
                } else if (GameBit_Get(0xc55) != 0) {
                    newState = 8;
                } else if (GameBit_Get(0x7fc) != 0) {
                    newState = 8;
                } else if (*(s8 *)(state + 0x65c) == 6) {
                    newState = 7;
                } else {
                    newState = 6;
                }
                break;
            case 10:
                if ((*(u8 (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) == 2) {
                    if (*(s8 *)(state + 0x65c) == 0x18) {
                        newState = 0x19;
                    } else if (*(s8 *)(state + 0x65c) == 0x19) {
                        newState = 0x1a;
                    } else if (*(s8 *)(state + 0x65c) == 0x1a) {
                        newState = 0x1b;
                    } else {
                        newState = 0x18;
                    }
                } else if (GameBit_Get(0xc90) != 0) {
                    newState = 0xf;
                } else if (GameBit_Get(0xc36) != 0) {
                    newState = 0xe;
                } else if (GameBit_Get(0xc55) != 0) {
                    newState = 0xd;
                } else if (GameBit_Get(0x7fc) != 0) {
                    if (*(s8 *)(state + 0x65c) == 0xb) {
                        newState = 0xc;
                    } else {
                        newState = 0xb;
                    }
                }
                break;
            case 11:
                if ((*(u8 (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) == 2) {
                    if (*(s8 *)(state + 0x65c) == 0x1c) {
                        newState = 0x1d;
                    } else if (*(s8 *)(state + 0x65c) == 0x1d) {
                        newState = 0x1e;
                    } else if (*(s8 *)(state + 0x65c) == 0x1e) {
                        newState = 0x1f;
                    } else {
                        newState = 0x1c;
                    }
                } else if (GameBit_Get(0xc90) != 0) {
                    newState = 0x13;
                } else if (GameBit_Get(0xc36) != 0) {
                    if (*(s8 *)(state + 0x65c) == 0x11) {
                        newState = 0x12;
                    } else {
                        newState = 0x11;
                    }
                } else if (GameBit_Get(0xc55) != 0) {
                    newState = 0x10;
                } else if (GameBit_Get(0x7fc) != 0) {
                    newState = 0x10;
                }
                break;
            case 1:
                if ((*(u8 (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) == 2) {
                    if (GameBit_Get(0xc92) != 0) {
                        *(u8 *)(obj + 0xaf) |= 8;
                        newState = -1;
                    } else if (GameBit_Get(0x235) != 0) {
                        newState = 9;
                    } else {
                        newState = 8;
                    }
                } else if (GameBit_Get(0xc90) != 0) {
                    newState = 7;
                } else if (GameBit_Get(0xc36) != 0) {
                    newState = 6;
                } else if (GameBit_Get(0xc55) != 0) {
                    newState = 5;
                } else {
                    newState = 0;
                }
                break;
            case 3:
                newState = 0;
                break;
            case 2:
                newState = 0;
                break;
            case 4:
                newState = 0;
                break;
            case 5:
                newState = 1;
                break;
            case 6:
                newState = 2;
                break;
            case 7:
                newState = 3;
                break;
            case 8:
                if ((u32)GameBit_Get(0x9ad) == 0) {
                    newState = 4;
                    buttonDisable(0, 0x100);
                    GameBit_Set(0x9ad, 1);
                } else {
                    newState = 0;
                }
                break;
            }
            if (newState != -1) {
                buttonDisable(0, 0x100);
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(newState, obj, -1);
                *(s8 *)(state + 0x65c) = newState;
            }
        }
        break;
    }

    ObjAnim_AdvanceCurrentMove(lbl_803E6CDC, timeDelta, obj, 0);
}
#pragma peephole on
#pragma scheduling on

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
extern f32 lbl_803E6D20;
extern f32 lbl_803E6D24;
extern f32 lbl_803E6D28;
extern f32 lbl_803E6D2C;
extern f32 lbl_803E6D30;
extern f32 lbl_803E6D34;
extern f32 lbl_803E6D3C;
extern f32 lbl_803E6D40;
#pragma peephole off
#pragma scheduling off
void wcbouncycra_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if ((*(u8 *)(state + 0xa) & 1) == 0) {
        int n = (int)((f32)*(s16 *)(state + 8) - timeDelta);
        *(s16 *)(state + 8) = n;
        if ((s16)n <= 0) {
            f32 v = lbl_803E6D20;
            f32 dist;

            if ((void *)ObjGroup_FindNearestObject(3, obj, &v) == NULL) {
                dist = lbl_803E6D24;
            } else if (v < lbl_803E6D28) {
                dist = lbl_803E6D2C;
            } else if (v > lbl_803E6D30) {
                dist = lbl_803E6D24;
            } else {
                dist = (lbl_803E6D38 - (v - lbl_803E6D28) / lbl_803E6D34) * lbl_803E6D2C;
            }
            *(f32 *)(obj + 0x28) = dist;
            *(u8 *)(state + 0xa) |= 1;
            *(u8 *)(state + 0xb) = 0;
        }
    } else {
        *(f32 *)(obj + 0x28) = lbl_803E6D3C * timeDelta + *(f32 *)(obj + 0x28);
        *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x28) * timeDelta + *(f32 *)(obj + 0x10);
        if (*(f32 *)(obj + 0x10) <= *(f32 *)(state + 0)) {
            *(f32 *)(obj + 0x10) =
                *(f32 *)(obj + 0x10) + (*(f32 *)(state + 0) - *(f32 *)(obj + 0x10));
            *(f32 *)(obj + 0x28) = lbl_803E6D40 * -*(f32 *)(obj + 0x28);
            *(u8 *)(state + 0xb) += 1;
            if (*(u8 *)(state + 0xb) > 0xa) {
                *(u8 *)(state + 0xa) &= ~1;
                *(s16 *)(state + 8) = 0x28;
                *(f32 *)(obj + 0x10) = *(f32 *)(state + 0);
                *(f32 *)(obj + 0x28) = lbl_803E6D24;
            }
        }
    }
}
#pragma scheduling on
#pragma peephole on
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
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

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

typedef struct {
    u8 phase : 3;
    u8 sfxActive : 1;
    u8 pad : 4;
} PushBlockFlags;

extern u8 fn_80296414(int player, int obj, int dir);
extern void Sfx_SetObjectSfxVolume(int obj, int sound, int vol, f32 v);
extern int fn_802242A8(int obj, int state, int player);
extern int Obj_GetPlayerObject(void);
extern int ObjGroup_FindNearestObject(int group, int obj, f32 *out);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern f32 sqrtf(f32 x);
extern f32 fn_80293E80(f32 x);
extern void fn_80097B30(int obj, int a, int b, int c, f32 e, f32 f, f32 g, f32 h, int i,
                        int j, int k);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sound);
extern void ObjHits_DisableObject(int obj);
extern void ObjHits_EnableObject(int obj);
extern int gameBitIncrement(int id);
extern f32 lbl_803E6D58;
extern f32 lbl_803E6D5C;
extern f32 lbl_803E6D60;
extern f32 lbl_803E6D64;
extern f32 lbl_803E6D68;
extern f32 lbl_803E6D6C;
extern f32 lbl_803E6D70;
extern f32 lbl_803E6D74;
extern f32 lbl_803E6D78;
extern f32 lbl_803E6D7C;
extern f32 lbl_803E6D80;
extern f32 lbl_803E6D84;
extern f32 lbl_803E6D88;
extern f32 lbl_803E6D8C;
extern f32 lbl_803E6D90;
extern f32 lbl_803E6D94;

#define PB_IFACE (*(int *)(*(int *)(*(int *)(state + 0x268) + 0x68)))

#pragma peephole off
#pragma scheduling off
void wcpushblock_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int player = Obj_GetPlayerObject();
    f32 range = lbl_803E6D58;
    f32 dist;
    int *tex;
    int moved;

    if (*(void **)(state + 0x268) == 0) {
        *(int *)(state + 0x268) = ObjGroup_FindNearestObject(9, obj, &range);
        *(u8 *)(obj + 0x36) = 0;
        return;
    }
    tex = objFindTexture(obj, 0, 0);
    if (tex != 0) {
        *tex = 0;
    }
    *(u16 *)(obj + 0xb0) &= ~0x100;

    if (((PushBlockFlags *)(state + 0x285))->phase != 6) {
        if ((s8)*(u8 *)(obj + 0xad) == 1) {
            if ((u32)GameBit_Get(2066) != 0) {
                ((PushBlockFlags *)(state + 0x285))->phase = 6;
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x34))(
                    *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
                (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x20))(
                    obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                    (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
            } else if ((u32)GameBit_Get(2056) != 0) {
                ((PushBlockFlags *)(state + 0x285))->phase = 3;
            }
        } else {
            if ((u32)GameBit_Get(2067) != 0) {
                ((PushBlockFlags *)(state + 0x285))->phase = 6;
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x50))(
                    *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
                (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x3c))(
                    obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                    (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
            } else if ((u32)GameBit_Get(2057) != 0) {
                ((PushBlockFlags *)(state + 0x285))->phase = 3;
            }
        }
    }

    {
        u32 ph = ((PushBlockFlags *)(state + 0x285))->phase;
        if (ph != 3 && ph != 5) {
            if ((s8)*(u8 *)(obj + 0xad) == 1) {
                fn_80097B30(obj, 1, 3, 1, lbl_803E6D5C, lbl_803E6D60, lbl_803E6D5C, lbl_803E6D60,
                            50, 0, 0);
            } else {
                fn_80097B30(obj, 1, 1, 1, lbl_803E6D5C, lbl_803E6D60, lbl_803E6D5C, lbl_803E6D60,
                            50, 0, 0);
            }
        }
    }

    switch (((PushBlockFlags *)(state + 0x285))->phase) {
    case 0:
        if ((s8)*(u8 *)(obj + 0xad) == 1) {
            (*(void (**)(int, int, int, int))(PB_IFACE + 0x30))(
                *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
            (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x20))(
                obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
        } else {
            (*(void (**)(int, int, int, int))(PB_IFACE + 0x4c))(
                *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
            (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x3c))(
                obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
        }
        ((PushBlockFlags *)(state + 0x285))->phase = 1;
        break;
    case 1:
        {
            int a = *(u8 *)(obj + 0x36) + framesThisStep * 8;
            if (a > 255) {
                a = 255;
            }
            *(u8 *)(obj + 0x36) = a;
        }
        {
            f32 zero = lbl_803E6D64;
            *(f32 *)(obj + 0x24) = zero;
            *(f32 *)(obj + 0x2c) = zero;
        }
        if (fn_80296414(player, obj, state + 0x282) != 0) {
            u32 dir = *(u8 *)(state + 0x282);
            if ((s8)*(u8 *)(obj + 0xad) == 1) {
                if (dir == 0) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x38))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), -1, 0, PB_IFACE);
                } else if (dir == 1) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x38))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 1, 0, PB_IFACE);
                } else if (dir == 2) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x38))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 0, -1, PB_IFACE);
                } else if (dir == 3) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x38))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 0, 1, PB_IFACE);
                }
            } else {
                if (dir == 0) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x54))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), -1, 0, PB_IFACE);
                } else if (dir == 1) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x54))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 1, 0, PB_IFACE);
                } else if (dir == 2) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x54))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 0, -1, PB_IFACE);
                } else if (dir == 3) {
                    *(u8 *)(state + 0x284) =
                        (*(int (**)(int, int, int, f32 *, f32 *, int, int, int))(PB_IFACE + 0x54))(
                            obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                            (f32 *)(state + 0x26c), (f32 *)(state + 0x270), 0, 1, PB_IFACE);
                }
            }
            if (*(f32 *)(state + 0x26c) == *(f32 *)(obj + 0xc) &&
                *(f32 *)(state + 0x270) == *(f32 *)(obj + 0x10)) {
                ;
            } else {
                ((PushBlockFlags *)(state + 0x285))->phase = 2;
            }
        }
        break;
    case 2:
        if (lbl_803E6D64 != *(f32 *)(obj + 0x24) || lbl_803E6D64 != *(f32 *)(obj + 0x2c)) {
            f32 speed = sqrtf(*(f32 *)(obj + 0x24) * *(f32 *)(obj + 0x24) +
                              *(f32 *)(obj + 0x2c) * *(f32 *)(obj + 0x2c)) -
                        lbl_803E6D68;
            if (speed < lbl_803E6D64) {
                speed = lbl_803E6D64;
            }
            dist = lbl_803E6D54 + lbl_803E6D6C * speed / lbl_803E6D70;
            if (dist > lbl_803E6D74) {
                dist = lbl_803E6D74;
            }
            Sfx_KeepAliveLoopedObjectSound(obj, 200);
            Sfx_SetObjectSfxVolume(obj, 200, (int)dist, lbl_803E6D78);
            ((PushBlockFlags *)(state + 0x285))->sfxActive = 1;
        }
        objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, lbl_803E6D64,
                *(f32 *)(obj + 0x2c) * timeDelta);
        moved = 0;
        {
            u32 dir = *(u8 *)(state + 0x282);
            if (dir == 0) {
                if (*(f32 *)(obj + 0x24) < lbl_803E6D7C) {
                    *(f32 *)(obj + 0x24) = lbl_803E6D80 * timeDelta + *(f32 *)(obj + 0x24);
                }
                if (*(f32 *)(obj + 0xc) >= *(f32 *)(state + 0x26c)) {
                    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x26c);
                    moved = 1;
                }
            } else if (dir == 1) {
                if (*(f32 *)(obj + 0x24) > lbl_803E6D84) {
                    *(f32 *)(obj + 0x24) = *(f32 *)(obj + 0x24) - lbl_803E6D80 * timeDelta;
                }
                if (*(f32 *)(obj + 0xc) <= *(f32 *)(state + 0x26c)) {
                    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x26c);
                    moved = 1;
                }
            } else if (dir == 2) {
                if (*(f32 *)(obj + 0x2c) < lbl_803E6D7C) {
                    *(f32 *)(obj + 0x2c) = lbl_803E6D80 * timeDelta + *(f32 *)(obj + 0x2c);
                }
                if (*(f32 *)(obj + 0x14) >= *(f32 *)(state + 0x270)) {
                    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x270);
                    moved = 1;
                }
            } else if (dir == 3) {
                if (*(f32 *)(obj + 0x2c) > lbl_803E6D84) {
                    *(f32 *)(obj + 0x2c) = *(f32 *)(obj + 0x2c) - lbl_803E6D80 * timeDelta;
                }
                if (*(f32 *)(obj + 0x14) <= *(f32 *)(state + 0x270)) {
                    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x270);
                    moved = 1;
                }
            }
        }
        if (*(f32 *)(obj + 0x24) > lbl_803E6D7C) {
            *(f32 *)(obj + 0x24) = lbl_803E6D7C;
        }
        if (*(f32 *)(obj + 0x24) < lbl_803E6D84) {
            *(f32 *)(obj + 0x24) = lbl_803E6D84;
        }
        if (*(f32 *)(obj + 0x2c) > lbl_803E6D7C) {
            *(f32 *)(obj + 0x2c) = lbl_803E6D7C;
        }
        if (*(f32 *)(obj + 0x2c) < lbl_803E6D84) {
            *(f32 *)(obj + 0x2c) = lbl_803E6D84;
        }
        if (moved == 0) {
            break;
        }
        {
            f32 zero = lbl_803E6D64;
            *(f32 *)(obj + 0x24) = zero;
            *(f32 *)(obj + 0x2c) = zero;
        }
        {
            u32 r = *(u8 *)(state + 0x284);
            if (r == 2) {
                ((PushBlockFlags *)(state + 0x285))->phase = 4;
                if ((s8)*(u8 *)(obj + 0xad) == 1) {
                    if (gameBitIncrement(2064) != 4) {
                        Sfx_PlayFromObject(0, 202);
                    }
                } else {
                    if (gameBitIncrement(2065) != 4) {
                        Sfx_PlayFromObject(0, 202);
                    }
                }
            } else if (r == 1) {
                ((PushBlockFlags *)(state + 0x285))->phase = 1;
                if (((PushBlockFlags *)(state + 0x285))->sfxActive != 0) {
                    ((PushBlockFlags *)(state + 0x285))->sfxActive = 0;
                    Sfx_PlayFromObject(obj, 201);
                }
            } else {
                if ((s8)*(u8 *)(obj + 0xad) == 1) {
                    GameBit_Set(2056, 1);
                } else {
                    GameBit_Set(2057, 1);
                }
            }
        }
        if (((PushBlockFlags *)(state + 0x285))->phase != 3) {
            if ((s8)*(u8 *)(obj + 0xad) == 1) {
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x28))(
                    0, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280), PB_IFACE);
                (*(void (**)(int, f32, f32, int, int, int))(PB_IFACE + 0x24))(
                    obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x14), state + 0x27e, state + 0x280,
                    PB_IFACE);
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x28))(
                    *(u8 *)(state + 0x283), *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                    PB_IFACE);
            } else {
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x44))(
                    0, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280), PB_IFACE);
                (*(void (**)(int, f32, f32, int, int, int))(PB_IFACE + 0x40))(
                    obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x14), state + 0x27e, state + 0x280,
                    PB_IFACE);
                (*(void (**)(int, int, int, int))(PB_IFACE + 0x44))(
                    *(u8 *)(state + 0x283), *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                    PB_IFACE);
            }
        }
        break;
    case 3:
        ObjHits_DisableObject(obj);
        if (*(u8 *)(obj + 0x36) == 255) {
            Sfx_PlayFromObject(obj, 203);
        }
        {
            int a = *(u8 *)(obj + 0x36) - framesThisStep * 8;
            if (a < 0) {
                a = 0;
            }
            *(u8 *)(obj + 0x36) = a;
        }
        if (*(u8 *)(obj + 0x36) == 0) {
            if (fn_802242A8(obj, state, Obj_GetPlayerObject()) != 0) {
                if ((s8)*(u8 *)(obj + 0xad) == 1) {
                    (*(void (**)(int, int, int, int))(PB_IFACE + 0x30))(
                        *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
                    (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x20))(
                        obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                        (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
                } else {
                    (*(void (**)(int, int, int, int))(PB_IFACE + 0x4c))(
                        *(u8 *)(state + 0x283), state + 0x27e, state + 0x280, PB_IFACE);
                    (*(void (**)(int, int, int, f32 *, f32 *, int))(PB_IFACE + 0x3c))(
                        obj, *(s16 *)(state + 0x27e), *(s16 *)(state + 0x280),
                        (f32 *)(obj + 0xc), (f32 *)(obj + 0x14), PB_IFACE);
                }
                ((PushBlockFlags *)(state + 0x285))->phase = 5;
            }
        }
        break;
    case 5:
        if (*(u8 *)(obj + 0x36) == 0) {
            ObjHits_EnableObject(obj);
            Sfx_PlayFromObject(0, 204);
        }
        {
            int a = *(u8 *)(obj + 0x36) + framesThisStep * 8;
            if (a > 255) {
                a = 255;
            }
            *(u8 *)(obj + 0x36) = a;
        }
        if (*(u8 *)(obj + 0x36) >= 0xff) {
            ((PushBlockFlags *)(state + 0x285))->phase = 1;
        }
        break;
    case 6:
        *(u8 *)(obj + 0x36) = 255;
    case 4:
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0) {
            *tex = 256;
        }
        *(u16 *)(obj + 0xb0) |= 256;
        break;
    }

    *(u16 *)(state + 0x27c) = lbl_803E6D88 * timeDelta + (f32)(u32) * (u16 *)(state + 0x27c);
    *(f32 *)(state + 0x278) =
        lbl_803E6D8C * fn_80293E80(lbl_803E6D90 * (f32)(u32) * (u16 *)(state + 0x27c) / lbl_803E6D94);
    *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x274) + *(f32 *)(state + 0x278);
}
#pragma scheduling on
#pragma peephole on
#undef PB_IFACE

extern u8 lbl_8032B0C8[][8];
extern u8 lbl_8032B088[][8];
extern u8 lbl_8032B048[][8];
extern u8 lbl_8032B008[][8];
extern u8 lbl_803AD298[][8];
extern u8 lbl_803AD2D8[][8];
extern f32 lbl_803E6DB0;
extern f32 lbl_803E6DB4;
extern f32 lbl_803E6DB8;
extern f32 lbl_803E6DBC;
extern f32 lbl_803E6DC0;
extern f32 lbl_803E6DD0;
extern f32 lbl_803E6DD4;
extern f32 lbl_803E6DD8;
extern void fn_8005B0A8(f32 *outX, f32 *outZ, f32 x, f32 y, f32 z);
extern void gameTimerStop(void);
extern u8 gameTimerIsRunning(void);
extern int *gSHthorntailAnimationInterface;
extern void Music_Trigger(int id, int p2);
extern void SCGameBitLatch_Update(int state, int a, int b, int c, int d, int e);
extern f32 lbl_803E6DA8;
extern void fn_8022578C(int obj, int state);
extern void fn_802251B4(int obj, int state);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void skyFn_80088e54(int a, f32 b);
extern int fn_80225BD8(int obj, int p2, int p3);
extern void *memcpy(void *dst, const void *src, u32 n);

#pragma peephole off
#pragma scheduling off
void wclevelcont_func16(s16 value, s16 *outRow, s16 *outCol)
{
    int i, j;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            if (value == lbl_8032B0C8[i][j]) {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}
void wclevelcont_func15(s16 value, s16 *outRow, s16 *outCol)
{
    int i, j;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            if (value == lbl_8032B088[i][j]) {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}
int wclevelcont_func14(s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7) {
        return 0;
    }
    return lbl_803AD298[i][j];
}
void wclevelcont_func13(int value, s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7) {
        return;
    }
    lbl_803AD298[i][j] = (u8)value;
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void wclevelcont_func12(int obj, s16 *outRow, s16 *outCol, f32 px, f32 pz)
{
    f32 outX, outZ;

    fn_8005B0A8(&outX, &outZ, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
    *outRow = (s16)((s16)(px - outX - lbl_803E6DB8) / 48);
    *outCol = (s16)((s16)(pz - outZ - lbl_803E6DC0) / 48);
}
void wclevelcont_func11(int obj, s16 col, s16 row, f32 *outXp, f32 *outZp)
{
    f32 outX, outZ;

    fn_8005B0A8(&outX, &outZ, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
    *outXp = lbl_803E6DB4 + (lbl_803E6DB8 + outX + (f32)(col * 48));
    *outZp = lbl_803E6DB4 + (lbl_803E6DC0 + outZ + (f32)(row * 48));
}
void wclevelcont_func0F(s16 value, s16 *outRow, s16 *outCol)
{
    int i, j;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            if (value == lbl_8032B048[i][j]) {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}
void wclevelcont_func0E(s16 value, s16 *outRow, s16 *outCol)
{
    int i, j;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            if (value == lbl_8032B008[i][j]) {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}
int wclevelcont_render2(s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7) {
        return 0;
    }
    return lbl_803AD2D8[i][j];
}
void wclevelcont_modelMtxFn(int value, s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7) {
        return;
    }
    lbl_803AD2D8[i][j] = (u8)value;
}
void wclevelcont_func0B(int obj, s16 *outRow, s16 *outCol, f32 px, f32 pz)
{
    f32 outX, outZ;

    fn_8005B0A8(&outX, &outZ, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
    *outRow = (s16)((s16)(px - outX - lbl_803E6DD0) / 48);
    *outCol = (s16)((s16)(pz - outZ - lbl_803E6DD4) / 48);
}
void wclevelcont_setScale(int obj, s16 col, s16 row, f32 *outXp, f32 *outZp)
{
    f32 outX, outZ;

    fn_8005B0A8(&outX, &outZ, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
    *outXp = lbl_803E6DB4 + (lbl_803E6DD0 + outX + (f32)(col * 48));
    *outZp = lbl_803E6DB4 + (lbl_803E6DD4 + outZ + (f32)(row * 48));
}
#pragma scheduling on
#pragma peephole on

int wclevelcont_getExtraSize(void) { return 0x1c; }
int wclevelcont_getObjectTypeId(void) { return 0; }
#pragma scheduling off
void wclevelcont_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    u8 mode;

    ObjGroup_RemoveObject(obj, 9);
    mode = *(u8 *)(state + 0xc);
    if (mode == 1) {
        GameBit_Set(0x7ef, 0);
        GameBit_Set(0x7ed, 0);
        GameBit_Set(0xba6, 0);
        GameBit_Set(0xedd, 0);
    } else if (mode == 2) {
        GameBit_Set(0x7f0, 0);
        GameBit_Set(0x7ee, 0);
        GameBit_Set(0xba6, 0);
        GameBit_Set(0xedc, 0);
    }
    gameTimerStop();
}
#pragma scheduling on
#pragma peephole off
void wclevelcont_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6DD8);
    }
}
#pragma peephole on
void wclevelcont_hitDetect(void) {}
#pragma peephole off
#pragma scheduling off
#pragma dont_inline on
void wclevelcont_syncProgressBits(int obj)
{
    int flag;

    if ((*(int (**)(int))(*gSHthorntailAnimationInterface + 0x24))(0)) {
        if (*(u16 *)(obj + 0x16) != 0x2d) {
            *(u16 *)(obj + 0x16) = 0x2d;
            Music_Trigger(0x2d, 1);
        }
        if (*(u16 *)(obj + 0x18) != -1) {
            *(u16 *)(obj + 0x18) = 0xffff;
            Music_Trigger(0x22, 0);
        }
    } else {
        if (*(u16 *)(obj + 0x16) != 0x39) {
            *(u16 *)(obj + 0x16) = 0x39;
            Music_Trigger(0x39, 1);
        }
        if (*(u16 *)(obj + 0x18) != 0x22) {
            *(u16 *)(obj + 0x18) = 0x22;
            Music_Trigger(0x22, 1);
        }
    }
    SCGameBitLatch_Update(obj + 0x10, 0x8, -1, -1, 0xba6, 0xd2);
    SCGameBitLatch_Update(obj + 0x10, 0x4, -1, -1, 0xcce, 0x36);
    SCGameBitLatch_Update(obj + 0x10, 0x10, -1, -1, 0xcd0, 0xd4);
    SCGameBitLatch_Update(obj + 0x10, 0x40, -1, -1, 0xcbb, 0xc4);
    flag = 0;
    if ((u32)GameBit_Get(0xba6) == 0 && ((u32)GameBit_Get(0xda9) != 0 || gameTimerIsRunning() != 0)) {
        flag = 1;
    }
    GameBit_Set(0xf31, flag);
    SCGameBitLatch_Update(obj + 0x10, 0x80, -1, -1, 0xf31, 0xaf);
}
#pragma dont_inline reset
void wclevelcont_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int hitOut;

    if (*(int *)(obj + 0xf4) == 0) {
        if ((u32)GameBit_Get(0xe05) == 0) {
            getEnvfxActImmediately(obj, obj, 0x1fb, 0);
            getEnvfxActImmediately(obj, obj, 0x1ff, 0);
            getEnvfxActImmediately(obj, obj, 0x1fc, 0);
            getEnvfxActImmediately(obj, obj, 0x1fd, 0);
            skyFn_80088e54(0, lbl_803E6DA8);
            GameBit_Set(0xe05, 1);
        }
        *(int *)(obj + 0xf4) = 1;
    }
    switch ((*(u8 (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac))) {
    case 1:
    default:
        fn_8022578C(obj, state);
        break;
    case 2:
        fn_802251B4(obj, state);
        break;
    }
    wclevelcont_syncProgressBits(state);
    if ((*(int (**)(int *))(*gSHthorntailAnimationInterface + 0x24))(&hitOut)) {
        GameBit_Set(0x7f3, 1);
        GameBit_Set(0x7f1, 0);
    } else {
        GameBit_Set(0x7f3, 0);
        GameBit_Set(0x7f1, 1);
    }
}
typedef struct {
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b18 : 2;
    u8 b07 : 3;
} WclevelcontFlags;

extern void gameTimerInit(int a, int b);
extern void timerSetToCountUp(void);
extern f32 lbl_803E6DAC;

#pragma peephole off
#pragma scheduling off
void fn_802251B4(int obj, int state)
{
    int scratch;

    (*(int (**)(int *))(*gSHthorntailAnimationInterface + 0x24))(&scratch);
    switch (*(u8 *)(state + 0xc)) {
    case 6:
        gameTimerInit(0x1d, 0x50);
        timerSetToCountUp();
        *(u8 *)(state + 0xc) = 4;
        break;
    case 4:
        if ((u32)GameBit_Get(0x2a5) != 0) {
            int player;
            GameBit_Set(0x274, 1);
            GameBit_Set(0xef1, 0);
            player = Obj_GetPlayerObject();
            (*(void (**)(int, int, int, int))(*gMapEventInterface + 0x1c))(
                player + 0xc, *(s16 *)player, 1, 0);
            *(u16 *)(state + 0x1a) |= 0x40;
            *(u8 *)(state + 0xc) = 0;
            Sfx_PlayFromObject(0, 0x7e);
            gameTimerStop();
        } else if (isGameTimerDisabled() != 0) {
            GameBit_Set(0x274, 0);
            GameBit_Set(0xef1, 0);
            if ((u32)GameBit_Get(0x34d) == 0) {
                GameBit_Set(0x2b1, 0);
                GameBit_Set(0x226, 1);
                GameBit_Set(0x2a6, 1);
                GameBit_Set(0x206, 1);
                GameBit_Set(0x25f, 1);
                *(u8 *)(state + 0xc) = 0;
            }
        }
        break;
    default:
        if (!(*(u16 *)(state + 0x1a) & 0x40) && (u32)GameBit_Get(0x2b1) != 0) {
            GameBit_Set(0xef1, 1);
            GameBit_Set(0xe6d, 0);
            if ((u32)GameBit_Get(0x204) != 0) {
                GameBit_Set(0x226, 0);
                GameBit_Set(0x2a6, 0);
                GameBit_Set(0x206, 0);
                GameBit_Set(0x25f, 0);
                GameBit_Set(0x274, 1);
                *(u8 *)(state + 0xc) = 6;
            }
        }
        break;
    }

    if (!(*(u16 *)(state + 0x1a) & 0x10)) {
        if ((u8)GameBit_Get(0x810) == 4) {
            GameBit_Set(0x812, 1);
            Sfx_PlayFromObject(0, 0x7e);
            *(u16 *)(state + 0x1a) |= 0x10;
        } else if ((u32)GameBit_Get(0x808) != 0) {
            if (*(f32 *)(state + 8) <= lbl_803E6DA8) {
                GameBit_Set(0x810, 0);
                memcpy(lbl_803AD2D8, lbl_8032B008, 0x40);
                *(f32 *)(state + 8) = lbl_803E6DAC;
            }
        }
        if (*(f32 *)(state + 8) > lbl_803E6DA8) {
            *(f32 *)(state + 8) -= timeDelta;
            if (*(f32 *)(state + 8) <= lbl_803E6DA8)
                GameBit_Set(0x808, 0);
        }
    }

    if (!(*(u16 *)(state + 0x1a) & 0x20)) {
        if ((u8)GameBit_Get(0x811) == 4) {
            GameBit_Set(0x813, 1);
            Sfx_PlayFromObject(0, 0x7e);
            *(u16 *)(state + 0x1a) |= 0x20;
        } else if ((u32)GameBit_Get(0x809) != 0) {
            if (*(f32 *)(state + 4) <= lbl_803E6DA8) {
                GameBit_Set(0x811, 0);
                memcpy(lbl_803AD298, lbl_8032B088, 0x40);
                *(f32 *)(state + 4) = lbl_803E6DAC;
            }
        }
        if (*(f32 *)(state + 4) > lbl_803E6DA8) {
            *(f32 *)(state + 4) -= timeDelta;
            if (*(f32 *)(state + 4) <= lbl_803E6DA8)
                GameBit_Set(0x809, 0);
        }
    }

    if (!(*(u16 *)(state + 0x1a) & 0x80)) {
        if ((u32)GameBit_Get(0xc58) != 0 && (u32)GameBit_Get(0xc59) != 0 &&
            (u32)GameBit_Get(0xc5a) != 0) {
            GameBit_Set(0x205, 1);
            Sfx_PlayFromObject(0, 0x7e);
            *(u16 *)(state + 0x1a) |= 0x80;
        } else if (!((WclevelcontFlags *)(state + 0x14))->b40 &&
                   (u32)GameBit_Get(0xc58) != 0) {
            Sfx_PlayFromObject(0, 0x109);
            ((WclevelcontFlags *)(state + 0x14))->b40 = 1;
        } else if (!((WclevelcontFlags *)(state + 0x14))->b20 &&
                   (u32)GameBit_Get(0xc59) != 0) {
            Sfx_PlayFromObject(0, 0x109);
            ((WclevelcontFlags *)(state + 0x14))->b20 = 1;
        } else if (!((WclevelcontFlags *)(state + 0x14))->b18 &&
                   (u32)GameBit_Get(0xc5a) != 0) {
            Sfx_PlayFromObject(0, 0x109);
            ((WclevelcontFlags *)(state + 0x14))->b18 = 1;
        }
    }

    if (!(*(u16 *)(state + 0x1a) & 0x100)) {
        if ((u32)GameBit_Get(0xbcf) != 0) {
            int player;
            GameBit_Set(0xbc8, 0);
            GameBit_Set(0x2f0, 1);
            GameBit_Set(0xeec, 0);
            GameBit_Set(0xbd0, 0);
            player = Obj_GetPlayerObject();
            (*(void (**)(int, int, int, int))(*gMapEventInterface + 0x1c))(
                player + 0xc, *(s16 *)player, 1, 0);
            Sfx_PlayFromObject(0, 0x7e);
            *(u16 *)(state + 0x1a) |= 0x100;
        }
    }

    *(u16 *)(state + 0x1a) &= ~1;
    if ((u32)GameBit_Get(0xc92) != 0) {
        GameBit_Set(0x4e4, 0);
        GameBit_Set(0x4e5, 0);
        if (GameBit_Get(0x4e3) == 0xff)
            GameBit_Set(0x4e3, randomGetRange(6, 7));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wclevelcont_func10(int obj, s16 a, s16 b, f32 *outX, f32 *outZ, int dx, int dy)
{
    int i;
    int limit;

    if (dx != 0) {
        int bi = b;
        if (dx == -1) {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + lbl_803E6DBC);
            *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + (f32)(bi * 48));
            a += 1;
            limit = 8;
        } else {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + lbl_803E6DA8);
            *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + (f32)(bi * 48));
            a -= 1;
            limit = -1;
        }
        for (i = a; i != limit; i -= dx) {
            if (lbl_803AD2D8[i][b] != 0) {
                if (lbl_803AD2D8[i][b] <= 4) {
                    f32 pz, px;
                    i += dx;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    } else {
        int ai = a;
        if (dy == -1) {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + (f32)(ai * 48));
            *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + lbl_803E6DBC);
            b += 1;
            limit = 8;
        } else {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + (f32)(ai * 48));
            *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + lbl_803E6DA8);
            b -= 1;
            limit = -1;
        }
        for (i = b; i != limit; i -= dy) {
            if (lbl_803AD2D8[a][i] != 0) {
                if (lbl_803AD2D8[a][i] <= 4) {
                    f32 pz, px;
                    i += dy;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    }
}

#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022578C(int obj, int state)
{
    if (*(u16 *)(state + 0x1a) & 0x2)
        return;
    *(u8 *)(state + 0xd) = *(u8 *)(state + 0xc);
    switch (*(u8 *)(state + 0xc)) {
    case 1:
        if (*(u16 *)(state + 0x1a) & 0x1) {
            gameTimerInit(0x1d, 0x3c);
            timerSetToCountUp();
            GameBit_Set(0xba6, 1);
            GameBit_Set(0xedd, 1);
        } else if ((u32)GameBit_Get(0x7f9) != 0) {
            *(u16 *)(state + 0x1a) |= 0x4;
            gameTimerStop();
            if ((u32)GameBit_Get(0x7fa) != 0)
                Sfx_PlayFromObject(0, 0x7e);
            else
                Sfx_PlayFromObject(0, 0x109);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedd, 0);
            if ((u32)GameBit_Get(0x7fa) != 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                *(u8 *)(state + 0xc) = 3;
            } else {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                *(u8 *)(state + 0xc) = 0;
            }
            *(u16 *)(state + 0x1a) |= 0x2;
        } else if (isGameTimerDisabled() != 0) {
            GameBit_Set(0x7ef, 0);
            GameBit_Set(0x7ed, 0);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedd, 0);
            *(u8 *)(state + 0xc) = 0;
        }
        break;
    case 2:
        if (*(u16 *)(state + 0x1a) & 0x1) {
            gameTimerInit(0x1d, 0x50);
            timerSetToCountUp();
            GameBit_Set(0xba6, 1);
            GameBit_Set(0xedc, 1);
        } else if ((u32)GameBit_Get(0x7fa) != 0) {
            *(u16 *)(state + 0x1a) |= 0x8;
            gameTimerStop();
            if ((u32)GameBit_Get(0x7f9) != 0)
                Sfx_PlayFromObject(0, 0x7e);
            else
                Sfx_PlayFromObject(0, 0x109);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedc, 0);
            if ((u32)GameBit_Get(0x7f9) != 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                *(u8 *)(state + 0xc) = 3;
            } else {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                *(u8 *)(state + 0xc) = 0;
            }
            *(u16 *)(state + 0x1a) |= 0x2;
        } else if (isGameTimerDisabled() != 0) {
            GameBit_Set(0x7f0, 0);
            GameBit_Set(0x7ee, 0);
            GameBit_Set(0xba6, 0);
            GameBit_Set(0xedc, 0);
            *(u8 *)(state + 0xc) = 0;
        }
        break;
    case 3:
        if ((u32)GameBit_Get(0xcac) != 0) {
            int player;
            GameBit_Set(0xda9, 0);
            GameBit_Set(0xc37, 1);
            player = Obj_GetPlayerObject();
            (*(void (**)(int, int, int, int))(*gMapEventInterface + 0x1c))(
                player + 0xc, *(s16 *)player, 1, 0);
            *(u8 *)(state + 0xc) = 7;
        }
        break;
    case 7:
        break;
    default:
        if (!(*(u16 *)(state + 0x1a) & 0x4) && (u32)GameBit_Get(0x7ed) != 0) {
            GameBit_Set(0x7ef, 1);
            *(f32 *)(state + 0) = lbl_803E6DB0;
            *(u8 *)(state + 0xc) = 1;
            *(u16 *)(state + 0x1a) |= 0x2;
            break;
        }
        if (!(*(u16 *)(state + 0x1a) & 0x8) && (u32)GameBit_Get(0x7ee) != 0) {
            GameBit_Set(0x7f0, 1);
            *(f32 *)(state + 0) = lbl_803E6DB0;
            *(u8 *)(state + 0xc) = 2;
            *(u16 *)(state + 0x1a) |= 0x2;
        }
        break;
    }
    *(u16 *)(state + 0x1a) &= ~1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_80225BD8(int obj, int p2, int p3)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    *(u16 *)(state + 0x1a) |= 0x1;
    *(u16 *)(state + 0x1a) &= ~0x2;
    if (*(u8 *)(state + 0xd) == 1) {
        f32 t = *(f32 *)(state + 0) - timeDelta;
        *(f32 *)(state + 0) = t;
        if (t <= lbl_803E6DA8) {
            int player;
            GameBit_Set(0x7f7, 1);
            player = Obj_GetPlayerObject();
            (*(void (**)(int, int, int, int))(*gMapEventInterface + 0x1c))(
                player + 0xc, *(s16 *)player, 1, 0);
        }
    } else if (*(u8 *)(state + 0xd) == 2) {
        f32 t = *(f32 *)(state + 0) - timeDelta;
        *(f32 *)(state + 0) = t;
        if (t <= lbl_803E6DA8) {
            int player;
            GameBit_Set(0x802, 1);
            player = Obj_GetPlayerObject();
            (*(void (**)(int, int, int, int))(*gMapEventInterface + 0x1c))(
                player + 0xc, *(s16 *)player, 1, 0);
        }
    }
    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        if (*(u8 *)(p3 + (i + 0x81)) == 1)
            *(u8 *)(state + 0xc) = 6;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_80225D2C(int obj, s16 a, s16 b, f32 *outX, f32 *outZ, int dx, int dy)
{
    int i;
    int limit;

    if (dx != 0) {
        int bi = b;
        if (dx == -1) {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + lbl_803E6DBC);
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)(bi * 48));
            a += 1;
            limit = 8;
        } else {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + lbl_803E6DA8);
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)(bi * 48));
            a -= 1;
            limit = -1;
        }
        for (i = a; i != limit; i -= dx) {
            if (lbl_803AD298[i][b] != 0) {
                if (lbl_803AD298[i][b] <= 4) {
                    f32 pz, px;
                    i += dx;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    } else {
        int ai = a;
        if (dy == -1) {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)(ai * 48));
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + lbl_803E6DBC);
            b += 1;
            limit = 8;
        } else {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)(ai * 48));
            *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + lbl_803E6DA8);
            b -= 1;
            limit = -1;
        }
        for (i = b; i != limit; i -= dy) {
            if (lbl_803AD298[a][i] != 0) {
                if (lbl_803AD298[a][i] <= 4) {
                    f32 pz, px;
                    i += dy;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_init(int obj)
{
    int state = *(int *)(obj + 0xb8);
    u16 flags;

    *(void **)(obj + 0xbc) = (void *)fn_80225BD8;
    GameBit_Set(0x810, 0);
    memcpy(lbl_803AD2D8, lbl_8032B008, 0x40);
    GameBit_Set(0x811, 0);
    memcpy(lbl_803AD298, lbl_8032B088, 0x40);
    if ((u32)GameBit_Get(0x7fa) != 0) *(u16 *)(state + 0x1a) |= 0x8;
    if ((u32)GameBit_Get(0x7f9) != 0) *(u16 *)(state + 0x1a) |= 0x4;
    if ((u32)GameBit_Get(0x813) != 0) *(u16 *)(state + 0x1a) |= 0x20;
    if ((u32)GameBit_Get(0x812) != 0) *(u16 *)(state + 0x1a) |= 0x10;
    if ((u32)GameBit_Get(0x2a5) != 0) *(u16 *)(state + 0x1a) |= 0x40;
    if ((u32)GameBit_Get(0x205) != 0) *(u16 *)(state + 0x1a) |= 0x80;
    if ((u32)GameBit_Get(0xbcf) != 0) *(u16 *)(state + 0x1a) |= 0x100;
    if ((u32)GameBit_Get(0xcac) != 0) *(u16 *)(state + 0x1a) |= 0x200;
    flags = *(u16 *)(state + 0x1a);
    if (flags & 0x200) {
        *(u8 *)(state + 0xc) = 7;
    } else if ((flags & 0x4) && (flags & 0x8)) {
        *(u8 *)(state + 0xc) = 3;
    }
    ObjGroup_AddObject(obj, 9);
    GameBit_Set(0x226, 1);
    GameBit_Set(0x2a6, 1);
    GameBit_Set(0x206, 1);
    GameBit_Set(0x25f, 1);
    (*(void (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac));
    ((WclevelcontFlags *)(state + 0x14))->b40 = GameBit_Get(0xc58);
    ((WclevelcontFlags *)(state + 0x14))->b20 = GameBit_Get(0xc59);
    ((WclevelcontFlags *)(state + 0x14))->b18 = GameBit_Get(0xc5a);
}
#pragma scheduling on
#pragma peephole on
void wclevelcont_release(void) {}
void wclevelcont_initialise(void) {}

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
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

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

extern int getTrickyObject(void);
extern int fn_80138F84(int tricky);
extern int trickyFn_80138f14(int tricky);
extern f32 lbl_803E6DE4;
extern f32 lbl_803E6DE8;

#pragma peephole off
#pragma scheduling off
void wcbeacon_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    u32 phase;

    *(u8 *)(obj + 0xaf) |= 8;
    phase = *(u8 *)(state + 4);
    if (phase == 1) {
        int tricky = getTrickyObject();
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) == 0) {
            if ((u32)fn_80138F84(tricky) != (u32)obj || trickyFn_80138f14(tricky) != 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                *(u8 *)(state + 4) = 0;
            }
        } else {
            *(u8 *)(obj + 0xaf) &= ~8;
            if ((u32)tricky != 0 && (*(u8 *)(obj + 0xaf) & 4)) {
                (*(void (**)(int, int, int, int, int))(*(int *)(*(int *)(tricky + 0x68)) + 0x28))(
                    tricky, obj, 1, 4, *(int *)(*(int *)(tricky + 0x68)));
            }
        }
        if (*(u8 *)(state + 5) != 0) {
            Sfx_PlayFromObject(obj, 159);
            Sfx_PlayFromObject(obj, 158);
            *(u8 *)(state + 4) = 2;
            *(f32 *)(state + 0) = lbl_803E6DE4;
        }
    } else if (phase == 0) {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
            *(u8 *)(state + 4) = 1;
        }
    } else if (phase == 2) {
        f32 v = *(f32 *)(state + 0) + timeDelta;
        *(f32 *)(state + 0) = v;
        if (v >= lbl_803E6DE8) {
            *(u8 *)(state + 4) = 3;
        }
    } else if (phase == 3) {
        if (*(u16 *)(obj + 0xb0) & 0x800) {
            (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(obj, 1850, 0, 2, -1,
                                                                                0);
        }
        if (*(int *)(obj + 0xf4) == 0) {
            (*(void (**)(int, int))(*gObjectTriggerInterface + 0x54))(obj, 105);
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, 1);
        }
    }
    *(int *)(obj + 0xf4) = 1;
}
#pragma scheduling on
#pragma peephole on

int wctile_getExtraSize(void) { return 0xc; }
#pragma scheduling off
int wctile_getObjectTypeId(int obj)
{
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

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

extern f32 lbl_803E6DF4;
extern f32 lbl_803E6DF8;

#pragma peephole off
#pragma scheduling off
void wctile_update(int obj)
{
    f32 nearest = lbl_803E6DF4;
    int state = *(int *)(obj + 0xb8);

    if (*(void **)(state + 0) == NULL) {
        *(int *)(state + 0) = ObjGroup_FindNearestObject(9, obj, &nearest);
        *(u8 *)(obj + 0x36) = 0;
        return;
    }
    *(s16 *)(obj + 0) += (int)(lbl_803E6DF8 * timeDelta);
    if (*(s16 *)(state + 0xa) != 5) {
        if ((s8)*(u8 *)(obj + 0xad) == 1) {
            if ((u32)GameBit_Get(0x812) != 0)
                *(s16 *)(state + 0xa) = 5;
            else if ((u32)GameBit_Get(0x808) != 0)
                *(s16 *)(state + 0xa) = 3;
        } else {
            if ((u32)GameBit_Get(0x813) != 0)
                *(s16 *)(state + 0xa) = 5;
            else if ((u32)GameBit_Get(0x809) != 0)
                *(s16 *)(state + 0xa) = 3;
        }
    }
    switch (*(s16 *)(state + 0xa)) {
    case 0:
        if ((s8)*(u8 *)(obj + 0xad) == 1) {
            (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x30))(
                *(s16 *)(state + 8), state + 4, state + 6,
                *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
            (*(void (**)(int, int, int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x20))(
                obj, *(s16 *)(state + 4), *(s16 *)(state + 6), obj + 0xc, obj + 0x14,
                *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
        } else {
            (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x4c))(
                *(s16 *)(state + 8), state + 4, state + 6,
                *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
            (*(void (**)(int, int, int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x3c))(
                obj, *(s16 *)(state + 4), *(s16 *)(state + 6), obj + 0xc, obj + 0x14,
                *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
        }
        *(u8 *)(obj + 0x36) = 0xff;
        *(s16 *)(state + 0xa) = 1;
        break;
    case 2:
        *(u8 *)(obj + 0x36) = 0;
        break;
    case 5:
        *(u8 *)(obj + 0x36) = 0;
        break;
    case 3:
        {
            int v = *(u8 *)(obj + 0x36) - framesThisStep * 8;
            if (v < 0)
                v = 0;
            *(u8 *)(obj + 0x36) = v;
        }
        if (*(u8 *)(obj + 0x36) == 0) {
            if ((s8)*(u8 *)(obj + 0xad) == 1) {
                (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x30))(
                    *(s16 *)(state + 8), state + 4, state + 6,
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
                (*(void (**)(int, int, int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x20))(
                    obj, *(s16 *)(state + 4), *(s16 *)(state + 6), obj + 0xc, obj + 0x14,
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
            } else {
                (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x4c))(
                    *(s16 *)(state + 8), state + 4, state + 6,
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
                (*(void (**)(int, int, int, int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x3c))(
                    obj, *(s16 *)(state + 4), *(s16 *)(state + 6), obj + 0xc, obj + 0x14,
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68)));
            }
            *(s16 *)(state + 0xa) = 4;
        }
        break;
    case 4:
        {
            int v = *(u8 *)(obj + 0x36) + framesThisStep * 8;
            if (v > 0xff)
                v = 0xff;
            *(u8 *)(obj + 0x36) = v;
        }
        if (*(u8 *)(obj + 0x36) >= 0xff)
            *(s16 *)(state + 0xa) = 1;
        break;
    case 1:
    default:
        {
            int v = *(u8 *)(obj + 0x36) + framesThisStep * 8;
            if (v > 0xff)
                v = 0xff;
            *(u8 *)(obj + 0x36) = v;
        }
        if ((s8)*(u8 *)(obj + 0xad) == 1) {
            if (*(s16 *)(state + 8) !=
                (u8)(*(int (**)(int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x2c))(
                    *(s16 *)(state + 4), *(s16 *)(state + 6),
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68))))
                *(s16 *)(state + 0xa) = 2;
        } else {
            if (*(s16 *)(state + 8) !=
                (u8)(*(int (**)(int, int, int))(*(int *)(*(int *)(*(int *)(state + 0) + 0x68)) + 0x48))(
                    *(s16 *)(state + 4), *(s16 *)(state + 6),
                    *(int *)(*(int *)(*(int *)(state + 0) + 0x68))))
                *(s16 *)(state + 0xa) = 2;
        }
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset

int wcpressures_getExtraSize(void) { return 0x7c; }
#pragma peephole off
#pragma scheduling off
int wcpressures_tileStateCallback(int obj, int unused, int callbackData)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    u8 i;

    if (*(u8 *)(callbackData + 0x80) == 1) {
        for (i = 0; i < 10; i++) {
            if (((void **)state)[i + 1] != NULL) {
                *(f32 *)(state + 0x2c + i * 8) = *(f32 *)(((int *)state)[i + 1] + 0xc);
                *(f32 *)(state + 0x30 + i * 8) = *(f32 *)(((int *)state)[i + 1] + 0x14);
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
#pragma peephole on

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
extern void fn_80137948(void *fmt, ...);
extern char sWCPressuresActivateFormat[];
extern f32 lbl_803E6E04;
#pragma peephole off
#pragma scheduling off
void wcpressures_update(int obj)
{
    int r4c = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int i;
    int j;
    f32 thr;

    if (*(s16 *)(r4c + 0x20) > 0 && (u32)GameBit_Get(*(s16 *)(r4c + 0x20)) == 0) {
        fn_80137948(sWCPressuresActivateFormat, *(s16 *)(r4c + 0x20));
        return;
    }
    {
        int n = *(u8 *)state - 1;
        *(s8 *)state = n;
        if ((s8)n < 0)
            *(s8 *)state = 0;
    }
    if ((s8)*(u8 *)(*(int *)(obj + 0x58) + 0x10f) > 0) {
        for (i = 0; i < (s8)*(u8 *)(*(int *)(obj + 0x58) + 0x10f); i++) {
            int ent = *(int *)(*(int *)(obj + 0x58) + (i * 4 + 0x100));
            if (*(f32 *)(ent + 0x10) - *(f32 *)(obj + 0x10) >
                (f32)(u32) * (u8 *)(r4c + 0x1d)) {
                int s2 = *(int *)(obj + 0xb8);
                int slot;

                for (j = 0; *(void **)(s2 + (u8)j * 4 + 4) != NULL || (u8)j == 9; j++)
                    ;
                slot = (u8)j;
                *(int *)(s2 + slot * 4 + 4) = ent;
                *(f32 *)(s2 + slot * 8 + 0x2c) = *(f32 *)(ent + 0xc);
                *(f32 *)(s2 + slot * 8 + 0x30) = *(f32 *)(ent + 0x14);
            }
        }
    }
    {
        int s2 = *(int *)(obj + 0xb8);
        int found = 0;

        for (j = 0; (u8)j < 0xa; j++) {
            int slot = (u8)j;
            int val = *(int *)(s2 + slot * 4 + 4);
            if ((u32)val != 0) {
                if (*(f32 *)(s2 + slot * 8 + 0x2c) == *(f32 *)(val + 0xc) &&
                    *(f32 *)(s2 + slot * 8 + 0x30) == *(f32 *)(val + 0x14)) {
                    found = 1;
                } else {
                    *(int *)(s2 + slot * 4 + 4) = 0;
                }
            }
        }
        if (found)
            *(s8 *)state = 5;
    }
    thr = *(f32 *)(r4c + 0xc) - (f32)(u32) * (u8 *)(r4c + 0x1c);
    switch ((s8)*(s8 *)(state + 1)) {
    case 0:
        if (*(s8 *)state != 0 && *(f32 *)(obj + 0x10) >= thr) {
            Sfx_PlayFromObject(obj, 0xc7);
            *(s8 *)(state + 1) = 3;
        }
        break;
    case 1:
        *(f32 *)(obj + 0x10) = lbl_803E6E04 * timeDelta + *(f32 *)(obj + 0x10);
        if (*(f32 *)(obj + 0x10) > *(f32 *)(r4c + 0xc)) {
            *(f32 *)(obj + 0x10) = *(f32 *)(r4c + 0xc);
            *(s8 *)(state + 1) = 0;
        }
        break;
    case 2:
        if ((u32)GameBit_Get(*(s16 *)(r4c + 0x1a)) == 0) {
            Sfx_PlayFromObject(obj, 0xc7);
            *(s8 *)(state + 1) = 1;
        }
        break;
    case 3:
        *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) - lbl_803E6E04 * timeDelta;
        if (*(f32 *)(obj + 0x10) < thr) {
            GameBit_Set(*(s16 *)(r4c + 0x1a), 1);
            *(s8 *)(state + 1) = 2;
            *(f32 *)(obj + 0x10) = thr;
        }
        break;
    }
    {
        int *tex = objFindTexture(obj, 0, 0);
        if (tex != 0) {
            *tex = (s8)*(s8 *)(state + 1) == 2 ? 1 : 0;
            *tex = *tex << 8;
        }
    }
}
#pragma scheduling on
#pragma peephole on
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
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

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

extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern u8 *mapGetBlock(int idx);
extern int fn_8006070C(int block, int index);
extern void fn_80056A6C(int a, int b, int c);
extern f32 lbl_803E6E58;
#pragma peephole off
#pragma scheduling off
#pragma dont_inline on
void wctempledia_syncPartVisibility(int obj, u8 mask)
{
    u8 *block;
    int part;
    int slot;
    int bit;

    block = mapGetBlock(objPosToMapBlockIdx(*(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14)));
    if (block != NULL) {
        for (part = 1; part < 4; part++) {
            bit = mask & (1 << (part - 1));
            for (slot = 0; slot < block[0xa2]; slot++) {
                int entry = fn_8006070C((int)block, slot);
                if (*(u8 *)(entry + 0x29) == part) {
                    if (bit != 0) {
                        fn_80056A6C(part, *(int *)(entry + 0x24), 0x100);
                    } else {
                        fn_80056A6C(part, *(int *)(entry + 0x24), 0);
                    }
                }
            }
        }
    }
}
#pragma scheduling on
#pragma peephole on
#pragma dont_inline reset
int wctempledia_getExtraSize(void) { return 0x14; }
int wctempledia_getObjectTypeId(void) { return 0; }
void wctempledia_free(void) {}
#pragma peephole off
void wctempledia_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E58);
    }
}
#pragma peephole on
void wctempledia_hitDetect(void) {}
extern s16 lbl_803DC3B8;
extern s16 lbl_803DC3C0;
extern f32 lbl_8032B348[];
extern f32 lbl_8032B354[];
extern f32 lbl_803E6E48;
int wctempledia_interactCallback(int obj, int p2, int p3);
#pragma peephole off
#pragma scheduling off
int wctempledia_interactCallback(int obj, int p2, int p3)
{
    f32 *p = *(f32 **)(obj + 0xb8);

    *p = lbl_803E6E48 * -*p * timeDelta + *p;
    *(s16 *)(obj + 4) = (int)(timeDelta * *p + (f32)*(s16 *)(obj + 4));
    *(s8 *)(p3 + 0x56) = 0;
    *(s16 *)(p3 + 0x70) &= ~2;
    *(s16 *)(p3 + 0x6e) &= ~2;
    return 0;
}
extern f32 lbl_803E6E5C;
extern f32 lbl_803E6E60;
extern f32 lbl_803E6E64;
extern f32 lbl_803E6E68;
void wctempledia_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int r4c = *(int *)(obj + 0x4c);
    int i;
    int j;
    int k;

    if (*(u8 *)(state + 9) & 1) {
        wctempledia_syncPartVisibility(obj, *(u8 *)(state + 8));
        return;
    }
    *(f32 *)state =
        timeDelta * (lbl_803E6E48 * (*(f32 *)(state + 4) - *(f32 *)state)) + *(f32 *)state;
    *(s16 *)(obj + 4) = (int)(timeDelta * *(f32 *)state + (f32)*(s16 *)(obj + 4));
    Sfx_KeepAliveLoopedObjectSound(obj, 0x7f);
    {
        f32 ratio = *(f32 *)state / *(f32 *)(*(int *)(state + 0xc) + 8);
        Sfx_SetObjectSfxVolume(obj, 0x7f, (u8)(lbl_803E6E60 * ratio + lbl_803E6E5C),
                               lbl_803E6E68 * ratio + lbl_803E6E64);
    }
    for (i = 0; i < 3; i++) {
        int bit = 1 << i;
        if ((*(u8 *)(state + 8) & bit) == 0 &&
            GameBit_Get(*(s16 *)(*(int *)(state + 0x10) + i * 2)) != 0) {
            int found = 0;
            for (j = 0; j < i; j++) {
                if ((*(u8 *)(state + 8) & (1 << j)) == 0) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                for (k = 0; k < 3; k++) {
                    GameBit_Set(*(s16 *)(*(int *)(state + 0x10) + k * 2), 0);
                }
                Sfx_PlayFromObject(0, 0x487);
                *(u8 *)(state + 8) = 0;
                *(f32 *)(state + 4) = *(f32 *)(*(int *)(state + 0xc) + 0);
                break;
            }
            *(u8 *)(state + 8) |= bit;
            if (i == 0) {
                *(f32 *)(state + 4) = *(f32 *)(*(int *)(state + 0xc) + 4);
                Sfx_PlayFromObject(0, 0x409);
            } else if (i == 1) {
                *(f32 *)(state + 4) = *(f32 *)(*(int *)(state + 0xc) + 8);
                Sfx_PlayFromObject(0, 0x409);
            }
        }
    }
    wctempledia_syncPartVisibility(obj, *(u8 *)(state + 8));
    if (*(u8 *)(state + 8) == 7) {
        GameBit_Set(*(s16 *)(r4c + 0x1e), 1);
        Sfx_PlayFromObject(0, 0x7e);
        *(u8 *)(state + 9) |= 1;
    }
}
void wctempledia_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    *(s16 *)obj = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    *(u8 *)(obj + 0xad) = *(u8 *)(setup + 0x19);
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }
    if (*(s8 *)(obj + 0xad) == 0) {
        *(s16 **)(state + 0x10) = &lbl_803DC3B8;
        *(f32 **)(state + 0xc) = lbl_8032B348;
    } else {
        *(s16 **)(state + 0x10) = &lbl_803DC3C0;
        *(f32 **)(state + 0xc) = lbl_8032B354;
    }
    for (i = 0; i < 3; i++) {
        if ((u32)GameBit_Get((*(s16 **)(state + 0x10))[i]) != 0) {
            *(u8 *)(state + 8) |= (1 << i);
        }
    }
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        *(u8 *)(state + 8) = 7;
        *(u8 *)(state + 9) |= 1;
    }
    if (*(u8 *)(state + 8) & 2) {
        *(f32 *)state = (*(f32 **)(state + 0xc))[2];
    } else if (*(u8 *)(state + 8) & 1) {
        *(f32 *)state = (*(f32 **)(state + 0xc))[1];
    } else {
        *(f32 *)state = (*(f32 **)(state + 0xc))[0];
    }
    *(f32 *)(state + 4) = *(f32 *)state;
    *(void **)(obj + 0xbc) = (void *)wctempledia_interactCallback;
    wctempledia_syncPartVisibility(obj, *(u8 *)(state + 8));
}
#pragma scheduling on
#pragma peephole on
void wctempledia_release(void) {}
void wctempledia_initialise(void) {}

extern f32 lbl_803E6E90;
#pragma dont_inline on
#pragma scheduling off
void wctemplebri_updateModelWarp(int obj, int p2)
{
    int tex;
    int v;

    tex = (int)objFindTexture(obj, 0, 0);
    *(s16 *)(tex + 0xa) += 0x14;
    if (*(s16 *)(tex + 0xa) > 0x2710) *(s16 *)(tex + 0xa) -= 0x2710;
    *(s16 *)(tex + 8) += 0xa;
    if (*(s16 *)(tex + 8) > 0x2710) *(s16 *)(tex + 8) -= 0x2710;
    tex = (int)objFindTexture(obj, 1, 0);
    *(s16 *)(tex + 0xa) += 0x1e;
    if (*(s16 *)(tex + 0xa) > 0x2710) *(s16 *)(tex + 0xa) -= 0x2710;
    v = *(u16 *)(p2 + 0x60) + (framesThisStep << 8);
    if (v > 0xffff) v -= 0xffff;
    *(u16 *)(p2 + 0x60) = (u16)v;
    v = *(u16 *)(p2 + 0x62) + (framesThisStep << 7);
    if (v > 0xffff) v -= 0xffff;
    *(u16 *)(p2 + 0x62) = (u16)v;
}
#pragma scheduling on
#pragma dont_inline reset
int wctemplebri_getExtraSize(void) { return 0x68; }
#pragma scheduling off
int wctemplebri_getObjectTypeId(int obj)
{
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
}
#pragma scheduling on
void wctemplebri_free(void) {}
#pragma peephole off
#pragma scheduling off
void wctemplebri_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int *)(obj + 0xb8);

    if (visible != 0) {
        if (*(u8 *)(state + 0x5f) != 0) {
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E90);
        }
    }
}
#pragma scheduling on
#pragma peephole on
void wctemplebri_hitDetect(void) {}
void wctemplebri_release(void) {}
void wctemplebri_initialise(void) {}

extern int ObjModel_GetCurrentVertexCoords(int model, int idx);
extern int ObjModel_GetBaseVertexCoords(int model, int idx);
extern void ObjHits_DisableObject(int obj);
extern int wctemplebri_interactCallback(int obj, int p2, int p3);
extern f32 lbl_803E6E70;
extern f32 lbl_803E6E74;
extern f32 lbl_803E6E78;
extern f32 lbl_803E6E7C;

#pragma peephole off
#pragma scheduling off
int wctemplebri_interactCallback(int obj, int p2, int p3)
{
    int r4c = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int model;
    int modelBase;
    int i;

    *(s8 *)(p3 + 0x56) = 0;
    *(s16 *)(p3 + 0x70) &= ~0x20;
    *(s16 *)(p3 + 0x6e) &= ~0x20;
    wctemplebri_updateModelWarp(obj, state);
    if (*(u8 *)(p3 + 0x80) == 1) {
        *(s8 *)(state + 0x5f) = 1;
    }
    if (*(u8 *)(state + 0x5f) != 0) {
        if ((*(u8 *)(state + 0x66) & 1) == 0) {
            *(u8 *)(state + 0x66) |= 1;
            GameBit_Set(*(s16 *)(r4c + 0x1e), 1);
        }
        {
            int a = (int)((f32)(u32) * (u8 *)(obj + 0x36) + timeDelta);
            if (a < 0)
                a = 0;
            else if (a > 0xff)
                a = 0xff;
            *(u8 *)(obj + 0x36) = a;
        }
    }
    model = Obj_GetActiveModel(obj);
    modelBase = *(int *)model;
    for (i = 0; i < *(u16 *)(modelBase + 0xe4); i++) {
        int curr = ObjModel_GetCurrentVertexCoords(model, i);
        int base = ObjModel_GetBaseVertexCoords(modelBase, i);
        int idx = (u16)(int)(lbl_803E6E70 * ((f32)*(s16 *)(curr + 4) / *(f32 *)state)) +
                  *(u16 *)(state + 0x60);
        if (*(s16 *)(base + 0) > 0)
            *(s16 *)(curr + 0) =
                (int)(lbl_803E6E74 * fn_80293E80(lbl_803E6E78 * (f32)idx / lbl_803E6E7C) +
                      (f32)*(s16 *)(base + 0));
        else
            *(s16 *)(curr + 0) =
                (int)((f32)*(s16 *)(base + 0) -
                      lbl_803E6E74 * fn_80293E80(lbl_803E6E78 * (f32)idx / lbl_803E6E7C));
    }
    return 0;
}
extern f32 PSVECDistance(void *a, void *b);
extern f32 lbl_803E6E94;
void wctemplebri_update(int obj)
{
    int r4c = *(int *)(obj + 0x4c);
    int state;
    int model;
    int modelBase;
    int i;

    Obj_GetPlayerObject();
    state = *(int *)(obj + 0xb8);
    wctemplebri_updateModelWarp(obj, state);
    model = Obj_GetActiveModel(obj);
    modelBase = *(int *)model;
    for (i = 0; i < *(u16 *)(modelBase + 0xe4); i++) {
        int curr = ObjModel_GetCurrentVertexCoords(model, i);
        int base = ObjModel_GetBaseVertexCoords(modelBase, i);
        int idx = (u16)(int)(lbl_803E6E70 * ((f32)*(s16 *)(curr + 4) / *(f32 *)state)) +
                  *(u16 *)(state + 0x60);
        if (*(s16 *)(base + 0) > 0)
            *(s16 *)(curr + 0) =
                (int)(lbl_803E6E74 * fn_80293E80(lbl_803E6E78 * (f32)idx / lbl_803E6E7C) +
                      (f32)*(s16 *)(base + 0));
        else
            *(s16 *)(curr + 0) =
                (int)((f32)*(s16 *)(base + 0) -
                      lbl_803E6E74 * fn_80293E80(lbl_803E6E78 * (f32)idx / lbl_803E6E7C));
    }
    if (*(u8 *)(state + 0x5f) != 0) {
        if ((*(u8 *)(state + 0x66) & 1) == 0) {
            GameBit_Set(0xedb, 1);
            *(u8 *)(state + 0x66) |= 1;
            GameBit_Set(*(s16 *)(r4c + 0x1e), 1);
        }
        {
            int a = (int)((f32)(u32) * (u8 *)(obj + 0x36) + timeDelta);
            if (a < 0)
                a = 0;
            else if (a > 0xff)
                a = 0xff;
            *(u8 *)(obj + 0x36) = a;
        }
        ObjHits_EnableObject(obj);
    } else {
        GameBit_Set(0xedb, 0);
        ObjHits_DisableObject(obj);
    }
    if ((void *)Obj_GetPlayerObject() != NULL) {
        if (PSVECDistance((void *)(obj + 0x18), (void *)(Obj_GetPlayerObject() + 0x18)) >
            lbl_803E6E94) {
            GameBit_Set(0xedb, 0);
        }
    }
}
#pragma scheduling on
#pragma peephole on

#pragma peephole off
#pragma scheduling off
void wctemplebri_init(int obj, int initData)
{
    int state;
    int model;
    int modelData;
    int maxY;
    int i;
    int p, k;
    int done;

    *(s16 *)(obj + 0) = (s16)((s8)*(u8 *)(initData + 0x18) << 8);
    *(u8 *)(obj + 0xad) = *(u8 *)(initData + 0x19);
    if ((s8)*(u8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55))
        *(u8 *)(obj + 0xad) = 0;
    *(void **)(obj + 0xbc) = (void *)wctemplebri_interactCallback;
    state = *(int *)(obj + 0xb8);
    maxY = 0;
    model = Obj_GetActiveModel(obj);
    modelData = *(int *)(model + 0);
    for (i = 0; i < *(u16 *)(modelData + 0xe4); i++) {
        int y = *(s16 *)(ObjModel_GetCurrentVertexCoords(model, i) + 4);
        if (y < maxY)
            maxY = y;
    }
    done = 0;
    while (done == 0) {
        done = 1;
        p = state;
        for (k = 0; k < *(u8 *)(state + 0x4f) - 1; k++) {
            f32 a = *(f32 *)(p + 4);
            f32 b = *(f32 *)(p + 8);
            if (a < b) {
                *(f32 *)(p + 4) = b;
                *(f32 *)(p + 8) = (f32)(int)a;
                done = 0;
            }
            p += 4;
        }
    }
    *(u8 *)(state + 0x4f) = 0xa;
    *(f32 *)(state + 0) = (f32)maxY;
    if ((u32)GameBit_Get(*(s16 *)(initData + 0x1e)) != 0) {
        *(u8 *)(state + 0x5f) = 1;
        *(u8 *)(state + 0x66) |= 1;
    }
    if (*(u8 *)(state + 0x5f) != 0) {
        for (k = 0; k < *(u8 *)(state + 0x4f); k++) {
            *(u8 *)(state + k + 0x50) = 0xff;
            *(u8 *)(state + k + 0x40) = 1;
        }
        *(u8 *)(obj + 0x36) = 0xff;
    } else {
        ObjHits_DisableObject(obj);
        *(u8 *)(obj + 0x36) = 0;
    }
    *(u16 *)(obj + 0xb0) |= 0x6000;
    ObjModel_SetPostRenderCallback(model, fn_800284CC);
}
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_803E6E98;
extern f32 lbl_803E6E2C;
extern f32 lbl_803E72E8;
extern void ModelLightStruct_free(void *light);
extern void queueGlowRender(void *light);
extern int lbl_803DDDA8;
extern f32 lbl_803DDDB0;
extern f32 lbl_803DDDAC;
extern f32 lbl_803E72B0;

int wcfloortile_getExtraSize(void) { return 8; }
int wcfloortile_getObjectTypeId(void) { return 0; }
void wcfloortile_free(void) {}
#pragma peephole off
void wcfloortile_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E98);
    }
}
#pragma peephole on
void wcfloortile_hitDetect(void) {}
#pragma peephole off
#pragma scheduling off
void wcfloortile_init(int obj)
{
    int state = *(int *)(obj + 0xb8);

    *(s16 *)obj = -0x4000;
    *(s16 *)(*(int *)(obj + 0x54) + 0x60) |= 0x1800;
    *(u8 *)(state + 7) |= 2;
}
#pragma scheduling on
#pragma peephole on
void wcfloortile_release(void) {}
void wcfloortile_initialise(void) {}

extern int fn_80065640(void);
extern void fn_80065574(int a, int b, int c);
extern f32 lbl_803E6E9C;
extern f32 lbl_803E6EA0;
extern f32 lbl_803E6EA4;
extern f32 lbl_803E6EA8;
extern f32 lbl_803E6EAC;
extern f32 lbl_803E6EB0;
extern f32 lbl_803E6EB4;
extern f32 lbl_803E6EB8;
extern f32 lbl_803E6EBC;

#pragma peephole off
#pragma scheduling off
void wcfloortile_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if ((u32)GameBit_Get(824) != 0) {
        *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc);
        *(u8 *)(state + 6) = 3;
    }
    switch (*(u8 *)(state + 6)) {
    case 0:
    default:
        if (*(u8 *)(state + 7) & 4) {
            f32 z = lbl_803E6E9C;
            int i, off;
            for (i = 0, off = 0; i < *(s8 *)(*(int *)(obj + 0x58) + 0x10f); i++, off += 4) {
                int e = *(int *)(*(int *)(obj + 0x58) + off + 0x100);
                if (*(s16 *)(e + 0x44) == 1) {
                    Sfx_PlayFromObject(obj, 198);
                    *(u8 *)(state + 6) = 1;
                    *(f32 *)(state + 0) = z;
                    *(f32 *)(obj + 0x28) = z;
                }
            }
        } else if ((u32)GameBit_Get(613) != 0) {
            *(u8 *)(state + 7) |= 4;
        }
        break;
    case 1:
        *(f32 *)(state + 0) = *(f32 *)(state + 0) + timeDelta;
        if (*(f32 *)(state + 0) > lbl_803E6EA0) {
            *(u8 *)(state + 7) |= 3;
            *(f32 *)(state + 0) = lbl_803E6EA0;
            *(f32 *)(obj + 0x28) = lbl_803E6EA4 * timeDelta + *(f32 *)(obj + 0x28);
        }
        *(s16 *)(state + 4) = lbl_803E6EA8 * (*(f32 *)(state + 0) / lbl_803E6EA0);
        *(s16 *)(obj + 2) = (s16)randomGetRange(-*(s16 *)(state + 4), *(s16 *)(state + 4));
        *(s16 *)(obj + 4) = (s16)randomGetRange(-*(s16 *)(state + 4), *(s16 *)(state + 4));
        *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x28) * timeDelta + *(f32 *)(obj + 0x10);
        {
            f32 d = *(f32 *)(setup + 0xc) - *(f32 *)(obj + 0x10);
            f32 t;
            if (d < lbl_803E6EAC) {
                t = lbl_803E6EB0;
            } else if (d > lbl_803E6EB4) {
                t = lbl_803E6E9C;
            } else {
                t = lbl_803E6E98 - (d - lbl_803E6EAC) / lbl_803E6EB8;
                if (t > lbl_803E6E98) {
                    t = lbl_803E6E98;
                } else if (t < lbl_803E6E9C) {
                    t = lbl_803E6E9C;
                }
                t = t * lbl_803E6EB0;
            }
            *(u8 *)(obj + 0x36) = (int)t;
        }
        if (*(u8 *)(obj + 0x36) == 0) {
            *(u8 *)(state + 6) = 2;
        }
        break;
    case 2:
        *(u8 *)(obj + 0x36) = 0;
        ObjHits_DisableObject(obj);
        *(u8 *)(state + 7) |= 3;
        break;
    case 3:
        {
            f32 a = lbl_803E6EBC * timeDelta + (f32)(u32) * (u8 *)(obj + 0x36);
            if (a > lbl_803E6EB0) {
                a = lbl_803E6EB0;
            }
            *(u8 *)(obj + 0x36) = (int)a;
        }
        ObjHits_EnableObject(obj);
        break;
    }
    {
        int setup2 = *(int *)(obj + 0x4c);
        if (fn_80065640() != 0) {
            *(u8 *)(state + 7) |= 2;
        }
        if (*(u8 *)(state + 7) & 2) {
            if (fn_80065640() == 0) {
                fn_80065574(*(s16 *)(setup2 + 0x1a), *(int *)(obj + 0x30), *(u8 *)(state + 7) & 1);
                *(u8 *)(state + 7) &= ~2;
            }
        }
    }
}
#pragma scheduling on
#pragma peephole on

int wcapertures_getExtraSize(void) { return 8; }
#pragma scheduling off
int wcapertures_getObjectTypeId(int obj)
{
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
}
void wcapertures_free(int obj)
{
    void *light = *(void **)(*(int *)(obj + 0xb8));

    if (light != NULL) {
        ModelLightStruct_free(light);
    }
}
#pragma peephole off
void wcapertures_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int *)(obj + 0xb8);
    u8 *light;

    if (visible != 0) {
        *(u8 *)(state + 7) |= 1;
    } else {
        *(u8 *)(state + 7) &= ~1;
    }
    light = *(u8 **)state;
    if (light != NULL && light[0x2f8] != 0 && light[0x4c] != 0) {
        queueGlowRender(light);
    }
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E2C);
    }
}
#pragma scheduling on
#pragma peephole on
extern f32 lbl_803E6E28;
extern f32 lbl_803E6E30;
extern f32 lbl_803E6E34;
extern void lightFn_8001d6b0(void *light);
#pragma peephole off
#pragma scheduling off
void wcapertures_hitDetect(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(u8 *)(state + 6) == 2) {
        f32 col[3];
        s16 ev[2];

        if ((s8)*(u8 *)(obj + 0xad) == 0)
            ev[1] = 1;
        else
            ev[1] = 0;
        col[0] = lbl_803E6E30;
        col[1] = lbl_803E6E34;
        col[2] = lbl_803E6E28;
        (*(void (**)(int, int, void *, int, int, void *))(*gPartfxInterface + 8))(
            obj, 0x805, ev, 2, -1, col);
    }
    if (*(void **)state != NULL)
        lightFn_8001d6b0(*(void **)state);
}
#pragma scheduling on
#pragma peephole on
void wcapertures_release(void) {}
void wcapertures_initialise(void) {}

extern f32 lbl_803E6E3C;
extern f32 lbl_803E6E40;
extern void *objCreateLight(int obj, int kind);
extern void modelLightStruct_setField50(void *light, int v);
extern void fn_8001D730(void *light, u16 a, u8 b, u8 c, u8 d, u8 e, f32 f);
extern void fn_8001D714(void *light, f32 v);

#pragma peephole off
#pragma scheduling off
int wcapertures_interactCallback(int obj, int p2, int p3)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        if (*(u8 *)(p3 + (i + 0x81)) == 1)
            *(u8 *)(state + 6) = 1;
    }
    return 0;
}
void wcapertures_init(int obj, int initData)
{
    int state = *(int *)(obj + 0xb8);

    *(s16 *)(obj + 0) = (s16)((s8)*(u8 *)(initData + 0x18) << 8);
    *(void **)(obj + 0xbc) = (void *)wcapertures_interactCallback;
    *(u8 *)(obj + 0xad) = *(u8 *)(initData + 0x19);
    if ((s8)*(u8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55))
        *(u8 *)(obj + 0xad) = 0;
    if ((u32)GameBit_Get(*(s16 *)(initData + 0x20)) != 0) {
        if ((u32)GameBit_Get(*(s16 *)(initData + 0x1e)) != 0)
            *(u8 *)(state + 6) = 2;
        else
            *(u8 *)(state + 6) = 1;
    }
    *(u8 *)(obj + 0x36) = 1;
    *(u16 *)(state + 4) = 0xff;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), fn_800284CC);
    *(int *)(state + 0) = (int)objCreateLight(obj, 1);
    if (*(int *)(state + 0) != 0) {
        modelLightStruct_setField50(*(void **)(state + 0), 2);
        if ((s8)*(u8 *)(obj + 0xad) == 0)
            fn_8001D730(*(void **)(state + 0), 0, 0xff, 0xff, 0x4d, 0x96, lbl_803E6E3C);
        else
            fn_8001D730(*(void **)(state + 0), 0, 0x4d, 0x4d, 0xff, 0xff, lbl_803E6E3C);
        fn_8001D714(*(void **)(state + 0), lbl_803E6E40);
    }
}
#pragma scheduling reset
#pragma peephole reset

extern int *gCameraInterface;
extern int fn_802969F0(int player);
extern f32 Camera_GetFovY(void);
extern void lightFn_8001db6c(void *light, int flag, f32 val);
extern f32 lbl_803E6E38;

#pragma peephole off
#pragma scheduling off
void wcapertures_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int player = Obj_GetPlayerObject();
    void *light;
    int alpha, target;

    *(s16 *)(state + 4) = 0;
    switch (*(u8 *)(state + 6)) {
    case 0:
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
            *(u8 *)(state + 6) = 1;
        }
        break;
    case 1:
        if ((*(int (**)(void))(*gCameraInterface + 0x10))() == 68 && fn_802969F0(player) == 33) {
            *(s16 *)(state + 4) = 255;
            if (Camera_GetFovY() <= lbl_803E6E38 && (*(u16 *)(obj + 0xb0) & 0x800)) {
                GameBit_Set(*(s16 *)(setup + 0x1e), 1);
                *(u8 *)(state + 6) = 2;
            }
        }
        break;
    case 2:
        *(s16 *)(state + 4) = 0;
        break;
    }
    alpha = *(u8 *)(obj + 0x36);
    target = *(s16 *)(state + 4);
    if (alpha < target) {
        int v = alpha + framesThisStep * 4;
        if (v > target) {
            v = target;
        }
        *(u8 *)(obj + 0x36) = v;
    } else if (alpha > target) {
        int v = alpha - framesThisStep * 4;
        if (v < target) {
            v = target;
        }
        *(u8 *)(obj + 0x36) = v;
    }
    light = *(void **)(state + 0);
    if (light != NULL) {
        if (*(u8 *)(obj + 0x36) > 128) {
            lightFn_8001db6c(light, 1, lbl_803E6E2C);
        } else {
            lightFn_8001db6c(light, 0, lbl_803E6E2C);
        }
    }
}
#pragma scheduling on
#pragma peephole on

int waterflowwe_getExtraSize(void) { return 8; }
int waterflowwe_getObjectTypeId(void) { return 0; }
extern f32 lbl_803E72F4;
extern int ObjAnim_SetCurrentMove(int obj, int moveId, f32 blend, int flag);
#pragma scheduling off
void waterflowwe_init(int obj, u8 *setup)
{
    *(s16 *)(obj + 4) = (s16)(setup[0x18] << 8);
    *(s16 *)(obj + 2) = (s16)(setup[0x19] << 8);
    *(s16 *)(obj + 0) = (s16)(setup[0x1a] << 8);
    if (setup[0x1b] != 0) {
        *(f32 *)(obj + 8) = (f32)(u32)setup[0x1b] / lbl_803E72F4;
        if (*(f32 *)(obj + 8) == lbl_803E72B0) {
            *(f32 *)(obj + 8) = lbl_803E72E8;
        }
        *(f32 *)(obj + 8) = *(f32 *)(obj + 8) * *(f32 *)(*(int *)(obj + 0x50) + 4);
    }
    *(u16 *)(obj + 0xb0) |= 0x2000;
    ObjAnim_SetCurrentMove(obj, 0, lbl_803E72B0, 0);
}
#pragma scheduling reset
#pragma scheduling off
void waterflowwe_free(int obj)
{
    if ((u32)obj == (u32)lbl_803DDDA8) {
        lbl_803DDDA8 = 0;
    }
}
#pragma scheduling on
#pragma peephole off
void waterflowwe_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E72E8);
    }
}
#pragma peephole on
void waterflowwe_hitDetect(void) {}
extern void waterflowwe_calcCurrentVector(int obj, f32 *vx, f32 *vz);
extern int getAngle(f32 dx, f32 dz);
extern int ObjAnim_SetCurrentMove(int obj, int moveId, f32 blend, int flag);
extern f32 lbl_803E72EC;
extern f32 lbl_803E72F0;
#pragma scheduling off
void waterflowwe_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    f32 vx, vz;

    waterflowwe_calcCurrentVector(obj, &vx, &vz);
    *(s16 *)obj = (s16)(getAngle(vx, vz) + 0x4000);
    if ((u32)lbl_803DDDA8 == 0 && *(u8 *)(setup + 0x1f) == 0) {
        lbl_803DDDA8 = obj;
    }
    if ((u32)obj == (u32)lbl_803DDDA8) {
        f32 a;

        lbl_803DDDB0 = lbl_803E72EC * timeDelta + lbl_803DDDB0;
        a = lbl_803DDDB0;
        while (a > lbl_803E72E8) {
            a -= lbl_803E72E8;
        }
        lbl_803DDDB0 = a;
        lbl_803DDDAC = lbl_803E72F0 * timeDelta + lbl_803DDDAC;
        a = lbl_803DDDAC;
        while (a > lbl_803E72E8) {
            a -= lbl_803E72E8;
        }
        lbl_803DDDAC = a;
    }
    if (lbl_803E72B0 == vx && lbl_803E72B0 == vz) {
        ObjAnim_SetCurrentMove(obj, 1, lbl_803DDDB0, 0);
    } else {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803DDDB0, 0);
    }
}
#pragma scheduling on
void waterflowwe_release(void) {}
#pragma scheduling off
void waterflowwe_initialise(void)
{
    lbl_803DDDA8 = 0;
    lbl_803DDDB0 = lbl_803E72B0;
    lbl_803DDDAC = lbl_803E72B0;
}
#pragma scheduling on

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
int suntemple_interactCallback(int obj, int p2, int p3);

extern f32 lbl_802C25D8[];
extern int getCurMapLayer(void);

typedef struct { f32 x, y, z; } SunVec3;

#pragma peephole off
#pragma scheduling off
int suntemple_interactCallback(int obj, int p2, int p3)
{
    int setup = *(int *)(obj + 0x4c);
    int i;
    SunVec3 vec = *(SunVec3 *)lbl_802C25D8;

    *(u8 *)(obj + 0xaf) |= 0x8;
    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        switch (*(u8 *)(p3 + 0x81 + i)) {
        default:
            if (*(u8 *)(setup + 0x1b) & 0x4) {
                int *tex;
                GameBit_Set(*(s16 *)(setup + 0x1c), 1);
                tex = (int *)objFindTexture(obj, 0, 0);
                if (tex != NULL)
                    *tex = 0x100;
            }
            break;
        case 2:
            if (*(s16 *)(setup + 0x24) != 0)
                (*(void (**)(int))(*gObjectTriggerInterface + 0x58))(p3);
            break;
        case 3:
            if ((s8)*(u8 *)(obj + 0xad) == 1)
                (*(void (**)(void *, int, int, int))(*gMapEventInterface + 0x24))(
                    &vec, -0x4000, getCurMapLayer(), 0);
            break;
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void suntemple_init(u8 *obj, u8 *setup)
{
    u8 *state;

    *(s16 *)(obj + 0) = (s16)(setup[0x18] << 8);
    *(s16 *)(obj + 2) = (s16)(setup[0x19] << 8);
    *(s16 *)(obj + 4) = (s16)(setup[0x1a] << 8);
    *(void **)(obj + 0xbc) = (void *)suntemple_interactCallback;
    obj[0xad] = setup[0x21];
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        obj[0xad] = 0;
    }
    state = *(u8 **)(obj + 0xb8);
    state[0] = (u8)GameBit_Get(*(s16 *)(setup + 0x1c));
    state[1] = (*(u8 (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac));
    if ((setup[0x1b] & 1) != 0 && state[0] != 0) {
        obj[0x36] = 0;
    }
    if (state[0] != 0) {
        int *texture = objFindTexture((int)obj, 0, 0);
        if (texture != NULL) {
            *texture = 0x100;
        }
    }
}

extern void buttonDisable(int a, int b);
extern int *gGameUIInterface;

void suntemple_update(int obj)
{
    int state;
    int cfg;
    int *texture;
    int flags;

    state = *(int *)(obj + 0xb8);
    cfg = *(int *)(obj + 0x4c);
    *(u8 *)(state + 0) = (u8)GameBit_Get(*(s16 *)(cfg + 0x1c));
    if (*(u8 *)(state + 0) == 0) {
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *texture = 0;
        }
        *(f32 *)(obj + 0xc) = *(f32 *)(cfg + 0x8);
        *(f32 *)(obj + 0x10) = *(f32 *)(cfg + 0xc);
        *(f32 *)(obj + 0x14) = *(f32 *)(cfg + 0x10);
        *(u8 *)(obj + 0xaf) &= ~0x08;

        if (*(s16 *)(cfg + 0x22) == -1) {
            *(u8 *)(obj + 0xaf) &= ~0x10;
        } else if ((u32)GameBit_Get(*(s16 *)(cfg + 0x22)) != 0) {
            *(u8 *)(obj + 0xaf) &= ~0x10;
        } else {
            *(u8 *)(obj + 0xaf) |= 0x10;
            if ((*(u8 *)(cfg + 0x1b) & 0x10) != 0) {
                *(u8 *)(obj + 0xaf) |= 0x08;
            }
        }

        if (*(s16 *)(obj + 0x46) == 0x830 && gameTimerIsRunning() != 0) {
            *(u8 *)(obj + 0xaf) |= 0x10;
        }

        if ((*(u8 *)(obj + 0xaf) & 0x1) != 0) {
            if (*(s16 *)(cfg + 0x1e) == -1 ||
                (*(int (**)(int))(*gGameUIInterface + 0x20))(*(s16 *)(cfg + 0x1e)) != 0) {
                if (*(s8 *)(cfg + 0x20) != -1) {
                    if (*(s16 *)(obj + 0x46) == 0x526) {
                        if (*(u8 *)(state + 1) == 1 &&
                            ((u32)GameBit_Get(0x25a) != 0 || (u32)GameBit_Get(0x25b) != 0)) {
                            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                                *(s8 *)(cfg + 0x20) + 2, obj, -1);
                        } else if (*(u8 *)(state + 1) == 2 &&
                                   ((u32)GameBit_Get(0x202) != 0 || (u32)GameBit_Get(0x243) != 0)) {
                            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                                *(s8 *)(cfg + 0x20) + 2, obj, -1);
                        } else {
                            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                                *(s8 *)(cfg + 0x20), obj, -1);
                        }
                    } else {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                            *(s8 *)(cfg + 0x20), obj, -1);
                    }
                }
                if ((*(u8 *)(cfg + 0x1b) & 0x04) == 0) {
                    GameBit_Set(*(s16 *)(cfg + 0x1c), 1);
                    texture = objFindTexture(obj, 0, 0);
                    if (texture != NULL) {
                        *texture = 0x100;
                    }
                }
                if ((*(u8 *)(cfg + 0x1b) & 0x08) != 0) {
                    GameBit_Set(*(s16 *)(cfg + 0x22), 0);
                } else {
                    *(u8 *)(state + 0) = 1;
                    *(int *)(obj + 0xf4) = 1;
                }
                buttonDisable(0, 0x100);
            }
        }
    } else {
        if (*(int *)(obj + 0xf4) == 0 && *(s8 *)(cfg + 0x20) != -1 &&
            *(s16 *)(cfg + 0x24) != 0) {
            (*(void (**)(int))(*gObjectTriggerInterface + 0x54))(obj);
            flags = 1;
            if ((*(u8 *)(cfg + 0x1b) & 0x20) != 0) {
                flags |= 0x2;
            }
            if ((*(u8 *)(cfg + 0x1b) & 0x40) != 0) {
                flags |= 0x3;
            }
            if ((*(u8 *)(cfg + 0x1b) & 0x80) != 0) {
                flags |= 0x4;
            }
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                *(s8 *)(cfg + 0x20), obj, flags);
        }
        *(u8 *)(obj + 0xaf) |= 0x08;
    }
    *(int *)(obj + 0xf4) = 1;
}
#pragma scheduling on
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

#pragma scheduling off
void pointlight_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)state != NULL) {
        ModelLightStruct_free(*(void **)state);
    }
    ObjGroup_RemoveObject(obj, 0x35);
}
#pragma scheduling reset

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

#pragma scheduling off
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
#pragma scheduling reset

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

#pragma scheduling off
void timer_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    ObjGroup_RemoveObject(obj, 0x4c);
    if (*(void **)(state + 4) != NULL) {
        fn_8001CB3C(state + 4);
    }
    gameTimerStop();
}
#pragma scheduling reset

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

#pragma scheduling off
void timer_forceStart(int obj)
{
    int state = *(int *)(obj + 0xb8);
    ((TimerFlags *)(state + 0xd))->manual = 1;
}
#pragma scheduling reset

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

extern int timerCountDown(void *timer);
extern int fn_8001CC9C(int obj, int a, int b, int c, int d);
extern f32 lbl_803DC418;
extern f32 lbl_803DC41C;
extern f32 lbl_803E741C;
extern f32 lbl_803E7420;

#pragma peephole off
#pragma scheduling off
void timer_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    TimerFlags *f = (TimerFlags *)(state + 0xd);
    int flag;

    if (fn_80080150(state) != 0) {
        flag = 0;
        if (f->manual == 0 && (u32)GameBit_Get(*(s16 *)(setup + 0x20)) == 0) {
            storeZeroToFloatParam((void *)state);
            if (*(u8 *)(state + 0xc) == 1) {
                if (*(int *)(*(int *)(obj + 0x4c) + 0x14) != 0x466ED) {
                    Sfx_PlayFromObject(obj, 126);
                }
            }
            flag = 1;
        }
        if (timerCountDown((void *)state) != 0) {
            GameBit_Set(*(s16 *)(setup + 0x1e), 1);
            GameBit_Set(*(s16 *)(setup + 0x20), 0);
            flag = 1;
        }
        if (flag != 0) {
            f->expired = 1;
            switch (*(u8 *)(state + 0xc)) {
            case 1:
                gameTimerStop();
                break;
            case 2:
                fn_8001CB3C(state + 4);
                break;
            }
            f->manual = 0;
        }
    } else {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0 || f->manual != 0) {
            storeZeroToFloatParam((void *)state);
            if (*(s16 *)(setup + 0x1a) != 0) {
                s16toFloat((void *)state, (s16)(*(s16 *)(setup + 0x1a) * 60));
            }
            switch (*(u8 *)(state + 0xc)) {
            case 1:
                gameTimerInit(29, *(s16 *)(setup + 0x1a));
                timerSetToCountUp();
                break;
            case 2:
                *(int *)(state + 4) = fn_8001CC9C(obj, 255, 0, 0, 0);
                if (*(int *)(state + 4) != 0) {
                    fn_8001D730((void *)*(int *)(state + 4), 0, 255, 0, 0, 100, lbl_803DC418);
                    lightVecFn_8001dd88((void *)*(int *)(state + 4), lbl_803E741C, lbl_803E7420,
                                        lbl_803E741C);
                }
                break;
            }
        }
        if (*(u8 *)(state + 0xc) == 2 && fn_80080150(state) != 0) {
            int hold = *(int *)(state + 4);
            int tv = (int)((f32)(*(s16 *)(setup + 0x1a) * 60) / *(f32 *)(state + 0) *
                           lbl_803DC41C);
            int *texPtr = objFindTexture(obj, 0, 0);
            int v;
            if (texPtr != 0) {
                v = *texPtr + tv * framesThisStep;
                if (v > 512) {
                    v -= 512;
                }
                *texPtr = v;
            }
            if (hold != 0) {
                tv = v >> 8;
            } else {
                tv = 0;
            }
            if (*(int *)(state + 4) != 0) {
                if (tv == 1 && tv != f->flag20) {
                    Sfx_PlayFromObject(obj, 986);
                }
                lightFn_8001db6c((void *)*(int *)(state + 4), (u8)tv, lbl_803E741C);
            }
            f->flag20 = (u8)tv;
        }
        if (*(int *)(state + 4) != 0) {
            lightFn_8001d6b0((void *)*(int *)(state + 4));
        }
    }
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

extern f32 lbl_8032BE20[];
extern f32 lbl_803DC3F8[2];
extern f32 lbl_803DC400[2];
extern f32 lbl_803DC408[2];
extern f32 lbl_803E7404;

#pragma peephole off
#pragma scheduling off
void vortex_init(int obj, int initData)
{
    f32 *base = lbl_8032BE20;
    int state = *(int *)(obj + 0xb8);
    u8 i;

    ((VortexFlags *)(state + 0x26))->active = 0;
    if (*(s16 *)(initData + 0x20) != -1) {
        ((VortexFlags *)(state + 0x26))->active = (u8)GameBit_Get(*(s16 *)(initData + 0x20));
    }
    if (*(s16 *)(obj + 0x46) == 0x835) {
        for (i = 0; i < 2; i++) {
            *(f32 *)(state + i * 4 + 0x14) = lbl_803DC3F8[i];
            *(f32 *)(state + i * 4 + 0x8) = lbl_803DC400[i];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    } else if (*(s16 *)(obj + 0x46) == 0x838) {
        for (i = 0; i < 2; i++) {
            *(f32 *)(state + i * 4 + 0x14) = lbl_803DC3F8[i];
            *(f32 *)(state + i * 4 + 0x8) = lbl_803DC408[i];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    } else if (*(s16 *)(obj + 0x46) == 0x83d) {
        for (i = 0; i < 3; i++) {
            *(f32 *)(state + i * 4 + 0x14) = base[i];
            *(f32 *)(state + i * 4 + 0x8) = base[i + 3];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
    } else {
        for (i = 0; i < 3; i++) {
            *(f32 *)(state + i * 4 + 0x14) = base[i + 6];
            *(f32 *)(state + i * 4 + 0x8) = base[i + 9];
            *(s16 *)(state + i * 2 + 0x20) = (s16)randomGetRange(-0x7fff, 0x7fff);
        }
        if (((VortexFlags *)(state + 0x26))->active != 0) {
            if (*(s16 *)(initData + 0x1e) != -1) {
                ((VortexFlags *)(state + 0x26))->active = !GameBit_Get(*(s16 *)(initData + 0x1e));
            }
        }
    }
    *(u16 *)(obj + 0xb0) |= 0x2000;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), fn_800284CC);
    if (((VortexFlags *)(state + 0x26))->active != 0)
        *(f32 *)(state + 0) = lbl_803E73E0;
    else
        *(f32 *)(state + 0) = lbl_803E73D0;
    *(f32 *)(state + 4) = (f32)randomGetRange(0, 0x14);
    *(f32 *)(obj + 0x40) = *(f32 *)(obj + 0x40) * lbl_803E7404;
}
#pragma scheduling reset
#pragma peephole reset

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

#pragma scheduling off
void ring_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 0x20) != NULL) {
        ModelLightStruct_free(*(void **)(state + 0x20));
        *(void **)(state + 0x20) = NULL;
    }
}
#pragma scheduling reset

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

typedef struct RingFlags {
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 bit20 : 1;
    u8 bit10 : 1;
    u8 pad : 4;
} RingFlags;

extern f32 lbl_803E70C4;
extern f32 lbl_803E70D8;

typedef struct CntHitFlags {
    u8 disabled : 1;
    u8 pad : 7;
} CntHitFlags;

extern f32 lbl_803E7430;
extern void spawnExplosion(int obj, f32 v, int a, int b, int c, int d, int e, int f, int g);
extern void ObjHits_DisableObject(int obj);
extern void ObjHits_EnableObject(int obj);
extern void ObjHitbox_SetSphereRadius(int obj, int radius);

#pragma peephole off
#pragma scheduling off
void ring_init(int obj, int setup) {
    int state = *(int *)(obj + 0xb8);
    RingFlags *f = (RingFlags *)(state + 0x14);
    s16 type = *(s16 *)(obj + 0x46);
    if (type == 1548) {
        *(u8 *)(state + 0) = 0;
    } else if (type == 2073) {
        *(u8 *)(state + 0) = 0;
        f->bit10 = 1;
    } else if (type == 1547) {
        *(u8 *)(state + 0) = 2;
    } else if (type == 2044) {
        *(u8 *)(state + 0) = 3;
    } else if (type == 2043) {
        *(u8 *)(state + 0) = 4;
    } else {
        *(u8 *)(state + 0) = 2;
    }
    *(u8 *)(state + 1) = *(u8 *)(setup + 0x19);
    if (*(u8 *)(state + 1) == 2 || *(u8 *)(state + 1) == 3 || *(u8 *)(state + 1) == 5) {
        f->bit80 = 0;
        Obj_SetActiveModelIndex(obj, 1);
    } else {
        f->bit80 = 1;
        ObjHits_DisableObject(obj);
    }
    *(u16 *)(state + 2) = *(s16 *)(setup + 0x1a);
    *(f32 *)(state + 4) = (f32)*(s16 *)(setup + 0x1c) / lbl_803E70C4;
    *(f32 *)(state + 8) = *(f32 *)(obj + 12);
    *(f32 *)(state + 0xc) = *(f32 *)(obj + 16);
    if (*(s8 *)(setup + 0x18) != 0)
        f->bit20 = 1;
    else
        f->bit20 = 0;
    *(s16 *)obj = -32768;
    if (*(u8 *)(state + 0) == 3 || *(u8 *)(state + 0) == 4) {
        f->bit10 = 1;
        *(f32 *)(state + 0x10) = lbl_803E70D8;
    } else {
        *(s16 *)(obj + 6) |= 0x4000;
        *(u8 *)(obj + 0x36) = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

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

extern int lbl_8032BEF8[];
extern u8 lbl_803DC42C[];
extern int lbl_803DC428;
extern void ObjHits_ClearSourceMask(int mask);
extern int arrayIndexOf(int array, int count, int value);
extern int ObjHits_GetPriorityHit(int obj, int *outHit, int *outIdx, int *outVol);
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);

#pragma peephole off
#pragma scheduling off
void cnthitobjec_hitDetect(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int hit;
    int dmg;
    int amount;
    int model;

    if (*(int *)(state + 0) == 0) {
        return;
    }
    hit = ObjHits_GetPriorityHit(obj, 0, 0, &dmg);
    if (hit == 0) {
        return;
    }
    if (*(u8 *)(state + 8) == 0) {
        return;
    }
    if (arrayIndexOf(*(int *)(state + 4), *(u8 *)(state + 8), hit) == -1) {
        return;
    }
    *(int *)(state + 0) = *(int *)(state + 0) - dmg;
    if (*(u8 *)(setup + 0x19) == 2) {
        Obj_SetModelColorFadeRecursive(obj, 30, 200, 0, 0, 1);
        Sfx_PlayFromObject(obj, 1174);
    }
    if (*(int *)(state + 0) <= 0) {
        int s = *(int *)(obj + 0x4c);
        *(int *)(state + 0) = 0;
        GameBit_Set(*(s16 *)(s + 0x1e), 1);
        if (*(u8 *)(s + 0x19) != 0) {
            if (*(u8 *)(s + 0x19) == 2) {
                amount = 80;
            } else {
                amount = *(s16 *)(s + 0x1c);
            }
            model = *(int *)(*(int *)(obj + 0x4c) + 0x14);
            if (model != 0x470EA && model != 0x480F5 && model != 0x46710 &&
                model != 0x49B43) {
                spawnExplosion(obj, (f32)amount, 1, 1, 1, 1, 0, 1, 0);
            }
            if (*(u8 *)(setup + 0x19) == 2) {
                Sfx_PlayFromObject(obj, 1175);
            }
        }
    } else {
        Sfx_PlayFromObject(obj, 24);
    }
}

void cnthitobjec_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    *(int *)(state + 0) = 0;
    *(s8 *)(setup + 0x18) = (s8)((u32)(s8)*(s8 *)(setup + 0x18) % 3);
    *(int *)(state + 4) = lbl_8032BEF8[(s8)*(s8 *)(setup + 0x18)];
    *(u8 *)(state + 8) = lbl_803DC42C[(s8)*(s8 *)(setup + 0x18)];
    if (*(void **)(state + 4) == (void *)&lbl_803DC428) {
        ObjHits_ClearSourceMask(8);
    }
    if (*(u8 *)(setup + 0x19) == 2) {
        *(s16 *)obj = *(s16 *)(setup + 0x1c);
    } else {
        *(s16 *)(obj + 6) |= 0x4000;
    }
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        ((CntHitFlags *)(state + 9))->disabled = 1;
        ObjHits_DisableObject(obj);
    }
    *(int *)(obj + 0xbc) = (int)cnthitobjec_emitHitEvents;
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

extern void fn_800971A0(int obj, int a, int b, f32 c, int d, int e);
extern void hitDetectFn_80097070(int obj, int a, int b, f32 c, int d, int e);
extern void fn_80097B30(int obj, int a, int b, int c, f32 e, f32 f, f32 g, f32 h, int i,
                        int j, int k);
extern void objFn_800972dc(int obj, int a, int b, int c, f32 e, f32 f, int g, int h, int i);
extern void objParticleFn_80097734(int obj, int enabled, f32 radius, int particleKind,
                                   int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                   f32 scaleZ, void *args, int arg9);

#pragma peephole off
#pragma scheduling off
void dustmotesou_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);

    if (*(s16 *)(setup + 0x24) != -1 && (u32)GameBit_Get(*(s16 *)(setup + 0x24)) == 0) {
        return;
    }
    if (*(s16 *)(obj + 0x46) == 2055) {
        if (*(u8 *)(setup + 0x1b) == 0) {
            return;
        }
        if (*(u8 *)(setup + 0x1c) == 0) {
            return;
        }
        fn_800971A0(obj, *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c), *(f32 *)(setup + 0x20),
                    *(u8 *)(setup + 0x1d), 0);
        return;
    }
    if (*(s16 *)(obj + 0x46) == 2062) {
        if (*(u8 *)(setup + 0x1b) == 0) {
            return;
        }
        if (*(u8 *)(setup + 0x1c) == 0) {
            return;
        }
        hitDetectFn_80097070(obj, *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c),
                             *(f32 *)(setup + 0x20), *(u8 *)(setup + 0x1d), 0);
        return;
    }
    if (*(u8 *)(setup + 0x1b) == 0) {
        return;
    }
    if (*(u8 *)(setup + 0x1c) == 0) {
        return;
    }
    if (*(u8 *)(setup + 0x1d) == 0) {
        return;
    }
    if (*(u8 *)(setup + 0x2a) == 0) {
        fn_80097B30(obj, *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c), *(u8 *)(setup + 0x1d),
                    *(f32 *)(setup + 0x20), (f32)(u32)*(u8 *)(setup + 0x26),
                    (f32)(u32)*(u8 *)(setup + 0x27), (f32)(u32)*(u8 *)(setup + 0x28),
                    *(u8 *)(setup + 0x29), 0, 0);
    } else if (*(u8 *)(setup + 0x2a) == 1) {
        objParticleFn_80097734(obj, *(u8 *)(setup + 0x1b), *(f32 *)(setup + 0x20),
                               *(u8 *)(setup + 0x1c), *(u8 *)(setup + 0x1d), *(u8 *)(setup + 0x29),
                               (f32)(u32)*(u8 *)(setup + 0x26), (f32)(u32)*(u8 *)(setup + 0x27),
                               (f32)(u32)*(u8 *)(setup + 0x28), 0, 0);
    } else {
        objFn_800972dc(obj, *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c), *(u8 *)(setup + 0x1d),
                       *(f32 *)(setup + 0x20), (f32)(u32)*(u8 *)(setup + 0x26),
                       *(u8 *)(setup + 0x29), 0, 0);
    }
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

#pragma scheduling off
int arwblocker_getBlockState(int obj)
{
    int state = *(int *)(obj + 0xb8);
    switch (*(u8 *)(state + 0)) {
    case 1:
        if (*(u8 *)(state + 1) != 0) {
            break;
        }
        return 1;
    case 0:
        break;
    }
    return 0;
}
#pragma scheduling reset

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

#pragma scheduling off
void arwproximit_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 4) != NULL) {
        ModelLightStruct_free(*(void **)(state + 4));
        *(void **)(state + 4) = NULL;
    }
}
#pragma scheduling reset

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

#pragma scheduling off
void arwarwingbo_free(int obj)
{
    (*(void (**)(int))(*gExpgfxInterface + 0x14))(obj);
    ObjGroup_RemoveObject(obj, 0x52);
}
#pragma scheduling reset

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

#pragma dont_inline on
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
#pragma dont_inline reset

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

#pragma dont_inline on
int getArwing(void) { return lbl_803DDD88; }
#pragma dont_inline reset

int arwarwing_getExtraSize(void) { return 0x498; }
int arwarwing_getObjectTypeId(void) { return 0; }
#pragma scheduling off
void arwarwing_free(int obj)
{
    int state = *(int *)(obj + 0xb8);

    ObjGroup_RemoveObject(obj, 0x26);
    lbl_803DDD88 = 0;
    if (*(void **)(state + 0x450) != NULL) {
        ModelLightStruct_free(*(void **)(state + 0x450));
    }
}
#pragma scheduling reset
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
#pragma dont_inline on
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
#pragma dont_inline reset
void arwarwinggu_release(void) {}
void arwarwinggu_initialise(void) {}

int arwingandrossstuff_getExtraSize(void) { return 0x20; }
int arwingandrossstuff_getObjectTypeId(void) { return 0; }
#pragma scheduling off
void arwingandrossstuff_free(int obj)
{
    int state = *(int *)(obj + 0xb8);

    ObjGroup_RemoveObject(obj, 0x2);
    if (*(void **)(state + 0x14) != NULL) {
        ModelLightStruct_free(*(void **)(state + 0x14));
    }
}
#pragma scheduling reset
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

extern int getArwing(void);
extern int ObjHits_GetPriorityHit(int obj, int *outHit, int *outIdx, int *outVol);
extern void spawnExplosion(int obj, f32 v, int a, int b, int c, int d, int e, int f, int g);
extern void Sfx_PlayFromObjectLimited(int obj, int sfxId, int limit);
extern int getAngle(f32 dx, f32 dz);
extern f32 sin(f32 x);
extern void fn_8022D4AC(int arwing, int in);
extern void doRumble(f32 v);
extern int fn_8022D738(int arwing);
extern void PSVECNormalize(void *src, void *dst);
extern void C_VECHalfAngle(void *out, void *a, void *b);
extern void projectileParticleFxFn_80099660(int obj, f32 p2, int p3);
extern f32 lbl_803E7008;
extern f32 lbl_803E7014;
extern f32 lbl_803E7028;
extern f32 lbl_803E702C;
extern f32 lbl_803E7030;
extern f32 lbl_803E7034;
extern f32 lbl_803E7038;
extern f32 lbl_803E703C;
#pragma peephole off
#pragma scheduling off
void arwingandrossstuff_hitDetect(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int arwing = getArwing();

    if (*(s16 *)(obj + 0x46) == 0x80d) {
        int hit;
        int vol;

        if (ObjHits_GetPriorityHit(obj, &hit, 0, &vol) != 0) {
            spawnExplosion(obj, lbl_803E7014, 1, 0, 0, 1, 0, 0, 3);
            *(s16 *)(obj + 6) |= 0x4000;
            ObjHits_DisableObject(obj);
            *(f32 *)(state + 0x10) = lbl_803E7028;
        }
    }
    if (*(void **)(*(int *)(obj + 0x54) + 0x50) != NULL && *(u8 *)(state + 1) == 0) {
        if (*(s16 *)(obj + 0x46) != 0x6ae) {
            Sfx_PlayFromObjectLimited(obj, 0x2b3, 4);
        }
        if (*(s16 *)(obj + 0x46) == 0x7e4) {
            struct {
                f32 x, y, z;
            } v, w;
            f32 ang = lbl_803E7030 *
                      (f32)(s16)(-getAngle(*(f32 *)(obj + 0xc) - *(f32 *)(arwing + 0xc),
                                           *(f32 *)(obj + 0x10) - *(f32 *)(arwing + 0x10))) /
                      lbl_803E7034;

            v.x = lbl_803E702C * fn_80293E80(ang);
            v.y = lbl_803E7038 * sin(ang);
            v.z = lbl_803E7008;
            w = v;
            fn_8022D4AC(arwing, (int)&w);
            doRumble(lbl_803E703C);
        }
        if (*(void **)(*(int *)(obj + 0x54) + 0x50) == (void *)arwing) {
            if (fn_8022D738(arwing) != 0) {
                struct {
                    f32 x, y, z;
                } d;

                PSVECNormalize((void *)(obj + 0x24), (void *)(obj + 0x24));
                d.x = *(f32 *)(obj + 0xc) - *(f32 *)(arwing + 0xc);
                d.y = *(f32 *)(obj + 0x10) - *(f32 *)(arwing + 0x10);
                d.z = *(f32 *)(obj + 0x14) - *(f32 *)(arwing + 0x14);
                PSVECNormalize(&d, &d);
                C_VECHalfAngle((void *)(obj + 0x24), &d, (void *)(obj + 0x24));
                *(f32 *)(obj + 0x24) *= *(f32 *)(state + 8);
                *(f32 *)(obj + 0x28) *= *(f32 *)(state + 8);
                *(f32 *)(obj + 0x2c) *= *(f32 *)(state + 8);
                *(u8 *)(state + 1) = 1;
            }
        }
        *(f32 *)(state + 0x10) = lbl_803E7028;
        *(u8 *)(obj + 0x36) = 0;
        projectileParticleFxFn_80099660(obj, lbl_803E701C, *(u8 *)state);
        if (*(int *)(state + 0x14) != 0) {
            ModelLightStruct_free(*(void **)(state + 0x14));
            *(int *)(state + 0x14) = 0;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

int arwlevelcon_getExtraSize(void) { return 0x24; }
int arwlevelcon_getObjectTypeId(void) { return 0; }
#pragma scheduling off
void arwlevelcon_free(void)
{
    arwingHudSetVisible(2);
    fn_80125D04();
    setIsOvercast(1);
}
#pragma scheduling reset
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

#pragma dont_inline on
#pragma scheduling off
void arwprojectile_setLifetime(int obj, int lifetime)
{
    int state = *(int *)(obj + 0xb8);

    *(f32 *)(state + 4) = (f32)lifetime;
}
#pragma scheduling reset
#pragma dont_inline reset

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

#pragma dont_inline on
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
#pragma dont_inline reset

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
    f32 thr = lbl_803E7154;

    if (*(f32 *)state > thr) {
        *(f32 *)state -= timeDelta;
        if (*(f32 *)state <= thr) {
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

extern void *Camera_GetViewMatrix(void);
extern void *Camera_GetInverseViewRotationMatrix(void);
extern void *fn_8008FB20(f32 *pos, f32 *dir, f32 a, f32 b, u16 angle, int c, int d);
extern void PSVECScale(void *dst, void *src, f32 scale);
extern void PSVECAdd(int p1, int p2, int p3);
extern f32 lbl_803DC518;
extern f32 lbl_803DC51C;
extern f32 lbl_803DC520;
extern f32 lbl_803DC524;
extern f32 lbl_803DC528;
extern f32 lbl_803DC52C;
extern f32 lbl_803E7608;
extern f32 lbl_803E760C;
#pragma peephole off
#pragma scheduling off
void androssligh_updateBeam(int obj, int beam)
{
    f32 start[3];
    f32 end[3];
    f32 tmp[3];

    start[0] = *(f32 *)(obj + 0xc) - lbl_803DC528;
    start[1] = *(f32 *)(obj + 0x10);
    start[2] = *(f32 *)(obj + 0x14);
    end[0] = *(f32 *)(obj + 0xc) + lbl_803DC528;
    end[1] = start[1];
    end[2] = start[2];
    tmp[0] = start[0] - playerMapOffsetX;
    tmp[1] = start[1];
    tmp[2] = start[0] - playerMapOffsetZ;
    PSMTXMultVec(Camera_GetViewMatrix(), tmp, tmp);
    tmp[0] = -tmp[0];
    tmp[1] = -tmp[1];
    tmp[2] = -tmp[2];
    PSVECScale(tmp, tmp, lbl_803DC52C);
    PSMTXMultVec(Camera_GetInverseViewRotationMatrix(), tmp, tmp);
    PSVECAdd((int)start, (int)tmp, (int)start);
    tmp[0] = end[0] - playerMapOffsetX;
    tmp[1] = end[1];
    tmp[2] = end[0] - playerMapOffsetZ;
    PSMTXMultVec(Camera_GetViewMatrix(), tmp, tmp);
    tmp[0] = -tmp[0];
    tmp[1] = -tmp[1];
    tmp[2] = -tmp[2];
    PSVECScale(tmp, tmp, lbl_803DC52C);
    PSMTXMultVec(Camera_GetInverseViewRotationMatrix(), tmp, tmp);
    PSVECAdd((int)end, (int)tmp, (int)end);
    if (*(void **)(beam + 4) == NULL) {
        *(int *)(beam + 4) = (int)fn_8008FB20(start, end, lbl_803DC518, lbl_803DC51C,
                                              (int)lbl_803DC520, (int)lbl_803DC524, 0);
        *(f32 *)(beam + 8) = lbl_803E7608;
    } else {
        *(f32 *)(beam + 8) += timeDelta;
        *(u16 *)(*(int *)(beam + 4) + 0x20) = (int)(lbl_803E760C + *(f32 *)(beam + 8));
        if (*(u16 *)(*(int *)(beam + 4) + 0x20) >= *(u16 *)(*(int *)(beam + 4) + 0x22)) {
            mm_free((void *)*(int *)(beam + 4));
            *(int *)(beam + 4) = 0;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

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
extern int gf_levelcon_handleScriptEvents(int obj, int eventId, u8 *script);
extern void gf_levelcon_findLinkedObjects(int obj);
extern int loadMapAndParent(int mapId);
extern void mapUnload(int a, int b);
extern int mapGetDirIdx(int mapId);
extern void warpToMap(int map, int p2);
extern void loadUiDll(int id);
extern void creditsStart(void);
extern void gameTextShow(int id);
extern f32 lbl_803E7460;
extern f32 lbl_803E7464;
extern f32 lbl_803E7468;
extern f32 lbl_803E746C;
extern f32 lbl_803E7470;
extern f32 lbl_803E7474;
extern f32 lbl_803E7478;
extern f32 lbl_803E747C;
extern f32 lbl_803E7484;
extern f32 lbl_803E7488;
extern f32 lbl_803E748C;
extern f32 timeDelta;

#pragma scheduling off
int gf_levelcon_handleScriptEvents(int obj, int eventId, u8 *script)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    script[0x56] = 0;
    for (i = 0; i < script[0x8b]; i++) {
        switch (script[0x81 + i]) {
        case 0:
            break;
        case 1:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7460, lbl_803E7464, lbl_803E7468);
            getEnvfxAct(obj, obj, 0x21f, 0);
            break;
        case 8:
            *(f32 *)(state + 0xc) = lbl_803E746C;
            break;
        case 2:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, (int)lbl_803E7470, (int)lbl_803E7474, (int)lbl_803E7478, 0, 0);
            skyFn_800894a8(7, lbl_803E7464, lbl_803E747C, lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21d, 0);
            break;
        case 3:
            gf_levelcon_findLinkedObjects(obj);
            if (*(void **)state != NULL) {
                pointlight_setEffectState(*(int *)state, 1);
            }
            break;
        case 4:
            gf_levelcon_findLinkedObjects(obj);
            if (*(void **)state != NULL) {
                pointlight_setEffectState(*(int *)state, 0);
            }
            break;
        case 5:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7480, lbl_803E747C, lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21e, 0);
            break;
        case 6:
            loadMapAndParent(0x29);
            break;
        case 7:
            unlockLevel(0, 0, 1);
            unlockLevel(0, 1, 1);
            mapUnload(mapGetDirIdx(0xb), 0x20000000);
            break;
        case 9:
            unlockLevel(0, 0, 1);
            loadUiDll(4);
            warpToMap(0x12, 0);
            creditsStart();
            break;
        case 10:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7484, lbl_803E747C, lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21f, 0);
            break;
        case 11:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, (int)lbl_803E7470, (int)lbl_803E7474, (int)lbl_803E7478, 0, 0);
            skyFn_800894a8(7, lbl_803E7484, lbl_803E747C, lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21d, 0);
            break;
        }
    }

    if (*(f32 *)(state + 0xc) > lbl_803E7488) {
        gameTextShow(0x476);
        *(f32 *)(state + 0xc) -= timeDelta;
        if (*(f32 *)(state + 0xc) < lbl_803E7488) {
            *(f32 *)(state + 0xc) = lbl_803E7488;
        }
    }

    {
        s16 *p = *(s16 **)(state + 4);
        if (p != NULL) {
            *p += (int)(lbl_803E748C * timeDelta);
        }
    }
    {
        s16 *p = *(s16 **)(state + 8);
        if (p != NULL) {
            *p -= (int)(lbl_803E748C * timeDelta);
        }
    }
    return 0;
}
#pragma scheduling reset

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
extern int mclightning_handleScriptEvents(int obj, int eventId, u8 *script);
extern f32 lbl_803E7440;

typedef struct McLightningFlags {
    u8 hi : 4;
    u8 lo : 4;
} McLightningFlags;

int mclightning_handleScriptEvents(int obj, int eventId, u8 *script) {
    int state = *(int *)(obj + 0xb8);
    int i;
    for (i = 0; i < script[0x8b]; i++) {
        McLightningFlags *f = (McLightningFlags *)(state + 0x1b);
        switch (f->hi) {
        case 0:
            f->hi = 1;
            *(f32 *)(state + 8) = lbl_803E7440 * (f32)(u32)script[0x81 + i];
            break;
        case 1:
            f->hi = 2;
            *(f32 *)(state + 0xc) = lbl_803E7440 * (f32)(u32)script[0x81 + i];
            break;
        case 2:
            f->hi = 3;
            *(u8 *)(state + 0x18) = script[0x81 + i];
            break;
        case 3:
            f->hi = 4;
            *(u8 *)(state + 0x19) = script[0x81 + i];
            break;
        case 4:
            f->hi = 5;
            *(u8 *)(state + 0x1a) = script[0x81 + i];
            *(s16 *)(obj + 6) &= ~0x4000;
            break;
        default:
            f->hi = 0xa;
            break;
        }
    }
    return 0;
}

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

extern void *fn_8008FB20(f32 *pos, f32 *dir, f32 a, f32 b, u16 angle, int c, int d);
extern f32 lbl_803E7450;
extern f32 lbl_803E7454;
extern f32 lbl_803E7458;

void mclightning_render(int obj, int p2, int p3, int p4, int p5, f32 scale) {
    int state = *(int *)(obj + 0xb8);
    McLightningFlags *f = (McLightningFlags *)(state + 0x1b);
    u32 mode = f->hi;
    if (mode == 5) {
        int count;
        int *objs = ObjGroup_GetObjects(0x48, &count);
        int i;
        for (i = 0; i < count; i++) {
            int *o = (int *)objs[i];
            if (*(u8 *)(*(int *)((int)o + 0x4c) + 0x1b) == *(u8 *)(state + 0x1a))
                break;
        }
        if (i == count) {
            f->hi = 0xa;
        } else {
            int foundState;
            McLightningFlags *ff;
            *(void **)(state + 0) =
                fn_8008FB20((f32 *)(obj + 0xc), (f32 *)(objs[i] + 0xc), *(f32 *)(state + 8),
                            *(f32 *)(state + 0xc), *(u8 *)(state + 0x18), *(u8 *)(state + 0x19), 0);
            f->hi = 6;
            *(f32 *)(state + 4) = lbl_803E7450;
            if (f->lo & 1) {
                hitDetectFn_80097070(obj, 1, 7, *(f32 *)(state + 0x10), 0x1e, 0);
            }
            foundState = *(int *)(objs[i] + 0xb8);
            ff = (McLightningFlags *)(foundState + 0x1b);
            if (ff->lo & 1) {
                hitDetectFn_80097070(objs[i], 1, 7, *(f32 *)(foundState + 0x10), 0x1e, 0);
            }
            if (f->lo & 2) {
                objFn_800972dc(obj, 5, 1, 1, *(f32 *)(state + 0x14), lbl_803E7454, 0x64, 0, 0);
            }
            if (ff->lo & 2) {
                objFn_800972dc(objs[i], 5, 1, 1, *(f32 *)(foundState + 0x14), lbl_803E7454, 0x64, 0,
                               0);
            }
        }
    } else if (mode == 6) {
        void *p = *(void **)(state + 0);
        if (p != NULL) {
            renderFn_8008f904(p);
            *(f32 *)(state + 4) += timeDelta;
            *(u16 *)((int)p + 0x20) = (u16)(lbl_803E7458 + *(f32 *)(state + 4));
            if (*(u16 *)((int)p + 0x20) >= *(u16 *)((int)p + 0x22)) {
                mm_free(p);
                *(void **)(state + 0) = NULL;
                f->hi = 0;
                *(s16 *)(obj + 6) |= 0x4000;
            }
        }
    }
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

extern int dll_2E_func07(int obj, int p2, int state, int p4, int p5);
extern void fn_80113F94(int state, f32 a);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern int lbl_803E6CD8;
extern f32 lbl_803E6CDC;
extern f32 lbl_803E6CE8;

#pragma peephole off
#pragma scheduling off
int earthwalker_animEventCallback(int obj, int p2, int p3, int p4)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    *(u8 *)(state + 0x659) &= ~1;
    characterDoEyeAnims(obj, state + 0x624);
    if (dll_2E_func07(obj, p3, state, 0, 0) != 0) {
        return 0;
    }
    if ((s8)p4 != 0) {
        ObjAnim_AdvanceCurrentMove(lbl_803E6CDC, timeDelta, obj, 0);
    }
    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        switch (*(u8 *)(p3 + i + 0x81)) {
        case 1:
            getEnvfxActImmediately(obj, obj, 509, 0);
            break;
        case 2:
            getEnvfxActImmediately(obj, obj, 512, 0);
            break;
        }
    }
    return 0;
}

void earthwalker_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);
    int local;

    local = lbl_803E6CD8;
    *(int *)(obj + 0xbc) = (int)earthwalker_animEventCallback;
    dll_2E_func05(obj, state, -8192, 12743, 2);
    dll_2E_func09(state, 0, &local, 2);
    fn_80113F94(state, lbl_803E6CE8);
    *(u8 *)(state + 0x611) |= 2;
    *(s16 *)obj = (s16)((s8)*(s8 *)(setup + 0x18) << 8);
    *(u8 *)(state + 0x65b) = *(u8 *)(setup + 0x19);
    if (*(u8 *)(state + 0x65b) == 1) {
        if (GameBit_Get(0x7fc) == 0 &&
            (u8)(*(int (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) != 2) {
            *(u8 *)(state + 0x658) = 0;
        } else {
            *(u8 *)(state + 0x658) = 2;
        }
    } else {
        *(u8 *)(state + 0x658) = 2;
    }
    *(s8 *)(state + 0x65c) = -1;
}
#pragma scheduling on
#pragma peephole on

extern int Obj_IsObjectAlive(int obj);
extern int Obj_GetPlayerObject(void);
extern f32 lbl_803E6C24;
extern f32 lbl_803E6C28;
extern f32 lbl_803E6C2C;
extern f32 lbl_803E6C30;
extern f32 lbl_803E6C34;

#pragma peephole off
#pragma scheduling off
void barrelgener_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int player = Obj_GetPlayerObject();

    if ((u32)GameBit_Get(0xadb) == 0) {
        if (Vec_distance(obj + 24, player + 24) < lbl_803E6C24) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
            GameBit_Set(0xadb, 1);
        }
    }
    if (fn_80080150(state + 8) != 0) {
        if (*(f32 *)(state + 8) <= lbl_803E6C28 && *(u8 *)(state + 4) == 0) {
            *(u8 *)(state + 4) = 1;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6C2C, 0);
            Sfx_PlayFromObject(obj, 808);
            *(u8 *)(state + 0xc) = 0;
        }
        if (timerCountDown((void *)(state + 8)) != 0) {
            if (Obj_IsObjectAlive(*(int *)(state + 0)) != 0) {
                int o = *(int *)(state + 0);
                f32 c2c;
                *(f32 *)(o + 12) = *(f32 *)(obj + 12);
                *(f32 *)(o + 16) = *(f32 *)(obj + 16);
                *(f32 *)(o + 20) = *(f32 *)(obj + 20);
                *(f32 *)(o + 128) = *(f32 *)(o + 12);
                *(f32 *)(o + 132) = *(f32 *)(o + 16);
                *(f32 *)(o + 136) = *(f32 *)(o + 20);
                *(f32 *)(o + 24) = *(f32 *)(o + 12);
                *(f32 *)(o + 28) = *(f32 *)(o + 16);
                *(f32 *)(o + 32) = *(f32 *)(o + 20);
                c2c = lbl_803E6C2C;
                *(f32 *)(o + 44) = c2c;
                *(f32 *)(o + 40) = c2c;
                *(f32 *)(o + 36) = c2c;
                ObjGroup_AddObject(o, 25);
                *(int *)(state + 0) = 0;
            }
        }
    }
    if (*(u8 *)(state + 4) != 0) {
        if (*(f32 *)(obj + 0x98) > lbl_803E6C30) {
            if (*(u8 *)(state + 0xc) == 0) {
                Sfx_PlayFromObject(obj, 809);
                *(u8 *)(state + 0xc) = 1;
            }
        }
        *(u8 *)(state + 4) = !ObjAnim_AdvanceCurrentMove(lbl_803E6C34, timeDelta, obj, 0);
    }
}
#pragma scheduling on
#pragma peephole on

extern int *gModgfxInterface;
extern void Resource_Release(int handle);
extern int Resource_Acquire(int id, int p2);
extern int lbl_803DDD80;

#pragma peephole off
#pragma scheduling off
void dll_299_free(int obj)
{
    (*(void (**)(int))(*gExpgfxInterface + 0x18))(obj);
    (*(void (**)(int))(*gModgfxInterface + 0x14))(obj);
    Resource_Release(lbl_803DDD80);
    lbl_803DDD80 = 0;
}

void dll_299_update(int obj)
{
    if (randomGetRange(0, 2) == 0) {
        (*(void (**)(int, int, int, int, int, int))(*(int *)lbl_803DDD80 + 0x4))(obj, 1, 0, 4, -1, 0);
    }
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x547, 0, 4, -1, 0);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x547, 0, 4, -1, 0);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x547, 0, 4, -1, 0);
}

void dll_299_init(int obj, int setup)
{
    *(s16 *)*(int *)(obj + 0xb8) = *(s16 *)(setup + 0x1e);
    *(u16 *)(obj + 0xb0) |= 0x2000;
    lbl_803DDD80 = Resource_Acquire(0xa6, 1);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x545, 0, 0x802, -1, 0);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x545, 0, 0x802, -1, 0);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x545, 0, 0x802, -1, 0);
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x546, 0, 0x802, -1, 0);
}
#pragma scheduling on
#pragma peephole on

extern void PSVECAdd(int p1, int p2, int p3);
typedef struct Vec12 { int a, b, c; } Vec12;

#pragma scheduling off
void fn_8022D460(int arwing, f32 val) { *(f32 *)(*(int *)(arwing + 0xb8) + 0x20) = val; }

int fn_8022D46C(int arwing) { return (s16) * (int *)(*(int *)(arwing + 0xb8) + 0x358); }

void fn_8022D47C(int arwing, int p2) { *(int *)(*(int *)(arwing + 0xb8) + 0x358) = (s16)p2; }

void fn_8022D48C(int out, int arwing)
{
    *(Vec12 *)out = *(Vec12 *)(*(int *)(arwing + 0xb8) + 0x48);
}

void fn_8022D4AC(int arwing, int in)
{
    int state = *(int *)(arwing + 0xb8);
    *(f32 *)(state + 0x48) = *(f32 *)(in + 0);
    *(f32 *)(state + 0x4c) = *(f32 *)(in + 4);
    *(f32 *)(state + 0x50) = *(f32 *)(in + 8);
}

void fn_8022D4CC(int arwing, int in)
{
    int v = *(int *)(arwing + 0xb8) + 0x48;
    PSVECAdd(v, in, v);
}

#pragma dont_inline on
void fn_8022D4F8(int arwing) { *(int *)(*(int *)(arwing + 0xb8) + 0x438) = 0; }
#pragma dont_inline reset

#pragma dont_inline on
int fn_8022D508(int arwing) { return *(u8 *)(*(int *)(arwing + 0xb8) + 0x471); }

int fn_8022D514(int arwing) { return *(u8 *)(*(int *)(arwing + 0xb8) + 0x470); }

void fn_8022D520(int arwing, u8 amount)
{
    int state = *(int *)(arwing + 0xb8);
    u16 v;
    *(u16 *)(state + 0x47c) = *(u16 *)(state + 0x47c) + amount;
    v = *(u16 *)(state + 0x47c);
    if (v > 0x270f) {
        v = 0x270f;
    }
    *(u16 *)(state + 0x47c) = v;
}

int fn_8022D550(int arwing)
{
    int state = *(int *)(arwing + 0xb8);
    if (*(u16 *)(state + 0x47c) > 0x270f) {
        *(u16 *)(state + 0x47c) = 0x270f;
    }
    return *(u16 *)(state + 0x47c);
}

int fn_8022D574(int arwing) { return *(u8 *)(*(int *)(arwing + 0xb8) + 0x44c); }

int fn_8022D580(int arwing) { return *(s8 *)(*(int *)(arwing + 0xb8) + 0x469); }

int fn_8022D590(int arwing) { return *(s8 *)(*(int *)(arwing + 0xb8) + 0x468); }

#pragma dont_inline on
int fn_8022D5A0(int arwing) { return (*(u8 *)(*(int *)(arwing + 0xb8) + 0x475))++; }

int fn_8022D5B4(int arwing) { return (*(u8 *)(*(int *)(arwing + 0xb8) + 0x474))++; }

int fn_8022D5C8(int arwing) { return (*(u8 *)(*(int *)(arwing + 0xb8) + 0x473))++; }

int fn_8022D5DC(int arwing) { return (*(u8 *)(*(int *)(arwing + 0xb8) + 0x472))++; }
#pragma dont_inline reset

int fn_8022D5F0(int arwing)
{
    int state = *(int *)(arwing + 0xb8);
    if (*(u8 *)(state + 0x470) == 9) {
        *(u16 *)(state + 0x47c) = *(u16 *)(state + 0x47c) + 0x64;
        if (*(u16 *)(state + 0x47c) > 0x270f) {
            *(u16 *)(state + 0x47c) = 0x270f;
        }
    }
    return (*(u8 *)(state + 0x470))++;
}

#pragma peephole off
void fn_8022D634(int arwing, int p2)
{
    int state = *(int *)(arwing + 0xb8);
    *(s8 *)(state + 0x469) = *(u8 *)(state + 0x469) + p2;
}
#pragma peephole on

void fn_8022D64C(int arwing, int p2)
{
    int state = *(int *)(arwing + 0xb8);
    s8 v;

    *(s8 *)(state + 0x468) = *(u8 *)(state + 0x468) + p2;
    v = *(s8 *)(state + 0x468);
    if (v < 0) {
        v = 0;
    } else if (v > *(s8 *)(state + 0x469)) {
        v = *(s8 *)(state + 0x469);
    }
    *(s8 *)(state + 0x468) = v;
    if (*(s8 *)(state + 0x468) > 3) {
        Sfx_StopObjectChannel(arwing, 4);
    }
}
#pragma dont_inline reset

extern int gameBitIncrement(int id);
extern f32 lbl_803E70A0;
extern f32 lbl_803E70A4;
extern f32 lbl_803E70A8;
extern f32 lbl_803E70AC;

#pragma scheduling off
void fn_8022FA00(int obj, int state) {
    u8 mode = *(u8 *)(state + 1);
    u16 raw = *(u16 *)(state + 2);
    if (mode == 1 || mode == 3) {
        f32 cur, lim, edge;
        *(f32 *)(obj + 0xc) = *(f32 *)(state + 4) * timeDelta + *(f32 *)(obj + 0xc);
        cur = *(f32 *)(obj + 0xc);
        lim = *(f32 *)(state + 8);
        edge = lim + (f32)(u32)raw;
        if (cur > edge) {
            *(f32 *)(obj + 0xc) = edge - (cur - edge);
            *(f32 *)(state + 4) = -*(f32 *)(state + 4);
        } else {
            edge = lim - (f32)(u32)raw;
            if (cur < edge) {
                *(f32 *)(obj + 0xc) = edge - (cur - edge);
                *(f32 *)(state + 4) = -*(f32 *)(state + 4);
            }
        }
    } else if (mode == 4 || mode == 5) {
        f32 cur, lim, edge;
        *(f32 *)(obj + 0x10) = *(f32 *)(state + 4) * timeDelta + *(f32 *)(obj + 0x10);
        cur = *(f32 *)(obj + 0x10);
        lim = *(f32 *)(state + 0xc);
        edge = lim + (f32)(u32)raw;
        if (cur > edge) {
            *(f32 *)(obj + 0x10) = edge - (cur - edge);
            *(f32 *)(state + 4) = -*(f32 *)(state + 4);
        } else {
            edge = lim - (f32)(u32)raw;
            if (cur < edge) {
                *(f32 *)(obj + 0x10) = edge - (cur - edge);
                *(f32 *)(state + 4) = -*(f32 *)(state + 4);
            }
        }
    }
}
#pragma scheduling on

#pragma scheduling off
void fn_8022FB5C(int obj, int state, int arwing) {
    int setup = *(int *)(obj + 0x4c);
    u8 mode = *(u8 *)(state + 0);
    if (mode == 0) {
        Sfx_PlayFromObject(arwing, 0x2a9);
        if (*(s16 *)(arwing + 0x46) == 0x601) {
            fn_8022D64C(arwing, 1);
            fn_8022D520(arwing, 0xa);
        }
    } else if (mode == 1) {
        Sfx_PlayFromObject(arwing, 0x2a9);
        if (*(s16 *)(arwing + 0x46) == 0x601) {
            fn_8022D634(arwing, 1);
            fn_8022D64C(arwing, fn_8022D580(arwing));
        }
    } else if (mode == 3 || mode == 4) {
        Sfx_PlayFromObject(arwing, 0x2a9);
        gameBitIncrement(*(s16 *)(setup + 0x1e));
    } else {
        Sfx_PlayFromObject(arwing, 0x2ab);
        if (*(s16 *)(arwing + 0x46) == 0x601) {
            int seg;
            fn_8022D5F0(arwing);
            fn_8022D64C(arwing, 1);
            fn_8022D520(arwing, 0x14);
            seg = fn_8022D508(arwing);
            if (fn_8022D514(arwing) == seg) {
                if (((RingFlags *)(state + 0x14))->bit20)
                    gameTextFn_80125ba4(7);
            } else {
                if (((RingFlags *)(state + 0x14))->bit20)
                    gameTextFn_80125ba4(9);
            }
        }
    }
    *(u8 *)(state + 0x15) = 2;
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
int fn_8022FCD8(int obj, int state, int arwing) {
    RingFlags *f = (RingFlags *)(state + 0x14);
    if (f->bit10) {
        f32 dx = *(f32 *)(obj + 0xc) - *(f32 *)(arwing + 0xc);
        f32 dy = *(f32 *)(obj + 0x10) - *(f32 *)(arwing + 0x10);
        f32 dz;
        if (dy < lbl_803E70A0)
            dy = -dy;
        dz = *(f32 *)(obj + 0x14) - *(f32 *)(arwing + 0x14);
        if (dy <= lbl_803E70A4) {
            if (dx * dx + dz * dz < lbl_803E70A8)
                return 1;
        }
    } else {
        f32 oz = *(f32 *)(obj + 0x14);
        f32 a = oz - *(f32 *)(arwing + 0x14);
        f32 b = oz - *(f32 *)(arwing + 0x88);
        if (a <= lbl_803E70A0 && b >= lbl_803E70A0) {
            f32 dx = *(f32 *)(obj + 0xc) - *(f32 *)(arwing + 0xc);
            f32 dy = *(f32 *)(obj + 0x10) - *(f32 *)(arwing + 0x10);
            if (sqrtf(dx * dx + dy * dy) < lbl_803E70AC)
                return 1;
            if (*(u8 *)(state + 0) == 2 && f->bit20)
                gameTextFn_80125ba4(0xa);
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_803E6ECC;
extern void fn_8022B764(int p, int q, int idx);

#pragma scheduling off
#pragma dont_inline on
void fn_8022AE1C(int obj, int bounds) {
    f32 cx = *(f32 *)(bounds + 0x14);
    f32 hx = cx + *(f32 *)(bounds + 0x20);
    f32 lx = cx - *(f32 *)(bounds + 0x20);
    f32 cy = *(f32 *)(bounds + 0x18);
    f32 hy = cy + *(f32 *)(bounds + 0x28);
    f32 ly = cy - *(f32 *)(bounds + 0x24);
    if (*(f32 *)(obj + 0xc) > hx) {
        *(f32 *)(obj + 0xc) = hx;
        *(f32 *)(bounds + 0x48) = lbl_803E6ECC;
    } else if (*(f32 *)(obj + 0xc) < lx) {
        *(f32 *)(obj + 0xc) = lx;
        *(f32 *)(bounds + 0x48) = lbl_803E6ECC;
    }
    if (*(f32 *)(obj + 0x10) > hy) {
        *(f32 *)(obj + 0x10) = hy;
        *(f32 *)(bounds + 0x4c) = lbl_803E6ECC;
    } else if (*(f32 *)(obj + 0x10) < ly) {
        *(f32 *)(obj + 0x10) = ly;
        *(f32 *)(bounds + 0x4c) = lbl_803E6ECC;
    }
    *(f32 *)(bounds + 0x2c) = *(f32 *)(obj + 0xc) - *(f32 *)(bounds + 0x14);
    *(f32 *)(bounds + 0x30) = *(f32 *)(obj + 0x10) - *(f32 *)(bounds + 0x18);
    *(f32 *)(bounds + 0x34) = lbl_803E6ECC;
}
#pragma dont_inline reset

extern f32 lbl_803E6ED0;
extern f32 lbl_803E6EFC;
extern f32 lbl_803E6F00;
extern f32 fn_80293E80(f32 x);
extern void fn_8022AB68(int obj, int p);
extern void PSVECScale(void *dst, void *src, f32 scale);
extern void PSVECSubtract(void *a, void *b, void *ab);

void fn_8022AECC(int obj, int p)
{
    f32 v[3];
    f32 cz;
    int diff;
    int iv;

    if (*(s8 *)(p + 0xac) == 0x26) {
        *(f32 *)(p + 0x44) = lbl_803E6ECC;
    }
    PSVECSubtract((void *)(p + 0x3c), (void *)(p + 0x48), v);
    v[0] = v[0] * *(f32 *)(p + 0x60);
    v[1] = v[1] * *(f32 *)(p + 0x64);
    v[2] = v[2] * *(f32 *)(p + 0x68);
    if (v[2] < *(f32 *)(p + 0x84)) {
        cz = *(f32 *)(p + 0x84);
    } else if (v[2] > *(f32 *)(p + 0x78)) {
        cz = *(f32 *)(p + 0x78);
    } else {
        cz = v[2];
    }
    v[2] = cz;
    PSVECScale(v, v, timeDelta);
    PSVECAdd((int)(p + 0x48), (int)v, (int)(p + 0x48));
    objMove(obj, *(f32 *)(p + 0x48) * timeDelta, *(f32 *)(p + 0x4c) * timeDelta,
            *(f32 *)(p + 0x50) * timeDelta);

    diff = *(int *)(p + 0x340) - (u16) * (int *)(p + 0x344);
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)(f32)((int)((f32)diff * *(f32 *)(p + 0x34c)) - *(int *)(p + 0x350));
    if (iv < -0x32) iv = -0x32;
    else if (iv > 0x32) iv = 0x32;
    *(int *)(p + 0x350) = (int)((f32)iv * timeDelta + (f32) * (int *)(p + 0x350));
    *(int *)(p + 0x344) =
        (int)((f32) * (int *)(p + 0x350) * timeDelta + (f32) * (int *)(p + 0x344));

    diff = *(int *)(p + 0x354) - (u16) * (int *)(p + 0x358);
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)(f32)((int)((f32)diff * *(f32 *)(p + 0x360)) - *(int *)(p + 0x364));
    if (iv < -0x32) iv = -0x32;
    else if (iv > 0x32) iv = 0x32;
    *(int *)(p + 0x364) = (int)((f32)iv * timeDelta + (f32) * (int *)(p + 0x364));
    *(int *)(p + 0x358) =
        (int)((f32) * (int *)(p + 0x364) * timeDelta + (f32) * (int *)(p + 0x358));

    diff = *(int *)(p + 0x368) - (u16) * (int *)(p + 0x36c);
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)((f32)(int)((f32)diff * *(f32 *)(p + 0x374)) - *(f32 *)(p + 0x378));
    if (iv < -0x64) iv = -0x64;
    else if (iv > 0x64) iv = 0x64;
    *(f32 *)(p + 0x378) = (f32)iv * timeDelta + *(f32 *)(p + 0x378);
    *(int *)(p + 0x36c) =
        (int)(*(f32 *)(p + 0x378) * timeDelta + (f32) * (int *)(p + 0x36c));

    if (*(u8 *)(p + 0x478) == 0) {
        diff = *(int *)(p + 0x37c) - (u16) * (int *)(p + 0x380);
        if (diff > 0x8000) diff -= 0xffff;
        if (diff < -0x8000) diff += 0xffff;
        *(int *)(p + 0x380) =
            (int)(timeDelta * ((f32)diff * *(f32 *)(p + 0x388)) + (f32) * (int *)(p + 0x380));
        if ((f32) * (int *)(p + 0x380) > *(f32 *)(p + 0x394) ||
            (f32) * (int *)(p + 0x380) < -*(f32 *)(p + 0x394)) {
            *(f32 *)(p + 0x38c) = *(f32 *)(p + 0x38c) - *(f32 *)(p + 0x390) * timeDelta;
        } else {
            *(f32 *)(p + 0x38c) = *(f32 *)(p + 0x390) * timeDelta + *(f32 *)(p + 0x38c);
        }
    } else {
        *(f32 *)(p + 0x38c) = *(f32 *)(p + 0x38c) - *(f32 *)(p + 0x390) * timeDelta;
    }
    if (*(f32 *)(p + 0x38c) < lbl_803E6ECC) {
        *(f32 *)(p + 0x38c) = lbl_803E6ECC;
    } else if (*(f32 *)(p + 0x38c) > lbl_803E6ED0) {
        *(f32 *)(p + 0x38c) = lbl_803E6ED0;
    }

    *(s16 *)(obj + 0) = (s16) * (int *)(p + 0x344);
    *(s16 *)(obj + 2) = (s16) * (int *)(p + 0x358);
    if (*(u8 *)(p + 0x478) == 1) {
        fn_8022AB68(obj, p);
    } else {
        *(s16 *)(obj + 4) = (s16)(int)((f32) * (int *)(p + 0x36c) * *(f32 *)(p + 0x38c) +
                                        (f32) * (int *)(p + 0x380));
        if (*(s16 *)(obj + 4) < -0x4000) {
            *(s16 *)(obj + 4) = -0x4000;
        } else if (*(s16 *)(obj + 4) > 0x4000) {
            *(s16 *)(obj + 4) = 0x4000;
        }
    }

    if (sqrtf(*(f32 *)(p + 0x48) * *(f32 *)(p + 0x48) +
              *(f32 *)(p + 0x4c) * *(f32 *)(p + 0x4c)) < *(f32 *)(p + 0x3b4) &&
        *(u8 *)(p + 0x478) == 0) {
        *(f32 *)(p + 0x3dc) = *(f32 *)(p + 0x3e0) * timeDelta + *(f32 *)(p + 0x3dc);
    } else {
        *(f32 *)(p + 0x3dc) = *(f32 *)(p + 0x3dc) - *(f32 *)(p + 0x3e0) * timeDelta;
    }
    if (*(f32 *)(p + 0x3dc) < lbl_803E6ECC) {
        *(f32 *)(p + 0x3dc) = lbl_803E6ECC;
    } else if (*(f32 *)(p + 0x3dc) > lbl_803E6ED0) {
        *(f32 *)(p + 0x3dc) = lbl_803E6ED0;
    }

    *(s16 *)(obj + 4) = (s16)(int)(*(f32 *)(p + 0x3dc) *
                                       (*(f32 *)(p + 0x3bc) *
                                        fn_80293E80(lbl_803E6EFC * (f32)(u32) * (u16 *)(p + 0x3c0) /
                                                    lbl_803E6F00)) +
                                   (f32) * (s16 *)(obj + 4));
    *(f32 *)(obj + 0xc) =
        *(f32 *)(p + 0x3dc) *
            (*(f32 *)(p + 0x3c8) *
             fn_80293E80(lbl_803E6EFC * (f32)(u32) * (u16 *)(p + 0x3cc) / lbl_803E6F00)) +
        *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x10) =
        *(f32 *)(p + 0x3dc) *
            (*(f32 *)(p + 0x3d4) *
             fn_80293E80(lbl_803E6EFC * (f32)(u32) * (u16 *)(p + 0x3d8) / lbl_803E6F00)) +
        *(f32 *)(obj + 0x10);
    *(u16 *)(p + 0x3c0) =
        (u16)(int)(*(f32 *)(p + 0x3b8) * timeDelta + (f32)(u32) * (u16 *)(p + 0x3c0));
    *(u16 *)(p + 0x3cc) =
        (u16)(int)(*(f32 *)(p + 0x3c4) * timeDelta + (f32)(u32) * (u16 *)(p + 0x3cc));
    *(u16 *)(p + 0x3d8) =
        (u16)(int)(*(f32 *)(p + 0x3d0) * timeDelta + (f32)(u32) * (u16 *)(p + 0x3d8));
    fn_8022AE1C(obj, p);
}

void fn_8022B8A0(int p, int q) {
    if (*(void **)(q + 0x438) != NULL)
        return;
    {
        f32 t = *(f32 *)(q + 0x440);
        if (t > lbl_803E6ECC) {
            *(f32 *)(q + 0x440) = t - timeDelta;
            if (*(f32 *)(q + 0x440) >= lbl_803E6ECC)
                return;
            *(f32 *)(q + 0x440) = lbl_803E6ECC;
        }
    }
    if (*(u16 *)(q + 0x3f4) & 0x200) {
        if ((s8) * (u8 *)(q + 0x43c) == 1) {
            fn_8022B764(p, q, 0);
            fn_8022B764(p, q, 1);
        } else {
            fn_8022B764(p, q, *(u8 *)(q + 0x43d));
            *(u8 *)(q + 0x43d) = (*(u8 *)(q + 0x43d) ^ 1) & 0xff;
        }
        *(f32 *)(q + 0x440) = (f32)(u32) * (u16 *)(q + 0x444);
    }
}
#pragma scheduling reset

extern f32 lbl_803E6F08;
extern f32 lbl_803E6F0C;
extern f32 lbl_803E6F10;
extern f32 lbl_803E6F14;
extern f32 lbl_803E6F18;
extern f32 lbl_803E6F1C;
extern f32 lbl_803E6F20;

#pragma peephole off
#pragma scheduling off
void fn_8022BCD0(int p, int q) {
    u8 flag;
    struct {
        u8 pad[6];
        s16 type;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } emit;
    flag = 0;
    if ((s8) * (u8 *)(q + 0x468) <= 4) {
        if ((*(u8 *)(q + 0x476))++ % 2 != 0) {
            emit.a = lbl_803E6F08;
            emit.b = lbl_803E6F0C;
            emit.c = lbl_803E6F10;
            emit.d = lbl_803E6F14;
            if ((s8) * (u8 *)(q + 0x468) <= 2)
                emit.type = 0x61a8;
            else
                emit.type = -0x63c0;
            (*(void (**)(int, int, void *, int, int, u8 *))(*gPartfxInterface + 0x8))(
                p, 0x7d0, &emit.pad, 4, -1, &flag);
        }
    }
    if ((s8) * (u8 *)(q + 0x468) <= 2) {
        emit.a = lbl_803E6F18;
        emit.type = 0xc0a;
        emit.b = lbl_803E6ECC;
        emit.c = lbl_803E6F1C;
        emit.d = lbl_803E6F20;
        (*(void (**)(int, int, void *, int, int, u8 *))(*gPartfxInterface + 0x8))(
            p, 0x7d1, &emit.pad, 4, -1, &flag);
    }
}
#pragma scheduling reset
#pragma peephole reset

extern void warpToMap(int map, int p2);

#pragma dont_inline on
#pragma scheduling off
void fn_8022C680(int obj) {
    switch ((s8) * (u8 *)(obj + 0xac)) {
    case 0x3a:
        if (GameBit_Get(0xc85) != 0) {
            GameBit_Set(0x405, 0);
            (*(void (**)(int, int))(*gMapEventInterface + 0x44))(0xb, 5);
            (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xb, 0xa, 1);
            (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xb, 0xb, 1);
            warpToMap(0x22, 0);
        } else {
            warpToMap(0x6c, 0);
        }
        break;
    case 0x3b:
        warpToMap(0x77, 0);
        break;
    case 0x3d:
        warpToMap(0x78, 0);
        break;
    case 0x3c:
        warpToMap(0x63, 0);
        break;
    case 0x3e:
        warpToMap(0x79, 0);
        break;
    }
}
#pragma scheduling reset
#pragma dont_inline reset

extern void lightSetFieldBC_8001db14(void *light, int v);
extern f32 lbl_803E700C;
extern f32 lbl_803E7010;
extern f32 lbl_803E7014;
extern f32 lbl_803E7018;

#pragma dont_inline on
#pragma peephole off
#pragma scheduling off
void arwprojectile_createLinkedEffect(int obj, u8 enable) {
    int state = *(int *)(obj + 0xb8);
    if (enable == 0)
        return;
    if (*(void **)(state + 0x14) != NULL)
        return;
    *(void **)(state + 0x14) = objCreateLight(obj, 1);
    if (*(void **)(state + 0x14) == NULL)
        return;
    modelLightStruct_setField50(*(void **)(state + 0x14), 2);
    lightVecFn_8001dd88(*(void **)(state + 0x14), lbl_803E7008, lbl_803E7008, lbl_803E7008);
    lightSetFieldBC_8001db14(*(void **)(state + 0x14), 1);
    if (*(s16 *)(obj + 0x46) == 0x6ae) {
        modelLightStruct_setColorsA8AC(*(void **)(state + 0x14), 0xff, 0x14, 0x50, 0);
    } else if ((s8) * (u8 *)(obj + 0xad) == 0) {
        modelLightStruct_setColorsA8AC(*(void **)(state + 0x14), 0x3c, 0xff, 0x5a, 0);
    } else {
        modelLightStruct_setColorsA8AC(*(void **)(state + 0x14), 0x3c, 0x5a, 0xff, 0);
    }
    if (*(s16 *)(obj + 0x46) == 0x655) {
        lightDistAttenFn_8001dc38(*(void **)(state + 0x14), lbl_803E700C, lbl_803E7010);
    } else {
        lightDistAttenFn_8001dc38(*(void **)(state + 0x14), lbl_803E7014, lbl_803E7018);
    }
    lightSetField2FB(*(void **)(state + 0x14), 1);
}
#pragma scheduling reset
#pragma peephole reset
#pragma dont_inline reset

extern f32 lbl_803E721C;
extern f32 lbl_803E7220;

#pragma scheduling off
void arwblocker_update(int obj) {
    int state = *(int *)(obj + 0xb8);
    int arwing = getArwing();
    if (arwing == 0)
        arwing = Obj_GetPlayerObject();
    if (Vec_distance(obj + 0x18, arwing + 0x18) < lbl_803E721C) {
        int a = (int)(lbl_803E7220 * timeDelta + (f32)(u32) * (u8 *)(obj + 0x36));
        if (a > 0xff)
            a = 0xff;
        *(u8 *)(obj + 0x36) = a;
        *(s16 *)(obj + 6) &= ~0x4000;
        ObjHits_EnableObject(obj);
        if (*(int *)(obj + 0xf4) == 0) {
            switch (*(u8 *)(state + 0)) {
            case 1:
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                break;
            case 0:
            default:
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                break;
            }
            *(int *)(obj + 0xf4) = 1;
        }
    }
}
#pragma scheduling reset

extern void fn_8001DACC(void *light, u8 *a, u8 *b, u8 *c, u8 *d);
extern void fn_8001D71C(void *light, u8 r, u8 g, u8 b, int e);
extern f32 lbl_803E71D8;
extern f32 lbl_803E71DC;
extern f32 lbl_803E71E0;
extern f32 lbl_803E71E8;
extern f32 lbl_803E71EC;
extern f32 lbl_803E71F0;
extern f32 lbl_803E71F4;
extern f32 lbl_803E71F8;
extern f32 lbl_803E71FC;
extern f32 lbl_803E7200;

#pragma peephole off
#pragma scheduling off
void arwproximit_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(u8 *)(state + 0x15) == 1) {
        int arwing = getArwing();
        if (arwing == 0)
            arwing = Obj_GetPlayerObject();
        if (Vec_distance(obj + 0x18, arwing + 0x18) < lbl_803E71E8) {
            gameTextFn_80125ba4(0xb);
            *(u8 *)(state + 0x15) = 0;
        }
    }

    switch (*(u8 *)(state + 0x14)) {
    case 0: {
        int arwing = getArwing();
        if (arwing == 0)
            arwing = Obj_GetPlayerObject();
        if (Vec_distance(obj + 0x18, arwing + 0x18) < lbl_803E71EC) {
            *(void **)(state + 4) = objCreateLight(obj, 1);
            if (*(void **)(state + 4) != NULL) {
                modelLightStruct_setField50(*(void **)(state + 4), 2);
                lightVecFn_8001dd88(*(void **)(state + 4), lbl_803E71D8, lbl_803E71D8,
                                    lbl_803E71F0);
                modelLightStruct_setColorsA8AC(*(void **)(state + 4), 0, 0xff, 0, 0);
                lightSetFieldB0(*(void **)(state + 4), 0, 0, 0, 0);
                lightDistAttenFn_8001dc38(*(void **)(state + 4), lbl_803E71F0, lbl_803E71F4);
                fn_8001D730(*(void **)(state + 4), 0, 0, 0xff, 0, 0x64, lbl_803E71F8);
                fn_8001D714(*(void **)(state + 4), lbl_803E71F0);
            }
            ObjHits_EnableObject(obj);
            ObjHits_MarkObjectPositionDirty(obj);
            *(s16 *)(obj + 6) &= ~0x4000;
            *(u8 *)(state + 0x14) = 1;
        }
        return;
    }
    case 1:
    default: {
        int arwing;
        int a = (int)(lbl_803E71FC * timeDelta + (f32)(u32)*(u8 *)(obj + 0x36));
        if (a > 0xff)
            a = 0xff;
        *(u8 *)(obj + 0x36) = a;
        arwing = getArwing();
        if (arwing == 0)
            arwing = Obj_GetPlayerObject();
        if (Vec_distance(obj + 0x18, arwing + 0x18) < lbl_803E7200) {
            if (*(void **)(state + 4) != NULL) {
                modelLightStruct_setColorsA8AC(*(void **)(state + 4), 0xff, 0, 0, 0);
                fn_8001D71C(*(void **)(state + 4), 0xff, 0, 0, 0x64);
                lightFn_8001d620(*(void **)(state + 4), 2, 0xa);
            }
            s16toFloat((void *)(state + 0xc), 0x3c);
            *(u8 *)(state + 0x14) = 2;
            if (*(u8 *)(state + 0x15) == 2) {
                if (randomGetRange(0, 1) != 0)
                    gameTextFn_80125ba4(0xf);
                else
                    gameTextFn_80125ba4(0xc);
            }
        }
        break;
    }
    case 2: {
        u8 b0, b1, b2, b3;
        *(u8 *)(obj + 0x36) = 0xff;
        if (*(void **)(state + 4) != NULL) {
            fn_8001DACC(*(void **)(state + 4), &b0, &b1, &b2, &b3);
            fn_8001D71C(*(void **)(state + 4), b0, b1, b2, 0x64);
        }
        if (timerCountDown((void *)(state + 0xc)) != 0 ||
            (*(void **)(*(int *)(obj + 0x54) + 0x50) != NULL &&
             *(void **)(*(int *)(obj + 0x54) + 0x50) == (void *)getArwing())) {
            storeZeroToFloatParam((void *)(state + 0xc));
            s16toFloat((void *)(state + 0x10), 0x14);
            if (*(void **)(state + 4) != NULL)
                lightFn_8001db6c(*(void **)(state + 4), 0, lbl_803E71D8);
            spawnExplosion(obj, lbl_803E71E0, 1, 0, 1, 1, 0, 0, 1);
            ObjHitbox_SetSphereRadius(obj, 0x12c);
            ObjHits_SetHitVolumeSlot(obj, 5, 1, 0);
            *(s16 *)(obj + 6) |= 0x4000;
            ObjHits_MarkObjectPositionDirty(obj);
            *(u8 *)(state + 0x14) = 3;
        }
        break;
    }
    case 3:
        if (timerCountDown((void *)(state + 0x10)) != 0) {
            ObjHits_DisableObject(obj);
            *(u8 *)(state + 0x14) = 4;
        }
        break;
    case 4:
        if (*(void **)(state + 4) != NULL) {
            ModelLightStruct_free(*(void **)(state + 4));
            *(void **)(state + 4) = NULL;
        }
        return;
    }

    if (*(u8 *)(state + 0x14) == 1 || *(u8 *)(state + 0x14) == 2) {
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
            fn_8022D520(getArwing(), 0xa);
            if (*(u8 *)(state + 0x15) == 3)
                gameTextFn_80125ba4(0xe);
            if (*(void **)(state + 4) != NULL)
                lightFn_8001db6c(*(void **)(state + 4), 0, lbl_803E71D8);
            spawnExplosion(obj, lbl_803E71DC, 1, 0, 0, 0, 0, 0, 1);
            ObjHits_DisableObject(obj);
            *(s16 *)(obj + 6) |= 0x4000;
            ObjHits_MarkObjectPositionDirty(obj);
            *(u8 *)(state + 0x14) = 4;
        }
        *(s16 *)(obj + 4) =
            timeDelta * (f32)*(s16 *)(state + 0) + (f32)*(s16 *)(obj + 4);
        *(s16 *)(obj + 2) =
            timeDelta * (f32)*(s16 *)(state + 0) + (f32)*(s16 *)(obj + 2);
    }

    if (*(void **)(state + 4) != NULL && fn_8001DB64(*(void **)(state + 4)) != 0)
        lightFn_8001d6b0(*(void **)(state + 4));
}
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_803E71A8;

#pragma peephole off
#pragma scheduling off
void arwsquadron_spawnProjectile(int obj, int pathIdx, int angle, u8 flag) {
    f32 pz, py, px;
    int proj;
    if (Obj_IsLoadingLocked() == 0)
        return;
    ObjPath_GetPointWorldPosition(obj, pathIdx, &px, &py, &pz, 0);
    {
        int setup = Obj_AllocObjectSetup(0x20, 0x6ae);
        *(f32 *)(setup + 8) = px;
        *(f32 *)(setup + 0xc) = py;
        *(f32 *)(setup + 0x10) = pz;
        *(u8 *)(setup + 0x1a) = (*(s16 *)obj + 0x10000 + angle - 0x8000) >> 8;
        *(u8 *)(setup + 0x19) = -*(s16 *)(obj + 2) >> 8;
        *(u8 *)(setup + 0x18) = 0;
        *(u8 *)(setup + 4) = 1;
        *(u8 *)(setup + 5) = 1;
    }
    proj = loadObjectAtObject(obj);
    if (proj == 0)
        return;
    if (flag != 0)
        arwprojectile_createLinkedEffect(proj, 1);
    arwprojectile_setLifetime(proj, 0x4b);
    arwprojectile_placeForward(proj, lbl_803E71A8);
    Sfx_PlayFromObjectLimited(proj, 0x2b5, 4);
}
#pragma scheduling reset
#pragma peephole reset

extern void *Camera_GetInverseViewMatrix(void);
extern f32 lbl_803E7104;
extern f32 lbl_803E7108;
extern f32 lbl_803E710C;

#pragma peephole off
#pragma scheduling off
void arwspeedstr_update(int obj) {
    int state = *(int *)(obj + 0xb8);
    if (*(u8 *)(state + 0x18) == 0) {
        f32 local[3];
        local[0] = (f32)(int)randomGetRange((int)-*(f32 *)(state + 0xc), (int)*(f32 *)(state + 0xc));
        local[1] =
            (f32)(int)randomGetRange((int)-*(f32 *)(state + 0x10), (int)*(f32 *)(state + 0x10));
        local[2] = *(f32 *)(state + 0x14);
        PSMTXMultVec(Camera_GetInverseViewMatrix(), &local[0], (f32 *)(obj + 0xc));
        *(f32 *)(obj + 0xc) += playerMapOffsetX;
        *(f32 *)(obj + 0x14) += playerMapOffsetZ;
        *(u8 *)(state + 0x18) = (*(u8 *)(state + 0x18) | 1) & 0xff;
        *(f32 *)(state + 8) = lbl_803E7104;
    }
    {
        f32 t = *(f32 *)(state + 4);
        if (t > lbl_803E7104) {
            *(f32 *)(state + 4) = t - timeDelta;
            if (*(f32 *)(state + 4) <= lbl_803E7104) {
                *(f32 *)(state + 4) = lbl_803E7104;
                Obj_FreeObject(obj);
            } else {
                objMove(obj, lbl_803E7104, lbl_803E7104, *(f32 *)(state + 0) * timeDelta);
                *(f32 *)(state + 8) = lbl_803E7108 * timeDelta + *(f32 *)(state + 8);
                if (*(f32 *)(state + 8) > lbl_803E710C)
                    *(f32 *)(state + 8) = lbl_803E710C;
                *(u8 *)(obj + 0x36) = (int)*(f32 *)(state + 8);
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

extern void fn_8022A9C8(int obj, int state);
extern void arwarwing_spawnLaserShot(int obj, int state, int a, int b, int c);
extern f32 lbl_803E6F04;

#pragma peephole off
#pragma scheduling off
void arwarwing_updateWeaponFire(int obj, int state) {
    int fire;
    fn_8022A9C8(obj, state);
    {
        f32 t = *(f32 *)(state + 0x408);
        if (t > lbl_803E6ECC) {
            *(f32 *)(state + 0x408) = t - timeDelta;
            if (*(f32 *)(state + 0x408) >= lbl_803E6ECC)
                return;
            *(f32 *)(state + 0x408) = lbl_803E6ECC;
        }
    }
    fire = 0;
    if (*(u16 *)(state + 0x3f8) & 0x100) {
        *(f32 *)(state + 0x414) -= timeDelta;
        if (*(f32 *)(state + 0x414) <= lbl_803E6ECC)
            fire = 1;
    }
    if ((*(u16 *)(state + 0x3f4) & 0x100) == 0 && fire == 0)
        return;
    *(f32 *)(state + 0x414) = lbl_803E6F04;
    switch ((s8) * (u8 *)(state + 0x404)) {
    case 2:
        arwarwing_spawnLaserShot(obj, state, 0, 2, 1);
        arwarwing_spawnLaserShot(obj, state, 1, 2, 0);
        break;
    case 1:
        arwarwing_spawnLaserShot(obj, state, 0, 1, 1);
        arwarwing_spawnLaserShot(obj, state, 1, 1, 0);
        break;
    default:
        arwarwing_spawnLaserShot(obj, state, *(u8 *)(state + 0x405), 0, 1);
        *(u8 *)(state + 0x405) = (*(u8 *)(state + 0x405) ^ 1) & 0xff;
        break;
    }
    *(f32 *)(state + 0x408) = (f32)(u32) * (u16 *)(state + 0x40c);
}
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_803E6F34;
extern f32 lbl_803E6F24;
extern f32 lbl_803E6F28;
extern f32 lbl_803E6F6C;
extern f32 lbl_803E6EF8;
extern f32 lbl_803E6FFC;
extern f32 lbl_803E7000;
extern int *gScreenTransitionInterface;
extern int *gCameraInterface;
extern void unlockLevel(int a, int b, int c);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int idx, int p2);
extern void warpToMap(int map, int p2);
extern void spawnExplosion(int obj, f32 v, int a, int b, int c, int d, int e, int f, int g);
extern void fn_8022CDEC(int obj, int state);
extern void fn_8022A670(int obj, int state);
extern void fn_8022C30C(int obj, int state);
extern void fn_8022BE14(int obj, int state);
extern void fn_8022C0D0(int obj, int state);

#pragma scheduling off
void arwarwing_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    f32 camPos[2];
    s16 camRot[3];
    u8 mode;
    int p;
    f32 t;
    f32 throttle;

    if ((*(u8 *)(state + 0x477) & 1) == 0) {
        fn_8022CDEC(obj, state);
        return;
    }
    mode = *(u8 *)(state + 0x478);
    if (mode == 5) {
        t = *(f32 *)(state + 0x46c) - timeDelta;
        *(f32 *)(state + 0x46c) = t;
        if (t <= lbl_803E6ECC) {
            *(u8 *)(state + 0x478) = 6;
            (*(void (**)(int, int))(*gScreenTransitionInterface + 8))(0x14, 1);
            *(f32 *)(state + 0x46c) = lbl_803E6F34;
        }
        return;
    }
    if (mode == 6) {
        t = *(f32 *)(state + 0x46c) - timeDelta;
        *(f32 *)(state + 0x46c) = t;
        if (t <= lbl_803E6ECC) {
            if (*(s8 *)(obj + 0xac) == 0x26) {
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x26), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                warpToMap(0x32, 0);
            } else {
                warpToMap(0x60, 0);
            }
        }
        return;
    }
    if (mode == 4) {
        t = *(f32 *)(state + 0x46c) - timeDelta;
        *(f32 *)(state + 0x46c) = t;
        if (t <= lbl_803E6ECC) {
            *(u8 *)(state + 0x478) = 5;
            *(f32 *)(state + 0x46c) = lbl_803E6F24;
            *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) | 0x4000);
            spawnExplosion(obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
        }
        *(int *)(state + 0x36c) =
            (int)(lbl_803E6F6C * timeDelta + (f32) * (int *)(state + 0x36c));
        *(s16 *)(obj + 4) = (s16) * (int *)(state + 0x36c);
        *(f32 *)(state + 0x4c) = *(f32 *)(state + 0x4c) - lbl_803E6EF8 * timeDelta;
        objMove(obj, *(f32 *)(state + 0x48) * timeDelta, *(f32 *)(state + 0x4c) * timeDelta,
                *(f32 *)(state + 0x50) * timeDelta);
        fn_8022AE1C(obj, state);
        p = *(int *)(state + 0x418);
        *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) | 0x4000);
        p = *(int *)(state + 0x41c);
        *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) | 0x4000);
    } else {
        fn_8022A670(obj, state);
        if ((*(s16 *)(obj + 6) & 0x4000) != 0) {
            *(s16 *)(state + 0x3f8) = 0;
            *(s16 *)(state + 0x3f4) = 0;
            p = *(int *)(state + 0x418);
            *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) | 0x4000);
            p = *(int *)(state + 0x41c);
            *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) | 0x4000);
        } else {
            p = *(int *)(state + 0x418);
            *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) & ~0x4000);
            throttle = lbl_803E6FFC * timeDelta +
                       (f32)(u32) * (u8 *)(*(int *)(state + 0x418) + 0x36);
            if (throttle > lbl_803E7000) throttle = lbl_803E7000;
            *(u8 *)(*(int *)(state + 0x418) + 0x36) = (u8)(int)throttle;
            p = *(int *)(state + 0x41c);
            *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) & ~0x4000);
            *(u8 *)(*(int *)(state + 0x41c) + 0x36) = (u8)(int)throttle;
        }
        *(f32 *)(state + 0x3c) = -*(f32 *)(state + 0x3e4) * *(f32 *)(state + 0x54);
        *(f32 *)(state + 0x40) = -*(f32 *)(state + 0x3e8) * *(f32 *)(state + 0x58);
        *(f32 *)(state + 0x44) = *(f32 *)(state + 0x5c) * *(f32 *)(state + 0x6c);
        *(int *)(state + 0x340) =
            (int)(-*(f32 *)(state + 0x3e4) * *(f32 *)(state + 0x348));
        *(int *)(state + 0x354) = (int)(*(f32 *)(state + 0x3e8) * *(f32 *)(state + 0x35c));
        *(int *)(state + 0x368) = (int)(*(f32 *)(state + 0x3e4) * *(f32 *)(state + 0x370));
        *(int *)(state + 0x37c) =
            (int)(*(f32 *)(state + 0x384) *
                  (*(f32 *)(state + 0x3f0) + *(f32 *)(state + 0x3ec)));
        fn_8022AECC(obj, state);
        arwarwing_updateWeaponFire(obj, state);
        fn_8022B8A0(obj, state);

        *(s16 *)(*(int *)(state + 0x454) + 0) =
            (int)((f32)(-*(int *)(state + 0x36c)) * *(f32 *)(state + 0x464));
        *(s16 *)(*(int *)(state + 0x454) + 4) =
            (int)((f32) * (int *)(state + 0x36c) * *(f32 *)(state + 0x464));
        *(s16 *)(*(int *)(state + 0x458) + 0) =
            (int)((f32)(-*(int *)(state + 0x36c)) * *(f32 *)(state + 0x464));
        *(s16 *)(*(int *)(state + 0x458) + 4) =
            (int)((f32) * (int *)(state + 0x36c) * *(f32 *)(state + 0x464));
        p = (int)((f32) * (int *)(state + 0x36c) * *(f32 *)(state + 0x464));
        *(s16 *)(*(int *)(state + 0x45c) + 4) = p;
        *(s16 *)(*(int *)(state + 0x45c) + 0) = p;
        p = (int)((f32) * (int *)(state + 0x36c) * *(f32 *)(state + 0x464));
        *(s16 *)(*(int *)(state + 0x460) + 4) = p;
        *(s16 *)(*(int *)(state + 0x460) + 0) = p;

        *(s16 *)(*(int *)(state + 0x454) + 0) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x454) + 0));
        *(s16 *)(*(int *)(state + 0x454) + 4) =
            (int)((f32) * (int *)(state + 0x358) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x454) + 4));
        *(s16 *)(*(int *)(state + 0x458) + 0) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x458) + 0));
        *(s16 *)(*(int *)(state + 0x458) + 4) =
            (int)((f32) * (int *)(state + 0x358) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x458) + 4));
        *(s16 *)(*(int *)(state + 0x45c) + 0) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x45c) + 0));
        *(s16 *)(*(int *)(state + 0x45c) + 4) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x45c) + 4));
        *(s16 *)(*(int *)(state + 0x460) + 0) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x460) + 0));
        *(s16 *)(*(int *)(state + 0x460) + 4) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x460) + 4));
    }

    fn_8022C30C(obj, state);
    (*(void (**)(void *, int))(*gCameraInterface + 0x60))((void *)(state + 0x2c), 0xc);
    camRot[0] = *(s16 *)(obj + 0);
    camRot[1] = *(s16 *)(obj + 2);
    camRot[2] = (s16) * (int *)(state + 0x36c);
    (*(void (**)(void *, int))(*gCameraInterface + 0x60))(camRot, 6);
    camPos[0] = *(f32 *)(state + 0x5c);
    camPos[1] = *(f32 *)(state + 0x50);
    (*(void (**)(void *, int))(*gCameraInterface + 0x60))(camPos, 8);
    fn_8022BE14(obj, state);
    fn_8022C0D0(obj, state);
    fn_8022BCD0(obj, state);
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void arwarwing_spawnLaserShot(int obj, int state, int side, int level, int linkEffect) {
    f32 pz, py, px;
    int proj;
    if (Obj_IsLoadingLocked() == 0)
        return;
    if (side == 0) {
        ObjPath_GetPointWorldPosition(obj, 3, &px, &py, &pz, 0);
        arwarwinggu_setActiveVisible(*(int *)(state + 8), 1, level == 2);
    } else {
        ObjPath_GetPointWorldPosition(obj, 4, &px, &py, &pz, 0);
        arwarwinggu_setActiveVisible(*(int *)(state + 0xc), 1, level == 2);
    }
    {
        int setup = Obj_AllocObjectSetup(0x20, 0x604);
        *(f32 *)(setup + 8) = px;
        *(f32 *)(setup + 0xc) = py;
        *(f32 *)(setup + 0x10) = pz;
        *(u8 *)(setup + 0x1a) = *(s16 *)obj >> 8;
        *(u8 *)(setup + 0x19) = *(s16 *)(obj + 2) >> 8;
        *(u8 *)(setup + 0x18) = 0;
        *(u8 *)(setup + 4) = 1;
        *(u8 *)(setup + 5) = 1;
    }
    proj = loadObjectAtObject(obj);
    if (proj == 0)
        return;
    if (level == 0) {
        Sfx_PlayFromObject(proj, 0x2a1);
    } else if (level == 1) {
        Sfx_PlayFromObject(proj, 0x2a2);
    } else {
        Sfx_PlayFromObject(proj, 0x2b4);
        Obj_SetActiveModelIndex(proj, 1);
    }
    if (linkEffect != 0)
        arwprojectile_createLinkedEffect(proj, 1);
    arwprojectile_setLifetime(proj, *(u16 *)(state + 0x40e));
    arwprojectile_placeForward(proj, *(f32 *)(state + 0x410));
}
#pragma scheduling reset
#pragma peephole reset

#pragma dont_inline on
void fn_8022D6D0(int arwing)
{
    int state = *(int *)(arwing + 0xb8);
    if (*(u8 *)(state + 0x44c) < *(u8 *)(state + 0x44d)) {
        (*(u8 *)(state + 0x44c))++;
    }
}

void fn_8022D6F0(int arwing)
{
    int state = *(int *)(arwing + 0xb8);
    if ((s8) * (u8 *)(state + 0x404) < 2) {
        (*(u8 *)(state + 0x404))++;
    }
}
#pragma dont_inline reset

#pragma scheduling off
#pragma dont_inline on
int fn_8022D710(int arwing)
{
    int result = 0;
    u32 v = *(u8 *)(*(int *)(arwing + 0xb8) + 0x478);
    if (v == 5 || v == 6) {
        result = 1;
    }
    return result;
}
#pragma dont_inline reset
#pragma scheduling on

int fn_8022D738(int arwing) { return *(u8 *)(*(int *)(arwing + 0xb8) + 0x478) == 1; }

int fn_8022D750(int arwing) { return *(u8 *)(*(int *)(arwing + 0xb8) + 0x478) == 4; }
#pragma scheduling on

extern int ObjTrigger_IsSet(int obj);
extern void hudFn_8011f38c(int arg);
extern int fn_80296A9C(int player, int p2);
extern int fn_802966CC(void);
extern void staffSetGlow(int staff, int p2, int p3);

#pragma scheduling off
int fn_80238F50(int obj, int p2, int setup)
{
    if (*(u8 *)(setup + 0x8b) != 0) {
        (*(void (**)(int, int, int, int))(*gGameUIInterface + 0x38))(
            *(s16 *)(*(int *)(obj + 0x4c) + 0x1a), 0x14, 0x8c, 0);
    }
    return 0;
}

int fn_80239054(int p1, int p2, int setup)
{
    int i;
    for (i = 0; i < *(u8 *)(setup + 0x8b); i++) {
        switch (*(u8 *)(setup + 0x81 + i)) {
        case 0:
            hudFn_8011f38c(1);
            break;
        case 1:
            fn_80296A9C(Obj_GetPlayerObject(), 0x19);
            (*(void (**)(int, int, int, int))(*gGameUIInterface + 0x38))(0x468, 0x14, 0x8c, 0);
            break;
        case 2:
            hudFn_8011f38c(0);
            break;
        }
    }
    return 0;
}

int fn_802391C4(int p1, int p2, int setup)
{
    int staff;
    int i;

    if (Obj_GetPlayerObject() == 0) {
        return 0;
    }
    staff = fn_802966CC();
    if (staff == 0) {
        return 0;
    }
    for (i = 0; i < *(u8 *)(setup + 0x8b); i++) {
        switch (*(u8 *)(setup + 0x81 + i)) {
        case 1:
            staffSetGlow(staff, 5, 1);
            break;
        case 2:
            staffSetGlow(staff, 5, (u8)*(int *)(p1 + 0xf8));
            break;
        case 3:
            staffSetGlow(staff, 5, 0);
            break;
        }
    }
    return 0;
}

void mcupgrade_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        *(u8 *)(obj + 0xaf) |= 8;
    } else if (ObjTrigger_IsSet(obj) != 0) {
        GameBit_Set(*(s16 *)(setup + 0x1e), 1);
        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
    } else {
        objRenderFn_80041018(obj);
    }
}

void mcupgrade_init(int obj) { *(int *)(obj + 0xbc) = (int)fn_80238F50; }

void mcupgradema_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1a)) != 0) {
        *(u8 *)(obj + 0xaf) |= 8;
    } else if (ObjTrigger_IsSet(obj) != 0) {
        GameBit_Set(*(s16 *)(setup + 0x1a), 1);
        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
    } else {
        objRenderFn_80041018(obj);
    }
}

void mcupgradema_init(int obj) { *(int *)(obj + 0xbc) = (int)fn_80239054; }

void mcstaffeffe_render(int obj)
{
    fn_80098B18(obj, *(f32 *)(obj + 0x8), (u8)*(int *)(obj + 0xf4), 0, 0, 0);
}

void mcstaffeffe_update(void) {}

void mcstaffeffe_init(int obj, int setup)
{
    *(int *)(obj + 0xbc) = (int)fn_802391C4;
    switch (*(u8 *)(setup + 0x1b)) {
    case 0:
        *(int *)(obj + 0xf4) = 4;
        *(int *)(obj + 0xf8) = 1;
        break;
    case 1:
        *(int *)(obj + 0xf4) = 5;
        *(int *)(obj + 0xf8) = 5;
        break;
    case 2:
        *(int *)(obj + 0xf4) = 6;
        *(int *)(obj + 0xf8) = 2;
        break;
    case 3:
        *(int *)(obj + 0xf4) = 0xb;
        *(int *)(obj + 0xf8) = 3;
        break;
    default:
        *(int *)(obj + 0xf4) = 4;
        *(int *)(obj + 0xf8) = 1;
        break;
    }
}
#pragma scheduling on

extern f32 sin(f32 x);
extern f32 lbl_803E6BF0;
extern f32 lbl_803E6BF4;
extern f32 lbl_803E6BF8;

#pragma scheduling off
int drcloudper_setScale(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) == 0) {
        return 0;
    }
    GameBit_Set(0x7a9, *(s8 *)(setup + 0x19));
    (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 0xc, 1);
    (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(2, obj, -1);
    return 1;
}

int drcloudper_selectActiveCloud(int obj)
{
    GameBit_Set(0x7a9, *(s8 *)(*(int *)(obj + 0x4c) + 0x19));
    (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
    return 0;
}

void drcloudper_init(int obj, int setup)
{
    int state;

    ObjGroup_AddObject(obj, 0x13);
    ObjGroup_AddObject(obj, 0x39);
    *(s16 *)obj = (s16)((s8)*(s8 *)(setup + 0x18) << 8);
    state = *(int *)(obj + 0xb8);
    *(f32 *)(state + 0) = fn_80293E80(lbl_803E6BF0 * (f32) * (s16 *)obj / lbl_803E6BF4);
    *(f32 *)(state + 4) = lbl_803E6BF8;
    *(f32 *)(state + 8) = sin(lbl_803E6BF0 * (f32) * (s16 *)obj / lbl_803E6BF4);
    *(f32 *)(state + 0xc) =
        -(*(f32 *)(state + 8) * *(f32 *)(obj + 0x14)) +
        (*(f32 *)(state + 0) * *(f32 *)(obj + 0xc) + *(f32 *)(state + 4) * *(f32 *)(obj + 0x10));
    *(u16 *)(obj + 0xb0) |= 0xe000;
    if (*(s8 *)(setup + 0x19) == GameBit_Get(0x7a9)) {
        (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 0xc, 1);
    }
}

#pragma scheduling on

#pragma scheduling off
extern int objModelGetVecFn_800395d8(int model, int idx);
extern f32 fn_802945E0(f32 ratio);
extern void Sfx_SetObjectChannelVolume(int obj, int channel, int p3, f32 vol);
extern double lbl_803E6F48;
extern double lbl_803E6F50;
extern f32 lbl_803E6F58;
extern f32 lbl_803E6F60;
extern f32 lbl_803E6F64;
extern f32 lbl_803E6F68;
extern f32 lbl_803E6F38;
extern f32 lbl_803E6EF8;
void fn_8022F270(int obj, int p2);

#pragma peephole off
void fn_8022C30C(int obj, int state)
{
    int vec;
    f32 vol;

    vec = objModelGetVecFn_800395d8(*(int *)(state + 0x4), 0x14);

    if (*(u8 *)(state + 0x478) < 4 && (u32)GameBit_Get(0x9d6) == 0 && (u32)GameBit_Get(0x9d8) == 0) {
        vol = (f32)((lbl_803E6F48 + fn_802945E0(*(f32 *)(state + 0x50) / *(f32 *)(state + 0x5c))) *
                    lbl_803E6F50);
        Sfx_KeepAliveLoopedObjectSound(obj, 0x29f);
        Sfx_SetObjectChannelVolume(obj, 0x40, 0xfe, vol);
    }

    fn_8022F270(*(int *)(state + 0x4), *(u16 *)(state + 0x44e));

    if (*(f32 *)(state + 0xb4) <= lbl_803E6ECC) {
        if ((*(u8 *)(state + 0x477) & 0x2) == 0) {
            if ((*(u16 *)(state + 0x3f4) & 0x800) != 0) {
                *(u8 *)(state + 0x477) &= ~0x4;
                *(u8 *)(state + 0x477) |= 0x2;
                *(f32 *)(state + 0xb0) = lbl_803E6F58;
                Sfx_PlayFromObjectLimited(obj, 0x2b6, 3);
            }
        } else {
            *(f32 *)(state + 0x6c) = *(f32 *)(state + 0x88);
            *(f32 *)(state + 0x68) = *(f32 *)(state + 0x90);
            if ((*(u16 *)(state + 0x3f6) & 0x800) != 0) {
                *(u8 *)(state + 0x477) &= ~0x2;
                *(f32 *)(state + 0xb0) = lbl_803E6F5C;
            }
        }
        if ((*(u8 *)(state + 0x477) & 0x4) == 0) {
            if ((*(u16 *)(state + 0x3f4) & 0x400) != 0) {
                *(u8 *)(state + 0x477) &= ~0x2;
                *(u8 *)(state + 0x477) |= 0x4;
                *(f32 *)(state + 0xb0) = lbl_803E6F60;
                Sfx_PlayFromObjectLimited(obj, 0x2b7, 3);
            }
        } else {
            *(f32 *)(state + 0x6c) = *(f32 *)(state + 0x8c);
            *(f32 *)(state + 0x68) = *(f32 *)(state + 0x94);
            if ((*(u16 *)(state + 0x3f6) & 0x400) != 0) {
                *(u8 *)(state + 0x477) &= ~0x4;
                *(f32 *)(state + 0xb0) = lbl_803E6F5C;
            }
        }
    } else {
        if ((*(u16 *)(state + 0x3f4) & 0xc00) != 0) {
            Sfx_PlayFromObject(obj, 0x381);
        }
        *(f32 *)(state + 0xb4) -= timeDelta;
        if (*(f32 *)(state + 0xb4) <= lbl_803E6ECC) {
            *(f32 *)(state + 0xb0) = lbl_803E6F5C;
        }
    }

    if ((*(u8 *)(state + 0x477) & 0x6) == 0) {
        *(f32 *)(state + 0x6c) = lbl_803E6ED0;
        *(f32 *)(state + 0x68) = *(f32 *)(state + 0x98);
        if (*(f32 *)(state + 0xbc) <= lbl_803E6ECC) {
            *(f32 *)(state + 0x9c) = lbl_803E6F64 * timeDelta + *(f32 *)(state + 0x9c);
        } else {
            *(f32 *)(state + 0xbc) -= timeDelta;
        }
    } else {
        *(f32 *)(state + 0x9c) -= timeDelta;
        *(f32 *)(state + 0xbc) = lbl_803E6F38;
    }

    *(f32 *)(state + 0x9c) = *(f32 *)(state + 0x9c) < lbl_803E6ECC
                                 ? lbl_803E6ECC
                                 : *(f32 *)(state + 0x9c) > *(f32 *)(state + 0xa0)
                                       ? *(f32 *)(state + 0xa0)
                                       : *(f32 *)(state + 0x9c);

    if (*(f32 *)(state + 0x9c) <= lbl_803E6ECC) {
        *(u8 *)(state + 0x477) &= ~0x6;
        *(f32 *)(state + 0xb4) = *(f32 *)(state + 0xb8);
        *(f32 *)(state + 0x9c) = *(f32 *)(state + 0xa0);
        *(f32 *)(state + 0xb0) = lbl_803E6F68;
        *(f32 *)(state + 0xbc) = lbl_803E6ECC;
    }

    if ((u32)vec != 0) {
        int n;
        *(f32 *)(state + 0xac) =
            lbl_803E6EF8 * (*(f32 *)(state + 0xb0) - *(f32 *)(state + 0xac)) + *(f32 *)(state + 0xac);
        n = (int)*(f32 *)(state + 0xac);
        *(s16 *)(vec + 0xa) = n;
        *(s16 *)(vec + 0x8) = n;
        *(s16 *)(vec + 0x6) = n;
    }
}
#pragma peephole reset

void fn_8022F270(int obj, int p2) { *(int *)(*(int *)(obj + 0xb8) + 0x4) = p2; }

void fn_8022C7A4(int obj) { *(u8 *)(*(int *)(obj + 0xb8) + 0x47f) = 0; }

extern void ObjLink_AttachChild(int obj, int child, int p3);
extern f32 lbl_803E6F2C;
extern f32 lbl_803E6F34;
extern f32 lbl_803E6F70;
extern f32 lbl_803E6F74;
extern f32 lbl_803E6F78;
extern f32 lbl_803E6F7C;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6F88;
extern f32 lbl_803E6F8C;
extern f32 lbl_803E6F90;
extern f32 lbl_803E6F94;
extern f32 lbl_803E6F98;
extern f32 lbl_803E6F9C;
extern f32 lbl_803E6FA0;
extern f32 lbl_803E6FA4;
extern f32 lbl_803E6FA8;
extern f32 lbl_803E6FAC;
extern f32 lbl_803E6FB0;
extern f32 lbl_803E6FB4;
extern f32 lbl_803E6FB8;
extern f32 lbl_803E6FBC;
extern f32 lbl_803E6FC0;
extern f32 lbl_803E6FC4;
extern f32 lbl_803E6FC8;
extern f32 lbl_803E6FCC;
extern f32 lbl_803E6FD0;
extern f32 lbl_803E6FD4;
extern f32 lbl_803E6FD8;
extern f32 lbl_803E6FDC;
extern f32 lbl_803E6FE0;
extern f32 lbl_803E6FE4;
extern f32 lbl_803E6FE8;
extern f32 lbl_803E6FEC;
extern f32 lbl_803E6FF0;
extern f32 lbl_803E6EF0;
extern f32 lbl_803E6EF4;

#pragma scheduling off
#pragma peephole off
void fn_8022CDEC(int obj, int state)
{
    int found;
    int mev;
    f32 radius;

    radius = lbl_803E6FC0;
    mev = (*(int (**)(int))(*gMapEventInterface + 0x8c))(*gMapEventInterface);

    if (*(void **)(state + 0x4) == 0) {
        *(int *)(state + 0x4) = ObjList_FindNearestObjectByDefNo(obj, 0x606, &radius);
        if (*(void **)(state + 0x4) != 0) {
            ObjLink_AttachChild(obj, *(int *)(state + 0x4), 0);
        }
    }

    if (*(u8 *)(state + 0x480) != 0) {
        if (*(void **)(state + 0x10) == 0) {
            *(int *)(state + 0x10) = ObjList_FindNearestObjectByDefNo(obj, 0x611, &radius);
            if (*(void **)(state + 0x10) != 0) {
                ObjLink_AttachChild(obj, *(int *)(state + 0x10), 0);
            }
        }
        if (*(void **)(state + 0x8) == 0) {
            *(int *)(state + 0x8) = ObjList_FindNearestObjectByDefNo(obj, 0x610, &radius);
            if (*(void **)(state + 0x8) != 0) {
                ObjLink_AttachChild(obj, *(int *)(state + 0x8), 0);
            }
        }
        if (*(void **)(state + 0xc) == 0) {
            *(int *)(state + 0xc) = ObjList_FindNearestObjectByDefNo(obj, 0x615, &radius);
            if (*(void **)(state + 0xc) != 0) {
                ObjLink_AttachChild(obj, *(int *)(state + 0xc), 0);
            }
        }
    }

    if (*(void **)(state + 0x418) == 0 && *(void **)(state + 0x41c) == 0) {
        int setup;
        setup = Obj_AllocObjectSetup(0x20, 0x6de);
        *(u8 *)(setup + 0x4) = 1;
        *(u8 *)(setup + 0x5) = 1;
        *(int *)(state + 0x418) = ((int (*)(int, int))loadObjectAtObject)(obj, setup);
        setup = Obj_AllocObjectSetup(0x20, 0x6de);
        *(u8 *)(setup + 0x4) = 1;
        *(u8 *)(setup + 0x5) = 1;
        *(int *)(state + 0x41c) = ((int (*)(int, int))loadObjectAtObject)(obj, setup);
    }

    found = 0;
    if (*(u8 *)(state + 0x480) != 0) {
        if (*(void **)(state + 0x450) == 0) {
            *(int *)(state + 0x450) = (int)objCreateLight(obj, 1);
            if (*(void **)(state + 0x450) != 0) {
                modelLightStruct_setField50(*(void **)(state + 0x450), 2);
                lightVecFn_8001dd88(*(void **)(state + 0x450), lbl_803E6ECC, lbl_803E6FC4, lbl_803E6FC8);
                lightSetFieldBC_8001db14(*(void **)(state + 0x450), 1);
                modelLightStruct_setColorsA8AC(*(void **)(state + 0x450), 0x28, 0x7d, 0xff, 0);
                lightDistAttenFn_8001dc38(*(void **)(state + 0x450), lbl_803E6FCC, lbl_803E6FD0);
                lightFn_8001d620(*(void **)(state + 0x450), 1, 1);
                lightSetFieldB0(*(void **)(state + 0x450), 0x14, 0x64, 0xc8, 0);
            }
        }
        if (*(void **)(state + 0x4) != 0 && *(void **)(state + 0x10) != 0 && *(void **)(state + 0x8) != 0 &&
            *(void **)(state + 0xc) != 0) {
            found = 1;
        }
    } else {
        if (*(void **)(state + 0x4) != 0) {
            found = 1;
        }
    }

    if (found != 0) {
        (*(void (**)(int, int))(*gCameraInterface + 0x28))(obj, 0);
        *(u8 *)(state + 0x477) |= 1;
        *(f32 *)(state + 0x54) = lbl_803E6F70;
        *(f32 *)(state + 0x60) = lbl_803E6F74;
        *(f32 *)(state + 0x58) = lbl_803E6F78;
        *(f32 *)(state + 0x64) = lbl_803E6F7C;
        *(f32 *)(state + 0x5c) = lbl_803E6F78;
        *(f32 *)(state + 0x68) = lbl_803E6F7C;
        *(f32 *)(state + 0x78) = lbl_803E6F80;
        *(f32 *)(state + 0x84) = lbl_803E6F84;
        *(f32 *)(state + 0x6c) = lbl_803E6ED0;
        *(f32 *)(state + 0x348) = lbl_803E6F88;
        *(f32 *)(state + 0x34c) = lbl_803E6F74;
        *(f32 *)(state + 0x35c) = lbl_803E6F8C;
        *(f32 *)(state + 0x360) = lbl_803E6F7C;
        *(f32 *)(state + 0x370) = lbl_803E6F90;
        *(f32 *)(state + 0x374) = lbl_803E6F94;
        *(f32 *)(state + 0x384) = lbl_803E6F98;
        *(f32 *)(state + 0x388) = lbl_803E6F9C;
        *(f32 *)(state + 0x394) = lbl_803E6FA0;
        *(f32 *)(state + 0x390) = lbl_803E6FA4;
        *(f32 *)(state + 0x39c) = lbl_803E6FA8;
        *(u8 *)(state + 0x3fa) = 0x19;
        *(f32 *)(state + 0x3a4) = lbl_803E6FAC;
        *(f32 *)(state + 0x38) = lbl_803E6FB0;
        *(f32 *)(obj + 0x8) = lbl_803E6FB0;
        *(f32 *)(state + 0x3ac) = lbl_803E6FB4;
        *(f32 *)(state + 0x3b0) = lbl_803E6FB8;
        *(f32 *)(state + 0x88) = lbl_803E6FBC;
        *(f32 *)(state + 0x8c) = lbl_803E6F64;
        *(f32 *)(state + 0x90) = lbl_803E6FD4;
        *(f32 *)(state + 0x94) = lbl_803E6F74;
        *(f32 *)(state + 0x98) = lbl_803E6FD8;
        *(f32 *)(state + 0xb8) = lbl_803E6FDC;
        *(f32 *)(state + 0xa0) = lbl_803E6FE0;
        *(f32 *)(state + 0xa8) = lbl_803E6F2C;
        *(f32 *)(state + 0x9c) = *(f32 *)(state + 0xa0);
        *(f32 *)(state + 0xa4) = *(f32 *)(state + 0xa8);
        *(f32 *)(state + 0xac) = lbl_803E6F5C;
        *(f32 *)(state + 0xb0) = lbl_803E6F5C;
        if (*(s8 *)(obj + 0xac) == 0x26) {
            *(f32 *)(state + 0x50) = lbl_803E6ECC;
        } else {
            *(f32 *)(state + 0x50) = lbl_803E6F78;
        }
        *(s16 *)(state + 0x40e) = 0x28;
        *(f32 *)(state + 0x410) = lbl_803E6FE0;
        *(s16 *)(state + 0x40c) = 0x6;
        *(s16 *)(state + 0x446) = 0x5a;
        *(f32 *)(state + 0x448) = lbl_803E6F34;
        *(s16 *)(state + 0x444) = 0xc;
        *(u8 *)(state + 0x44d) = 0x3;
        *(int *)(state + 0x454) = objModelGetVecFn_800395d8(obj, 0);
        *(int *)(state + 0x458) = objModelGetVecFn_800395d8(obj, 1);
        *(int *)(state + 0x45c) = objModelGetVecFn_800395d8(obj, 2);
        *(int *)(state + 0x460) = objModelGetVecFn_800395d8(obj, 3);
        *(f32 *)(state + 0x464) = lbl_803E6F64;
        *(s16 *)(state + 0x44e) = 0xaf;
        *(u8 *)(state + 0x469) = *(u8 *)(mev + 0x1);
        *(u8 *)(state + 0x468) = *(u8 *)(state + 0x469);
        *(f32 *)(state + 0x3b4) = lbl_803E6EF8;
        *(f32 *)(state + 0x3b8) = lbl_803E6EF0;
        *(f32 *)(state + 0x3bc) = lbl_803E6FE4;
        *(f32 *)(state + 0x3c4) = lbl_803E6EF4;
        *(f32 *)(state + 0x3c8) = lbl_803E6FD4;
        *(f32 *)(state + 0x3d0) = lbl_803E6FE8;
        *(f32 *)(state + 0x3d4) = lbl_803E6F80;
        *(f32 *)(state + 0x3e0) = lbl_803E6FA4;
        *(f32 *)(state + 0x14) = *(f32 *)(obj + 0xc);
        *(f32 *)(state + 0x18) = *(f32 *)(obj + 0x10);
        *(f32 *)(state + 0x1c) = *(f32 *)(obj + 0x14);
        *(f32 *)(state + 0x20) = lbl_803E6FEC;
        *(f32 *)(state + 0x28) = lbl_803E6FF0;
        *(f32 *)(state + 0x24) = lbl_803E6EF0;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E707C;
extern f32 lbl_803E7080;
extern f32 lbl_803E7084;
extern f32 lbl_803E7088;
extern f32 lbl_803E708C;

typedef struct {
    u8 b80 : 1;
    u8 b40 : 1;
} ArwBombFlags;

#pragma scheduling off
#pragma peephole off
void arwbombcoll_update(int obj)
{
    ArwBombFlags *flags;
    int arw;
    int s;
    int a2;

    arw = getArwing();
    s = *(int *)(obj + 0xb8);
    flags = (ArwBombFlags *)(s + 0x4);

    if (*(f32 *)(s + 0x0) > lbl_803E707C) {
        *(f32 *)(s + 0x0) -= timeDelta;
        if (*(f32 *)(s + 0x0) <= lbl_803E707C) {
            Obj_FreeObject(obj);
            return;
        }
    }

    if ((u32)arw != 0 && fn_8022D710(arw) != 0) {
        flags->b80 = 0;
        *(s16 *)(obj + 0x6) &= ~0x4000;
        ObjHits_EnableObject(obj);
        return;
    }

    if (flags->b80 == 0) {
        a2 = getArwing();
        if ((((u32)a2 != 0) ? (*(f32 *)(obj + 0x14) - *(f32 *)(a2 + 0x14) < lbl_803E7080) : 0) != 0) {
            goto active;
        }
    }
    *(s16 *)(obj + 0x6) |= 0x4000;
    *(u8 *)(obj + 0x36) = 0;
    return;
active : {
        int v;
        v = (int)(lbl_803E7084 * timeDelta + (f32)(u32) * (u8 *)(obj + 0x36));
        if (v > 0xff) {
            v = 0xff;
        }
        *(u8 *)(obj + 0x36) = v;
        *(s16 *)(obj + 0x6) &= ~0x4000;
        *(s16 *)(obj + 0x0) = (int)(lbl_803E7088 * timeDelta + (f32) * (s16 *)(obj + 0x0));
        ObjHits_SetHitVolumeSlot(obj, 0x13, 0, 0);
        if (flags->b40 != 0) {
            if (*(void **)(*(int *)(obj + 0x54) + 0x50) != 0 &&
                *(void **)(*(int *)(obj + 0x54) + 0x50) == (void *)getArwing()) {
                fn_8022D520(arw, 0x19);
                flags->b80 = 1;
                *(s16 *)(obj + 0x6) |= 0x4000;
                ObjHits_DisableObject(obj);
            }
        } else {
            int hit;
            if (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0 && (u32)hit != 0 &&
                (*(s16 *)(hit + 0x46) == 0x604 || *(s16 *)(hit + 0x46) == 0x605)) {
                fn_8022D520(arw, 0xf);
                flags->b40 = 1;
                Obj_SetActiveModelIndex(obj, 1);
                spawnExplosion(obj, lbl_803E708C, 1, 0, 0, 0, 0, 0, 2);
            }
            if (*(void **)(*(int *)(obj + 0x54) + 0x50) != 0 &&
                *(void **)(*(int *)(obj + 0x54) + 0x50) == (void *)getArwing()) {
                *(s16 *)(obj + 0x6) |= 0x4000;
                ObjHits_DisableObject(obj);
                spawnExplosion(obj, lbl_803E708C, 1, 0, 0, 0, 0, 0, 2);
            }
        }
        if ((u32)arw != 0 && flags->b80 != 0) {
            switch (*(s16 *)(obj + 0x46)) {
            case 0x609:
                Sfx_PlayFromObject(obj, 0x2a6);
                fn_8022D6F0(arw);
                break;
            case 0x608:
                Sfx_PlayFromObject(obj, 0x2a7);
                fn_8022D6D0(arw);
                break;
            case 0x6d8:
                Sfx_PlayFromObject(obj, 0x2a8);
                fn_8022D5DC(arw);
                break;
            case 0x6d9:
                Sfx_PlayFromObject(obj, 0x2a8);
                fn_8022D5C8(arw);
                break;
            case 0x6db:
                Sfx_PlayFromObject(obj, 0x2a8);
                fn_8022D5B4(arw);
                break;
            case 0x6da:
                Sfx_PlayFromObject(obj, 0x2a8);
                fn_8022D5A0(arw);
                break;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int lbl_803E7160;
extern f32 lbl_803E716C;
extern f32 lbl_803E7170;
extern f32 lbl_803E71C0;
extern f32 lbl_803E71C4;
extern f32 lbl_803E71C8;
extern f32 lbl_803E71CC;
extern f32 lbl_803E71D0;
extern f32 lbl_803E71D4;
void arwsquadron_applyCommandParams(int p1, int p2);

typedef struct {
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
} SquadFlags;

#pragma scheduling off
#pragma peephole off
void arwsquadron_init(int obj, int setup)
{
    SquadFlags *flags;
    int s;
    int tmp;

    tmp = lbl_803E7160;
    s = *(int *)(obj + 0xb8);
    flags = (SquadFlags *)(s + 0x160);

    *(s16 *)(obj + 0x0) = *(u8 *)(setup + 0x18) << 8;
    *(s16 *)(obj + 0x2) = *(u8 *)(setup + 0x19) << 8;
    *(s16 *)(obj + 0x4) = *(u8 *)(setup + 0x1a) << 8;
    flags->b10 = 1;
    *(u8 *)(s + 0x15e) = 1;
    *(f32 *)(s + 0x108) = (f32)(u32) * (u8 *)(setup + 0x30) * lbl_803E716C;
    *(f32 *)(s + 0x10c) = *(f32 *)(s + 0x108);
    *(s16 *)(s + 0x140) = *(u8 *)(setup + 0x1b) << 4;
    *(s16 *)(s + 0x142) = *(u8 *)(setup + 0x1c) << 4;
    *(s16 *)(s + 0x144) = *(u8 *)(setup + 0x1d) << 4;
    ObjHits_SetTargetMask(obj, 4);

    if (*(s16 *)(setup + 0x0) == 0x616 || *(s16 *)(setup + 0x0) == 0x617) {
        *(u8 *)(s + 0x15c) = 3;
        if (*(s16 *)(setup + 0x0) == 0x616) {
            flags->b10 = 0;
        }
        if (*(s16 *)(setup + 0x0) == 0x616) {
            *(f32 *)(s + 0x130) = lbl_803E71C0;
        } else {
            *(f32 *)(s + 0x130) = lbl_803E71C4;
        }
        *(u8 *)(s + 0x157) = 5;
        *(u8 *)(s + 0x158) = 0;
        if (*(s16 *)(setup + 0x0) == 0x616) {
            *(u8 *)(s + 0x156) = 2;
        } else {
            *(u8 *)(s + 0x156) = 1;
        }
        *(s16 *)(s + 0x140) = randomGetRange(-0x12c, 0x12c);
        *(s16 *)(s + 0x142) = randomGetRange(-0x12c, 0x12c);
        *(s16 *)(s + 0x144) = randomGetRange(-0x12c, 0x12c);
        flags->b80 = 1;
    } else if (*(s16 *)(setup + 0x0) == 0x7f0) {
        *(u8 *)(s + 0x15c) = 2;
        flags->b10 = 0;
        *(f32 *)(s + 0x130) = lbl_803E71C0;
    } else {
        *(u8 *)(s + 0x15c) = 1;
        *(f32 *)(s + 0x130) = lbl_803E71C4;
        *(u8 *)(s + 0x156) = 1;
        *(u8 *)(s + 0x157) = 0x14;
        *(u8 *)(s + 0x158) = 0;
        *(f32 *)(s + 0x11c) = lbl_803E71C8;
        *(f32 *)(s + 0x120) = lbl_803E7170;
        flags->b80 = 1;
        switch (*(s16 *)(obj + 0x46)) {
        case 0x6d6:
            *(u8 *)(s + 0x15a) = 1;
            *(u8 *)(s + 0x15b) = 2;
            *(f32 *)(s + 0x114) = lbl_803E71CC;
            *(f32 *)(s + 0x118) = lbl_803E71D0;
            break;
        case 0x6d5:
            *(u8 *)(s + 0x15a) = 0;
            *(u8 *)(s + 0x15b) = 1;
            break;
        case 0x6d7:
            *(u8 *)(s + 0x15a) = 1;
            *(u8 *)(s + 0x15b) = 1;
            *(f32 *)(s + 0x114) = lbl_803E71CC;
            *(f32 *)(s + 0x118) = lbl_803E71D0;
            break;
        default:
            *(u8 *)(s + 0x15a) = 1;
            *(u8 *)(s + 0x15b) = 1;
            *(f32 *)(s + 0x114) = lbl_803E7170;
            *(f32 *)(s + 0x118) = lbl_803E71D0;
            break;
        }
    }

    *(f32 *)(s + 0x134) = (f32)(u32) * (u16 *)(setup + 0x24);
    if (*(f32 *)(s + 0x134) > *(f32 *)(s + 0x130)) {
        *(f32 *)(s + 0x134) = *(f32 *)(s + 0x130);
    }
    *(u8 *)(obj + 0x36) = 0;
    *(s16 *)(obj + 0x6) |= 0x4000;
    storeZeroToFloatParam((void *)(s + 0x12c));

    if (*(u8 *)(setup + 0x2f) != 0) {
        if (*(u8 *)(s + 0x15c) == 1 || *(u8 *)(s + 0x15c) == 2) {
            tmp = 0x28;
        } else {
            tmp = 2;
        }
        if ((u8)(*(int (**)(int, int, f32, int *, int))(*gRomCurveInterface + 0x8c))(
                s, obj, lbl_803E71D4, &tmp, -1) == 0) {
            flags->b40 = 1;
            *(f32 *)(obj + 0xc) = *(f32 *)(s + 0x68);
            *(f32 *)(obj + 0x10) = *(f32 *)(s + 0x6c);
            *(f32 *)(obj + 0x14) = *(f32 *)(s + 0x70);
            arwsquadron_applyCommandParams(obj, s);
        }
    }

    *(u16 *)(s + 0x146) = randomGetRange(0, 0xffff);
    *(u16 *)(s + 0x148) = randomGetRange(0, 0xffff);
    *(u16 *)(s + 0x14a) = randomGetRange(0xc8, 0x12c);
    *(u16 *)(s + 0x14c) = randomGetRange(0xc8, 0x12c);
    *(f32 *)(s + 0x138) = (f32)(int)randomGetRange(0x3e8, 0x7d0);
    *(u8 *)(s + 0x15d) = *(u8 *)(setup + 0x31);
}
#pragma peephole reset
#pragma scheduling reset

void fn_80231058(int obj, int src)
{
    *(f32 *)(obj + 0x24) = *(f32 *)(src + 0x0);
    *(f32 *)(obj + 0x28) = *(f32 *)(src + 0x4);
    *(f32 *)(obj + 0x2c) = *(f32 *)(src + 0x8);
}

void fn_8023137C(int obj, int src)
{
    *(f32 *)(obj + 0x24) = *(f32 *)(src + 0x0);
    *(f32 *)(obj + 0x28) = *(f32 *)(src + 0x4);
    *(f32 *)(obj + 0x2c) = *(f32 *)(src + 0x8);
}

#pragma dont_inline on
void fn_8022ED74(int obj, int v) { *(f32 *)(*(int *)(obj + 0xb8) + 0x0) = (f32)v; }
#pragma dont_inline reset
#pragma dont_inline on
void fn_8022F558(int obj, int v) { *(f32 *)(*(int *)(obj + 0xb8) + 0x0) = (f32)v; }
#pragma dont_inline reset
void fn_80231028(int obj, int v) { *(f32 *)(*(int *)(obj + 0xb8) + 0x0) = (f32)v; }
void fn_8023134C(int obj, int v) { *(f32 *)(*(int *)(obj + 0xb8) + 0x0) = (f32)v; }

extern f32 lbl_803E7140;
#pragma scheduling off
void fn_802315EC(int obj, int state, int setup)
{
    int newObj;
    f32 dir[3];

    if (Obj_IsLoadingLocked()) {
        newObj = Obj_AllocObjectSetup(0x20, 0x616);
        *(f32 *)(newObj + 8) = *(f32 *)(obj + 0xc) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x22), (s8)*(u8 *)(setup + 0x22));
        *(f32 *)(newObj + 0xc) = *(f32 *)(obj + 0x10) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x23), (s8)*(u8 *)(setup + 0x23));
        *(f32 *)(newObj + 0x10) = *(f32 *)(obj + 0x14) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x24), (s8)*(u8 *)(setup + 0x24));
        *(u8 *)(newObj + 0x1a) = 0;
        *(u8 *)(newObj + 0x19) = 0;
        *(u8 *)(newObj + 0x18) = 0;
        *(u8 *)(newObj + 4) = 1;
        *(u8 *)(newObj + 5) = 1;
        newObj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        dir[0] = (f32)(s8)*(u8 *)(setup + 0x1c) / lbl_803E7140;
        dir[1] = (f32)(s8)*(u8 *)(setup + 0x1d) / lbl_803E7140;
        dir[2] = (f32)(s8)*(u8 *)(setup + 0x1e) / lbl_803E7140;
        fn_8023137C(newObj, (int)dir);
        fn_8023134C(newObj, *(u16 *)(setup + 0x1a));
    }
}
void fn_802317A8(int obj, int state, int setup)
{
    int newObj;
    f32 dir[3];

    if (Obj_IsLoadingLocked()) {
        newObj = Obj_AllocObjectSetup(0x20, 0x617);
        *(f32 *)(newObj + 8) = *(f32 *)(obj + 0xc) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x22), (s8)*(u8 *)(setup + 0x22));
        *(f32 *)(newObj + 0xc) = *(f32 *)(obj + 0x10) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x23), (s8)*(u8 *)(setup + 0x23));
        *(f32 *)(newObj + 0x10) = *(f32 *)(obj + 0x14) + (f32)(int)randomGetRange(-(s8)*(u8 *)(setup + 0x24), (s8)*(u8 *)(setup + 0x24));
        *(u8 *)(newObj + 0x1a) = 0;
        *(u8 *)(newObj + 0x19) = 0;
        *(u8 *)(newObj + 0x18) = 0;
        *(u8 *)(newObj + 4) = 1;
        *(u8 *)(newObj + 5) = 1;
        newObj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        dir[0] = (f32)(s8)*(u8 *)(setup + 0x1c) / lbl_803E7140;
        dir[1] = (f32)(s8)*(u8 *)(setup + 0x1d) / lbl_803E7140;
        dir[2] = (f32)(s8)*(u8 *)(setup + 0x1e) / lbl_803E7140;
        fn_80231058(newObj, (int)dir);
        fn_80231028(newObj, *(u16 *)(setup + 0x1a));
    }
}
#pragma scheduling on

void fn_8022F27C(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int model = Obj_GetActiveModel(obj);
    int *texture = objFindTexture(obj, 0, 0);
    int anim = fn_800283E8(*(int *)model, 0);
    fn_800541A4(anim, (u16)*(int *)(state + 4));
    textureAnimFn_80053f2c(anim, state, (int)texture);
}

extern f32 lbl_803E7044;
#pragma dont_inline on
void fn_8022ECE0(int obj, f32 param)
{
    int state = *(int *)(obj + 0xb8);
    f32 mtx[12];
    ArwProjPosSrc src;

    *(f32 *)(state + 4) = param;
    src.pos[0] = lbl_803E7044;
    src.pos[1] = lbl_803E7044;
    src.pos[2] = lbl_803E7044;
    src.rot[0] = *(s16 *)obj;
    src.rot[1] = *(s16 *)(obj + 2);
    src.rot[2] = 0;
    src.scale = lbl_803E704C;
    setMatrixFromObjectPos(mtx, &src);
    Matrix_TransformPoint(mtx, lbl_803E7044, lbl_803E7044, *(f32 *)(state + 4),
                          (f32 *)(obj + 0x24), (f32 *)(obj + 0x28), (f32 *)(obj + 0x2c));
}
#pragma dont_inline reset

extern int loadObjectAtObject(int obj);

#pragma dont_inline on
#pragma peephole off
void fn_8022B764(int p, int q, int idx) {
    f32 pz, py, px;
    int setup;
    u8 cnt;
    if (Obj_IsLoadingLocked() == 0)
        return;
    cnt = *(u8 *)(q + 0x44c);
    if (cnt == 0)
        return;
    *(u8 *)(q + 0x44c) = cnt - 1;
    if (idx == 0)
        ObjPath_GetPointWorldPosition(p, 5, &px, &py, &pz, 0);
    else
        ObjPath_GetPointWorldPosition(p, 6, &px, &py, &pz, 0);
    setup = Obj_AllocObjectSetup(0x20, 0x605);
    *(f32 *)(setup + 8) = px;
    *(f32 *)(setup + 0xc) = py;
    *(f32 *)(setup + 0x10) = pz;
    *(u8 *)(setup + 0x1a) = *(s16 *)(p + 0) >> 8;
    *(u8 *)(setup + 0x19) = *(s16 *)(p + 2) >> 8;
    *(u8 *)(setup + 0x18) = *(s16 *)(p + 4) >> 8;
    *(u8 *)(setup + 4) = 1;
    *(u8 *)(setup + 5) = 1;
    *(int *)(q + 0x438) = loadObjectAtObject(p);
    fn_8022ED74(*(int *)(q + 0x438), *(u16 *)(q + 0x446));
    fn_8022ECE0(*(int *)(q + 0x438), *(f32 *)(q + 0x448));
    Sfx_PlayFromObject(p, 0x2a3);
}
#pragma peephole reset
#pragma dont_inline reset

extern int ObjList_FindNearestObjectByDefNo(int obj, int defNo, f32 *maxDistanceSq);
extern f32 lbl_803E7490;

#pragma dont_inline on
#pragma peephole off
#pragma scheduling off
void fn_80239DD8(int p1, int p2)
{
    f32 maxDist;
    int near;
    int newObj;

    maxDist = lbl_803E7490;
    if (Obj_IsLoadingLocked()) {
        near = ObjList_FindNearestObjectByDefNo(p1, 0x7e5, &maxDist);
        if (near != 0) {
            newObj = Obj_AllocObjectSetup(0x24, 0x608);
            *(f32 *)(newObj + 8) = *(f32 *)(near + 0xc);
            *(f32 *)(newObj + 0xc) = *(f32 *)(near + 0x10);
            *(f32 *)(newObj + 0x10) = *(f32 *)(near + 0x14);
            *(u8 *)(newObj + 4) = 1;
            *(u8 *)(newObj + 5) = 1;
            *(int *)(p2 + 0x10) = ((int (*)(int, int))loadObjectAtObject)(p1, newObj);
            if (*(void **)(p2 + 0x10) != NULL) {
                *(u8 *)(*(int *)(p2 + 0x10) + 0x36) = 0xff;
                *(u8 *)(*(int *)(p2 + 0x10) + 0x37) = 0xff;
                *(int *)(p2 + 0x90) = 0x12c;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
#pragma dont_inline reset

extern int lbl_803DC4E8;

#pragma scheduling off
void fn_80239EAC(int p1, int p2)
{
    f32 dx, dy, dz;
    int *objs;
    int obj;
    int i;
    int count;
    int defNo;

    objs = ObjGroup_GetObjects(2, &count);
    for (i = 0; i < count; i++) {
        obj = *objs;
        defNo = *(s16 *)(*(int *)(obj + 0x4c));
        if (defNo == 0x80d || defNo == 0x859) {
            dy = *(f32 *)(p2 + 0xc4) - *(f32 *)(obj + 0x10);
            dz = *(f32 *)(p2 + 0xc8) - *(f32 *)(obj + 0x14);
            dx = *(f32 *)(p2 + 0xc0) - *(f32 *)(obj + 0xc);
            *(s16 *)(obj + 0) = (s16)getAngle(dx, dz);
            *(s16 *)(obj + 2) = -(s16)getAngle(dy, dz);
            arwprojectile_placeForward(obj, (f32)(u32)lbl_803DC4E8);
        }
        objs++;
    }
}
#pragma scheduling reset

extern f32 lbl_803E74AC;
extern f32 lbl_803E74B0;
extern f32 lbl_803E74D4;
extern f32 lbl_803E74D8;

#pragma peephole off
#pragma scheduling off
void fn_8023A168(int p1, int p2)
{
    int yawRnd;
    int pitchRnd;
    int newObj;
    int proj;

    if (Obj_IsLoadingLocked()) {
        yawRnd = (s16)(randomGetRange(-0x1f40, 0x1f40) - 0x8000);
        pitchRnd = randomGetRange(-0x1f40, 0x1f40) >> 8;
        newObj = Obj_AllocObjectSetup(0x20, 0x80d);
        *(f32 *)(newObj + 8) = *(f32 *)(p2 + 0xc0);
        *(f32 *)(newObj + 0xc) = *(f32 *)(p2 + 0xc4);
        *(f32 *)(newObj + 0x10) = *(f32 *)(p2 + 0xc8);
        *(u8 *)(newObj + 0x1a) = (*(s16 *)p1 + yawRnd) >> 8;
        *(u8 *)(newObj + 0x19) = pitchRnd;
        *(u8 *)(newObj + 0x18) = 0;
        *(u8 *)(newObj + 4) = 1;
        *(u8 *)(newObj + 5) = 1;
        proj = ((int (*)(int, int))loadObjectAtObject)(p1, newObj);
        if (proj != 0) {
            *(f32 *)(proj + 8) = lbl_803E74B0;
            arwprojectile_setLifetime(proj, 0x6e);
            arwprojectile_placeForward(proj, lbl_803E74AC);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

void fn_8023A87C(int p1, int p2)
{
    void *spawned;

    spawned = *(void **)(p2 + 0x10);
    if (spawned != NULL) {
        *(f32 *)((char *)spawned + 0x14) -= lbl_803E74D8;
        *(int *)(p2 + 0x90) -= framesThisStep;
        if (*(int *)(p2 + 0x90) < 0) {
            fn_8022F558(*(int *)(p2 + 0x10), 5);
            *(int *)(p2 + 0x90) = 0;
            *(int *)(p2 + 0x10) = 0;
        }
    } else if (*(f32 *)(p2 + 0x6c) >= lbl_803E74D4) {
        *(f32 *)(p2 + 0x6c) -= timeDelta;
        if (*(f32 *)(p2 + 0x6c) < lbl_803E74D4)
            fn_80239DD8(p1, p2);
    } else if ((u32)GameBit_Get(0x12) != 0) {
        *(f32 *)(p2 + 0x6c) = (f32)(u32)randomGetRange(1, 0x14);
        GameBit_Set(0x12, 0);
    }
}

extern int lbl_803DC4D8;
extern int lbl_803DC4DC;
extern int lbl_803DC4E0;
extern f32 lbl_803DC4E4;
extern int lbl_803DDDBC;
extern int lbl_803DDDC0;
extern s16 lbl_803DDDC4;
extern s16 lbl_803DDDC6;
extern f32 lbl_803E74A0;
extern f32 lbl_803E74A4;
extern f32 lbl_803E74A8;

#pragma peephole off
#pragma scheduling off
void fn_8023A268(int p1, int p2)
{
    f32 dx, dz, dist;
    int yaw;
    int newObj;
    int proj;

    if (Obj_IsLoadingLocked()) {
        dx = *(f32 *)(p2 + 0xc0) - *(f32 *)(*(int *)p2 + 0xc);
        dz = *(f32 *)(p2 + 0xc8) - *(f32 *)(*(int *)p2 + 0x14);
        dist = sqrtf(dx * dx + dz * dz);
        yaw = (u16)getAngle(dx, dz);
        lbl_803DDDBC = (u16)getAngle(*(f32 *)(p2 + 0xc4) - *(f32 *)(*(int *)p2 + 0x10), dist) >> 8;
        newObj = Obj_AllocObjectSetup(0x20, 0x7e4);
        *(f32 *)(newObj + 8) = *(f32 *)(p2 + 0xc0);
        *(f32 *)(newObj + 0xc) = *(f32 *)(p2 + 0xc4);
        *(f32 *)(newObj + 0x10) = *(f32 *)(p2 + 0xc8);
        *(u8 *)(newObj + 0x1a) = (*(s16 *)p1 + yaw) >> 8;
        *(u8 *)(newObj + 0x19) = lbl_803DDDBC;
        *(u8 *)(newObj + 0x18) = 0;
        *(u8 *)(newObj + 4) = 1;
        *(u8 *)(newObj + 5) = 1;
        proj = ((int (*)(int, int))loadObjectAtObject)(p1, newObj);
        if (proj != 0) {
            arwprojectile_setLifetime(proj, lbl_803DC4DC);
            arwprojectile_placeForward(proj, (f32)(u32)lbl_803DC4D8);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_80239FCC(int p1, int p2)
{
    f32 ang;
    int yaw;
    int rndYaw;
    int rndDur;
    int newObj;
    int proj;

    if (Obj_IsLoadingLocked()) {
        yaw = lbl_803DDDC4;
        lbl_803DDDC0 = lbl_803DDDC6;
        rndYaw = (s16)randomGetRange(-0x8000, 0x7fff);
        rndDur = randomGetRange(0x64, 0x12c);
        newObj = Obj_AllocObjectSetup(0x20, 0x859);
        ang = lbl_803E74A0 * (f32)(u32)rndYaw / lbl_803E74A4;
        *(f32 *)(newObj + 8) = (f32)(u32)rndDur * fn_80293E80(ang) + *(f32 *)(*(int *)p2 + 0xc);
        *(f32 *)(newObj + 0xc) = (f32)(u32)rndDur * sin(ang) + *(f32 *)(*(int *)p2 + 0x10);
        *(f32 *)(newObj + 0x10) = *(f32 *)(p2 + 0xc8) - lbl_803E74A8;
        *(u8 *)(newObj + 0x1a) = (*(s16 *)p1 + yaw) >> 8;
        *(u8 *)(newObj + 0x19) = lbl_803DDDC0;
        *(u8 *)(newObj + 0x18) = 0;
        *(u8 *)(newObj + 4) = 1;
        *(u8 *)(newObj + 5) = 1;
        proj = ((int (*)(int, int))loadObjectAtObject)(p1, newObj);
        if (proj != 0) {
            *(f32 *)(proj + 8) = lbl_803DC4E4;
            arwprojectile_setLifetime(proj, lbl_803DC4E0);
            arwprojectile_placeForward(proj, lbl_803E74AC);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_803DC4C0;
extern f32 lbl_803DC4C4;

#pragma peephole off
#pragma scheduling off
int fn_8023A6A4(int p1, f32 a, f32 b, f32 c)
{
    f32 val, ang;
    f32 dx, dy, dz, dist;
    int yaw;
    int result;
    f32 vel[3];

    result = 0;
    dx = *(f32 *)(p1 + 0xc0) - *(f32 *)(*(int *)p1 + 0xc);
    dy = *(f32 *)(p1 + 0xc4) - *(f32 *)(*(int *)p1 + 0x10);
    dz = *(f32 *)(p1 + 0xc8) - *(f32 *)(*(int *)p1 + 0x14);
    dist = sqrtf(dx * dx + dy * dy);
    yaw = (s16)getAngle(dx, dy);
    if ((s16)getAngle(dist, dz) > 0x2ee0 && dz > lbl_803DC4C0)
        result = 1;
    val = dist / b;
    if (val < -a)
        val = -a;
    else if (val > a)
        val = a;
    ang = lbl_803E74A0 * (f32)(u32)yaw / lbl_803E74A4;
    *(f32 *)(p1 + 0xd8) = val * fn_80293E80(ang);
    *(f32 *)(p1 + 0xdc) = val * sin(ang);
    fn_8022D48C((int)vel, *(int *)p1);
    *(f32 *)(p1 + 0xd8) -= vel[0] * lbl_803DC4C4;
    *(f32 *)(p1 + 0xdc) -= vel[1] * lbl_803DC4C4;
    *(f32 *)(p1 + 0xe0) = c;
    return result;
}
#pragma scheduling reset
#pragma peephole reset

extern u8 lbl_803DC4C8;

#pragma scheduling off
void fn_8023A3E4(int p1, int p2)
{
    int hitVol;
    int hitType;
    int hitObj;
    u8 i;
    int got;

    got = ObjHits_GetPriorityHit(p1, &hitObj, &hitType, &hitVol);
    for (i = 0; i < 4; i++) {
        int v = *(u8 *)(p2 + 0xb2 + i) - framesThisStep;
        if (v < 0)
            v = 0;
        *(u8 *)(p2 + 0xb2 + i) = v;
    }
    if (got != 0) {
        if (hitType == 3) {
            if (*(s16 *)(hitObj + 0x46) == 0x605 &&
                *(u8 *)(p2 + hitType + 0xb2) == 0 &&
                *(u8 *)(p2 + hitType + 0xae) != 0 &&
                *(int *)(p2 + 0x88) == 0xc) {
                Obj_SetModelColorFadeRecursive(p1, 0x19, 0xc8, 0, 0, 1);
                *(u8 *)(p2 + hitType + 0xae) = *(u8 *)(p2 + hitType + 0xae) - 1;
                *(u8 *)(p2 + hitType + 0xb2) = 0xc8;
            }
        } else if (hitType >= 0 && hitType < 3) {
            if (*(u8 *)(p2 + hitType + 0xae) != 0 && *(u8 *)(p2 + hitType + 0xb2) == 0) {
                *(u8 *)(p2 + hitType + 0xae) = *(u8 *)(p2 + hitType + 0xae) - 1;
                *(u8 *)(p2 + hitType + 0xb2) = 6;
                if (*(u8 *)(p2 + hitType + 0xae) != 0)
                    Sfx_PlayFromObject(p1, 0x484);
                else
                    Sfx_PlayFromObject(p1, 0x485);
                switch (hitType) {
                case 0:
                    *(s16 *)(p2 + 0xa2) = -0xfa;
                    break;
                case 1:
                    *(s16 *)(p2 + 0xa2) = 0xfa;
                    break;
                case 2:
                    *(s16 *)(p2 + 0xa4) = -0xc8;
                    break;
                }
            }
        }
    }
    for (i = 0; i < 3; i++) {
        int state;
        int adjusted;
        int texIdx;
        int *tex;

        if (*(u8 *)(p2 + i + 0xae) != 0) {
            if (*(u8 *)(p2 + i + 0xb2) != 0)
                *(u8 *)(p2 + i + 0xb9) = 1;
            else
                *(u8 *)(p2 + i + 0xb9) = 0;
        } else {
            *(u8 *)(p2 + i + 0xb9) = 2;
        }
        state = *(u8 *)(p2 + i + 0xb9);
        adjusted = state;
        texIdx = (&lbl_803DC4C8)[i];
        if (texIdx < 2 && state == 1)
            adjusted = 0;
        tex = objFindTexture(p1, texIdx * 2, 0);
        *tex = adjusted << 8;
        if (texIdx == 2 && state == 1)
            state = 0;
        tex = objFindTexture(p1, texIdx * 2 + 1, 0);
        *tex = state << 8;
    }
}
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_803E6D50;

#pragma scheduling off
int fn_802242A8(int p1, int p2, int p3)
{
    f32 cy;
    f32 cx;
    int result;

    if ((s8)*(u8 *)(p1 + 0xad) == 1) {
        (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)) + 0x30))(
            *(u8 *)(p2 + 0x283), p2 + 0x27e, p2 + 0x280,
            *(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)));
        (*(void (**)(int, int, int, f32 *, f32 *, int))(*(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)) + 0x20))(
            p1, *(s16 *)(p2 + 0x27e), *(s16 *)(p2 + 0x280), &cy, &cx,
            *(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)));
    } else {
        (*(void (**)(int, int, int, int))(*(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)) + 0x4c))(
            *(u8 *)(p2 + 0x283), p2 + 0x27e, p2 + 0x280,
            *(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)));
        (*(void (**)(int, int, int, f32 *, f32 *, int))(*(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)) + 0x3c))(
            p1, *(s16 *)(p2 + 0x27e), *(s16 *)(p2 + 0x280), &cy, &cx,
            *(int *)(*(int *)(*(int *)(p2 + 0x268) + 0x68)));
    }
    if (*(f32 *)(p3 + 0xc) > cy + lbl_803E6D50 || *(f32 *)(p3 + 0xc) < cy - lbl_803E6D50)
        result = 1;
    else if (*(f32 *)(p3 + 0x14) > cx + lbl_803E6D50 || *(f32 *)(p3 + 0x14) < cx - lbl_803E6D50)
        result = 1;
    else
        result = 0;
    return result;
}
#pragma scheduling reset

extern f32 lbl_803E6ECC;
extern f32 lbl_803E6ED0;
extern f32 lbl_803E6F5C;
extern f32 lbl_803E6F64;
extern f32 lbl_803E6F70;
extern f32 lbl_803E6F74;
extern f32 lbl_803E6F78;
extern f32 lbl_803E6F7C;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6F88;
extern f32 lbl_803E6F8C;
extern f32 lbl_803E6F90;
extern f32 lbl_803E6F94;
extern f32 lbl_803E6F98;
extern f32 lbl_803E6F9C;
extern f32 lbl_803E6FA0;
extern f32 lbl_803E6FA4;
extern f32 lbl_803E6FA8;
extern f32 lbl_803E6FAC;
extern f32 lbl_803E6FB0;
extern f32 lbl_803E6FB4;
extern f32 lbl_803E6FB8;
extern f32 lbl_803E6FBC;

#pragma scheduling off
void fn_8022D308(int obj)
{
    int state = *(int *)(obj + 0xb8);
    f32 v7c = lbl_803E6F7C;
    f32 v74 = lbl_803E6F74;

    *(f32 *)(state + 0x54) = lbl_803E6F70;
    *(f32 *)(state + 0x60) = v74;
    *(f32 *)(state + 0x58) = lbl_803E6F78;
    *(f32 *)(state + 0x64) = v7c;
    *(f32 *)(state + 0x5c) = lbl_803E6F78;
    *(f32 *)(state + 0x68) = v7c;
    *(f32 *)(state + 0x78) = lbl_803E6F80;
    *(f32 *)(state + 0x84) = lbl_803E6F84;
    *(f32 *)(state + 0x6c) = lbl_803E6ED0;
    *(f32 *)(state + 0x348) = lbl_803E6F88;
    *(f32 *)(state + 0x34c) = v74;
    *(f32 *)(state + 0x35c) = lbl_803E6F8C;
    *(f32 *)(state + 0x360) = v7c;
    *(f32 *)(state + 0x370) = lbl_803E6F90;
    *(f32 *)(state + 0x374) = lbl_803E6F94;
    *(f32 *)(state + 0x384) = lbl_803E6F98;
    *(f32 *)(state + 0x388) = lbl_803E6F9C;
    *(f32 *)(state + 0x394) = lbl_803E6FA0;
    *(f32 *)(state + 0x390) = lbl_803E6FA4;
    *(f32 *)(state + 0x39c) = lbl_803E6FA8;
    *(u8 *)(state + 0x3fa) = 0x19;
    *(f32 *)(state + 0x3a4) = lbl_803E6FAC;
    *(f32 *)(state + 0x38) = lbl_803E6FB0;
    *(f32 *)(state + 0x3ac) = lbl_803E6FB4;
    *(f32 *)(state + 0x3b0) = lbl_803E6FB8;
    *(f32 *)(state + 0x88) = lbl_803E6FBC;
    *(f32 *)(state + 0x8c) = lbl_803E6F64;
    *(f32 *)(state + 0x9c) = *(f32 *)(state + 0xa0);
    *(f32 *)(state + 0xa4) = *(f32 *)(state + 0xa8);
    *(f32 *)(state + 0xac) = lbl_803E6F5C;
    *(f32 *)(state + 0xb0) = lbl_803E6F5C;
    *(f32 *)(state + 0x48) = lbl_803E6ECC;
    *(f32 *)(state + 0x4c) = lbl_803E6ECC;
    *(f32 *)(state + 0x50) = lbl_803E6ECC;
    *(u8 *)(state + 0x404) = 0;
    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x14);
    *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x18);
    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x1c);
    *(int *)(state + 0x358) = 0;
    *(int *)(state + 0x36c) = 0;
    *(s16 *)(obj + 0) = 0;
    *(s16 *)(obj + 2) = 0;
    *(s16 *)(obj + 4) = 0;
    arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
}
#pragma scheduling reset

extern f32 lbl_803E7040;
extern f32 lbl_803E7048;

#pragma scheduling off
void arwarwingbo_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int arwing = getArwing();

    if (*(u16 *)(arwing + 0xb0) & 0x1000) {
        fn_8022D4F8(arwing);
        Obj_FreeObject(obj);
        return;
    }
    if (*(f32 *)(state + 8) > lbl_803E7044) {
        *(f32 *)(state + 8) -= timeDelta;
        if (*(f32 *)(state + 8) <= lbl_803E7044)
            Obj_FreeObject(obj);
        return;
    }
    if (*(f32 *)(state + 0) > lbl_803E7044) {
        *(f32 *)(state + 0) -= timeDelta;
        if (*(f32 *)(state + 0) <= lbl_803E7044) {
            state = *(int *)(obj + 0xb8);
            fn_8022D4F8(getArwing());
            Sfx_PlayFromObject(obj, 0x2a5);
            *(f32 *)(state + 8) = lbl_803E7040;
            *(f32 *)(state + 0) = lbl_803E7044;
            *(u8 *)(obj + 0x36) = 0;
            *(s16 *)(*(int *)(obj + 0x54) + 0x60) &= ~0x200;
            spawnExplosion(obj, lbl_803E7048, 1, 0, 1, 1, 0, 1, 0);
            ObjHitbox_SetSphereRadius(obj, 0x280);
            ObjHits_SetHitVolumeSlot(obj, 5, 5, 0);
            *(f32 *)(obj + 0x24) = lbl_803E7044;
            *(f32 *)(obj + 0x28) = lbl_803E7044;
            *(f32 *)(obj + 0x2c) = lbl_803E7044;
        }
        (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(obj, 0x79e, 0, 1, -1, obj + 0x24);
        (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(obj, 0x79e, 0, 1, -1, obj + 0x24);
        ObjHits_SetHitVolumeSlot(obj, 0xf, 0, 0);
        if (*(void **)(*(int *)(obj + 0x54) + 0x50) != NULL ||
            (s8)*(u8 *)(*(int *)(obj + 0x54) + 0xad) != 0 ||
            (getButtonsJustPressed(0) & 0x200)) {
            state = *(int *)(obj + 0xb8);
            fn_8022D4F8(getArwing());
            Sfx_PlayFromObject(obj, 0x2a5);
            *(f32 *)(state + 8) = lbl_803E7040;
            *(f32 *)(state + 0) = lbl_803E7044;
            *(u8 *)(obj + 0x36) = 0;
            *(s16 *)(*(int *)(obj + 0x54) + 0x60) &= ~0x200;
            spawnExplosion(obj, lbl_803E7048, 1, 0, 1, 1, 0, 1, 0);
            ObjHitbox_SetSphereRadius(obj, 0x280);
            ObjHits_SetHitVolumeSlot(obj, 5, 5, 0);
            *(f32 *)(obj + 0x24) = lbl_803E7044;
            *(f32 *)(obj + 0x28) = lbl_803E7044;
            *(f32 *)(obj + 0x2c) = lbl_803E7044;
        }
        objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
                *(f32 *)(obj + 0x2c) * timeDelta);
    }
}
#pragma scheduling reset

extern f32 lbl_803E6EF0;
extern f32 lbl_803E6EF4;

#pragma dont_inline on
#pragma scheduling off
void fn_8022A9C8(int obj, int state)
{
    int slot;
    f32 mtx[12];
    ArwProjPosSrc src;

    slot = Camera_GetCurrentViewSlot();
    src.pos[0] = *(f32 *)(obj + 0xc);
    src.pos[1] = *(f32 *)(obj + 0x10);
    src.pos[2] = *(f32 *)(obj + 0x14);
    src.rot[0] = *(s16 *)obj;
    src.rot[1] = *(s16 *)(obj + 2);
    src.rot[2] = 0;
    src.scale = lbl_803E6ED0;
    setMatrixFromObjectPos(mtx, &src);

    Matrix_TransformPoint(mtx, lbl_803E6ECC, lbl_803E6ECC, lbl_803E6EF0,
                          (f32 *)(*(int *)(state + 0x418) + 0xc),
                          (f32 *)(*(int *)(state + 0x418) + 0x10),
                          (f32 *)(*(int *)(state + 0x418) + 0x14));
    *(f32 *)(*(int *)(state + 0x418) + 0x18) = *(f32 *)(*(int *)(state + 0x418) + 0xc);
    *(f32 *)(*(int *)(state + 0x418) + 0x1c) = *(f32 *)(*(int *)(state + 0x418) + 0x10);
    *(f32 *)(*(int *)(state + 0x418) + 0x20) = *(f32 *)(*(int *)(state + 0x418) + 0x14);
    *(s16 *)(*(int *)(state + 0x418) + 4) = -*(s16 *)(slot + 4);
    *(s16 *)(*(int *)(state + 0x418) + 2) = -*(s16 *)(slot + 2);
    *(s16 *)(*(int *)(state + 0x418) + 0) = 0x8000 - *(s16 *)slot;

    Matrix_TransformPoint(mtx, lbl_803E6ECC, lbl_803E6ECC, lbl_803E6EF4,
                          (f32 *)(*(int *)(state + 0x41c) + 0xc),
                          (f32 *)(*(int *)(state + 0x41c) + 0x10),
                          (f32 *)(*(int *)(state + 0x41c) + 0x14));
    *(f32 *)(*(int *)(state + 0x41c) + 0x18) = *(f32 *)(*(int *)(state + 0x41c) + 0xc);
    *(f32 *)(*(int *)(state + 0x41c) + 0x1c) = *(f32 *)(*(int *)(state + 0x41c) + 0x10);
    *(f32 *)(*(int *)(state + 0x41c) + 0x20) = *(f32 *)(*(int *)(state + 0x41c) + 0x14);
    *(s16 *)(*(int *)(state + 0x41c) + 4) = -*(s16 *)(slot + 4);
    *(s16 *)(*(int *)(state + 0x41c) + 2) = -*(s16 *)(slot + 2);
    *(s16 *)(*(int *)(state + 0x41c) + 0) = 0x8000 - *(s16 *)slot;
}
#pragma scheduling reset
#pragma dont_inline reset

extern int *gPathControlInterface;
extern f32 lbl_803E6F24;
extern f32 lbl_803E6F28;
extern f32 lbl_803E6F2C;
extern f32 lbl_803E6F30;
extern f32 lbl_803E6F34;
extern f32 lbl_803E6F38;
extern f32 lbl_803E6F3C;
extern f32 lbl_803E6F40;

#pragma scheduling off
void fn_8022BE14(int obj, int state)
{
    int sub = state + 0xc0;
    int dmg;

    (*(void (**)(int, int, f32))(*gPathControlInterface + 0x10))(obj, sub, timeDelta);
    (*(void (**)(int, int))(*gPathControlInterface + 0x14))(obj, sub);
    (*(void (**)(int, int, f32))(*gPathControlInterface + 0x18))(obj, sub, timeDelta);

    if (*(u8 *)(state + 0x338) == 0 || *(u8 *)(state + 0x478) == 4) {
        dmg = (s8)*(u8 *)(sub + 0x260);
        if (dmg == 0)
            return;
        if (*(u8 *)(state + 0x478) == 4) {
            *(u8 *)(state + 0x478) = 5;
            *(f32 *)(state + 0x46c) = lbl_803E6F24;
            *(s16 *)(obj + 6) |= 0x4000;
            spawnExplosion(obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
            return;
        }
        if ((dmg & 1) && (s8)*(u8 *)(sub + 0xb8) == 8)
            *(u8 *)(state + 0x468) = 0;
        else
            *(u8 *)(state + 0x468) = *(u8 *)(state + 0x468) - 1;
        doRumble(lbl_803E6F2C);
        if ((s8)*(u8 *)(state + 0x468) <= 0) {
            arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
            if ((s8)*(u8 *)(obj + 0xac) == 0x26)
                GameBit_Set(0xe74, 1);
            else
                *(u8 *)(state + 0x478) = 4;
            *(f32 *)(state + 0x46c) = lbl_803E6F30;
            Sfx_PlayFromObject(obj, 0x380);
            Music_Trigger(0xd6, 1);
        } else if ((s8)*(u8 *)(*(int *)(obj + 0xb8) + 0x468) <= 3) {
            Sfx_KeepAliveLoopedObjectSound(obj, 0x37f);
        }
        Sfx_PlayFromObject(obj, 0x2a0);
        *(u8 *)(state + 0x339) |= 0x80;
        Obj_SetModelColorFadeRecursive(obj, 0x4b, 0xc8, 0, 0, 1);
        *(f32 *)(state + 0x328) = lbl_803E6F34;
        *(u8 *)(state + 0x338) = 1;
        *(s16 *)(state + 0x33a) = 0;
        *(s16 *)(state + 0x33c) = 0;
        *(f32 *)(state + 0x32c) = *(f32 *)(sub + 0x1a0);
        *(f32 *)(state + 0x330) = *(f32 *)(sub + 0x1a4);
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E6F38);
    } else {
        *(s16 *)(state + 0x33a) = lbl_803E6F3C * timeDelta + (f32)*(u16 *)(state + 0x33a);
        *(s16 *)(state + 0x33c) = lbl_803E6F40 * timeDelta + (f32)*(u16 *)(state + 0x33c);
    }
}
#pragma scheduling reset

extern int objGetFlagsE5_2(int obj);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int idx, int p2);
extern int loadMapAndParent(int mapId);

#pragma scheduling off
void fn_8022C0D0(int obj, int state)
{
    int hitVol;
    int hitObj;

    if (objGetFlagsE5_2(obj) != 0)
        return;
    if (ObjHits_GetPriorityHit(obj, &hitObj, 0, &hitVol) != 0 && hitVol != 0) {
        if (*(u8 *)(state + 0x478) == 4) {
            *(u8 *)(state + 0x478) = 5;
            *(f32 *)(state + 0x46c) = lbl_803E6F24;
            *(s16 *)(obj + 6) |= 0x4000;
            spawnExplosion(obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
        } else {
            if (*(s16 *)(hitObj + 0x46) == 0x6ae && *(u8 *)(state + 0x478) == 1) {
                Sfx_PlayFromObject(obj, 0x2c0);
                return;
            }
            doRumble(lbl_803E6F2C);
            *(u8 *)(state + 0x468) = *(u8 *)(state + 0x468) - hitVol;
            Sfx_PlayFromObject(obj, 0x2ac);
            *(u8 *)(state + 0x339) |= 0x80;
            Obj_SetModelColorFadeRecursive(obj, 0x4b, 0xc8, 0, 0, 1);
            *(f32 *)(state + 0x328) = lbl_803E6F34;
            *(u8 *)(state + 0x338) = 1;
            *(s16 *)(state + 0x33a) = 0;
            *(s16 *)(state + 0x33c) = 0;
            *(f32 *)(state + 0x32c) = lbl_803E6ECC;
            *(f32 *)(state + 0x330) = lbl_803E6ECC;
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E6F2C);
        }
    }
    if (*(u8 *)(state + 0x478) != 4 && *(u8 *)(state + 0x478) != 5 &&
        *(u8 *)(state + 0x478) != 6 && (s8)*(u8 *)(state + 0x468) <= 0) {
        arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
        if ((s8)*(u8 *)(obj + 0xac) == 0x26)
            GameBit_Set(0xe74, 1);
        *(u8 *)(state + 0x478) = 4;
        *(f32 *)(state + 0x46c) = lbl_803E6F30;
        Sfx_PlayFromObject(obj, 0x380);
        Music_Trigger(0xd6, 1);
        unlockLevel(0, 0, 1);
        loadMapAndParent(0x29);
        lockLevel(mapGetDirIdx(0x29), 0);
    } else if ((s8)*(u8 *)(*(int *)(obj + 0xb8) + 0x468) <= 3) {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x37f);
    }
}
#pragma scheduling reset

extern int lbl_803DDDD0;
extern int lbl_803DC50C;
extern int lbl_803DC510;

#pragma peephole off
#pragma scheduling off
void androsshand_spawnShot(int p1, int p2)
{
    f32 pt[3];
    f32 dx, dz, dist;
    int yaw;
    int newObj;
    int proj;

    if (Obj_IsLoadingLocked()) {
        ObjPath_GetPointWorldPosition(p1, 0, &pt[0], &pt[1], &pt[2], 0);
        dx = pt[0] - *(f32 *)(*(int *)(p2 + 4) + 0xc);
        dz = pt[2] - *(f32 *)(*(int *)(p2 + 4) + 0x14);
        dist = sqrtf(dx * dx + dz * dz);
        yaw = (u16)getAngle(dx, dz) + 0x8000;
        lbl_803DDDD0 = (u16)getAngle(pt[1] - *(f32 *)(*(int *)(p2 + 4) + 0x10), dist) >> 8;
        newObj = Obj_AllocObjectSetup(0x20, 0x7e4);
        *(f32 *)(newObj + 8) = pt[0];
        *(f32 *)(newObj + 0xc) = pt[1];
        *(f32 *)(newObj + 0x10) = pt[2];
        *(u8 *)(newObj + 0x1a) = (*(s16 *)p1 + yaw) >> 8;
        *(u8 *)(newObj + 0x19) = lbl_803DDDD0;
        *(u8 *)(newObj + 0x18) = 0;
        *(u8 *)(newObj + 4) = 1;
        *(u8 *)(newObj + 5) = 1;
        proj = ((int (*)(int, int))loadObjectAtObject)(p1, newObj);
        if (proj != 0) {
            arwprojectile_setLifetime(proj, lbl_803DC510);
            arwprojectile_placeForward(proj, (f32)(u32)lbl_803DC50C);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

extern void mapUnload(int a, int b);
extern void setLoadedFileFlags_blocks1(void);
extern void clearLoadedFileFlags_blocks1(void);
extern void registerNewScore(int a, int b, int c, int d);
extern u8 lbl_803DC3C8[8];
typedef struct { u8 scoreFlag : 1; } Arw339Flags;

#pragma scheduling off
int fn_8022C7B4(int obj, int p2, int script)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    Camera_GetCurrentViewSlot();
    *(int *)(script + 0xe8) = (int)fn_8022C7A4;
    if ((*(u8 *)(state + 0x477) & 1) == 0) {
        fn_8022CDEC(obj, state);
        return 0;
    }
    fn_8022C30C(obj, state);
    fn_8022A9C8(obj, state);
    if (*(int *)(state + 0x10) != 0)
        arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
    *(s16 *)(*(int *)(state + 0x418) + 6) |= 0x4000;
    *(u8 *)(*(int *)(state + 0x418) + 0x36) = 0;
    *(s16 *)(*(int *)(state + 0x41c) + 6) |= 0x4000;
    *(u8 *)(*(int *)(state + 0x41c) + 0x36) = 0;
    *(s16 *)(obj + 6) &= ~0x4000;

    for (i = 0; i < *(u8 *)(script + 0x8b); i++) {
        switch (*(u8 *)(script + i + 0x81)) {
        case 8: {
            int cam = Camera_GetCurrentViewSlot();
            *(f32 *)(state + 0x484) = *(f32 *)(cam + 0xc) - *(f32 *)(obj + 0xc);
            *(f32 *)(state + 0x488) = *(f32 *)(cam + 0x10) - *(f32 *)(obj + 0x10);
            *(f32 *)(state + 0x48c) = *(f32 *)(cam + 0x14) - *(f32 *)(obj + 0x14);
            *(s16 *)(state + 0x490) = *(s16 *)(obj + 0) - (u16)*(s16 *)(cam + 0);
            if (*(s16 *)(state + 0x490) > 32768)
                *(s16 *)(state + 0x490) -= 65535;
            if (*(s16 *)(state + 0x490) < -32768)
                *(s16 *)(state + 0x490) += 65535;
            *(s16 *)(state + 0x492) = *(s16 *)(obj + 2) - (u16)*(s16 *)(cam + 2);
            if (*(s16 *)(state + 0x492) > 32768)
                *(s16 *)(state + 0x492) -= 65535;
            if (*(s16 *)(state + 0x492) < -32768)
                *(s16 *)(state + 0x492) += 65535;
            *(s16 *)(state + 0x494) = *(s16 *)(cam + 4) - *(s16 *)(obj + 4);
            *(u8 *)(state + 0x47f) = 1;
            break;
        }
        case 9:
            *(u8 *)(state + 0x47f) = 0;
            break;
        case 1:
            clearLoadedFileFlags_blocks1();
            warpToMap(0x60, 0);
            break;
        case 2:
            clearLoadedFileFlags_blocks1();
            fn_8022C680(obj);
            break;
        case 0xa:
            if (Obj_IsLoadingLocked()) {
                int setup = Obj_AllocObjectSetup(0x24, 0x608);
                int o;
                *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc);
                *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
                *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
                *(u8 *)(setup + 4) = 1;
                *(u8 *)(setup + 5) = 1;
                o = loadObjectAtObject(obj);
                if (o != 0)
                    fn_8022F558(o, 0x12c);
            }
            break;
        case 0xb:
            *(u8 *)(state + 0x44c) = 1;
            fn_8022B764(obj, state, *(u8 *)(state + 0x43d));
            *(u8 *)(state + 0x43d) ^= 1;
            break;
        case 0xc:
            arwarwing_spawnLaserShot(obj, state, 0, 1, 1);
            arwarwing_spawnLaserShot(obj, state, 1, 1, 0);
            break;
        case 4:
            unlockLevel(0, 0, 1);
            mapUnload(0, 0x80000000);
            setLoadedFileFlags_blocks1();
            break;
        case 5:
            if (*(u8 *)(state + 0x47b) == 0 && GameBit_Get(0xc85)) {
                loadMapAndParent(0xb);
                lockLevel(mapGetDirIdx(0xb), 0);
            } else {
                loadMapAndParent(lbl_803DC3C8[*(u8 *)(state + 0x47b)]);
                lockLevel(mapGetDirIdx(lbl_803DC3C8[*(u8 *)(state + 0x47b)]), 0);
            }
            switch ((s8)*(u8 *)(obj + 0xac)) {
            case 0x3b:
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0x13, 0, 1);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0x13, 0x16, 1);
                break;
            case 0x3d:
                GameBit_Set(0x36a, 0);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xd, 0, 1);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xd, 1, 1);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xd, 5, 1);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xd, 0xa, 1);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xd, 0xb, 1);
                GameBit_Set(0xe05, 0);
                break;
            case 0x3c:
                GameBit_Set(0x458, 0);
                GameBit_Set(0x47c, 0);
                GameBit_Set(0x4a3, 0);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(0xc, 0, 1);
                GameBit_Set(0xd73, 0);
                break;
            case 0x3e:
                GameBit_Set(0x5db, 0);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(2, 0xf, 1);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(2, 0x10, 1);
                GameBit_Set(0xe7b, 0);
                GameBit_Set(0x9e9, 0);
                break;
            }
            break;
        case 6:
            unlockLevel(0, 0, 1);
            loadMapAndParent(0x29);
            lockLevel(mapGetDirIdx(0x29), 0);
            break;
        case 7:
            if (!((Arw339Flags *)(state + 0x339))->scoreFlag) {
                int s2 = *(int *)(obj + 0xb8);
                *(u16 *)(s2 + 0x47c) = *(u16 *)(s2 + 0x47c) + 0xc8;
                if (*(u16 *)(s2 + 0x47c) > 0x270f)
                    *(u16 *)(s2 + 0x47c) = 0x270f;
            }
            registerNewScore((s8)*(u8 *)(state + 0x47e), *(u16 *)(state + 0x47c),
                             *(u8 *)(state + 0x470), 2);
            break;
        case 0xd:
            gameTextFn_80125ba4(0x13);
            break;
        case 0xe:
            gameTextFn_80125ba4(0x14);
            break;
        }
    }
    return 0;
}
#pragma scheduling reset

typedef struct { int a; int b; u16 c; } ArwInitCfg;
extern ArwInitCfg lbl_802C25E8;
extern int lbl_8032B408[];
extern int lbl_8032B480[];

#pragma scheduling off
void arwarwing_init(int obj)
{
    int state;
    int sub;
    ArwInitCfg cfg;

    cfg.a = lbl_802C25E8.a;
    cfg.b = lbl_802C25E8.b;
    cfg.c = lbl_802C25E8.c;
    state = *(int *)(obj + 0xb8);
    sub = state + 0xc0;
    *(int *)(obj + 0xbc) = (int)fn_8022C7B4;
    (*(void (**)(int, int, int, int))(*gPathControlInterface + 4))(sub, 4, 0x1040006, 1);
    (*(void (**)(int, int, void *, void *, void *))(*gPathControlInterface + 0xc))(sub, 3, lbl_8032B408, lbl_8032B480, &cfg);
    (*(void (**)(int, int))(*gPathControlInterface + 0x20))(obj, sub);
    ObjGroup_AddObject(obj, 0x26);
    lbl_803DDD88 = obj;
    ObjHits_SetTargetMask(obj, 1);
    *(u8 *)(state + 0x480) = 1;
    switch ((s8)*(u8 *)(obj + 0xac) - 0x26) {
    case 27:
    default:
        *(u8 *)(state + 0x480) = 0;
        break;
    case 20:
        *(u8 *)(state + 0x47b) = 0;
        *(u8 *)(state + 0x471) = 1;
        *(u8 *)(state + 0x47e) = 0;
        break;
    case 21:
        *(u8 *)(state + 0x47b) = 1;
        *(u8 *)(state + 0x471) = 3;
        *(u8 *)(state + 0x47e) = 1;
        break;
    case 23:
        *(u8 *)(state + 0x47b) = 2;
        *(u8 *)(state + 0x471) = 7;
        *(u8 *)(state + 0x47e) = 3;
        break;
    case 22:
        *(u8 *)(state + 0x47b) = 3;
        *(u8 *)(state + 0x471) = 5;
        *(u8 *)(state + 0x47e) = 2;
        break;
    case 24:
        *(u8 *)(state + 0x47b) = 4;
        *(u8 *)(state + 0x471) = 0xa;
        *(u8 *)(state + 0x47e) = 4;
        break;
    case 0:
        break;
    }
}
#pragma scheduling reset

extern f32 PSVECMag(f32 *v);
extern void PSVECNormalize(void *src, void *dst);
extern void PSVECCrossProduct(f32 *a, f32 *b, f32 *out);
extern f32 PSVECDotProduct(f32 *a, f32 *b);
extern void PSMTXRotAxisRad(f32 *mtx, f32 *axis, f32 angle);
extern void PSMTXMultVecSR(f32 *mtx, f32 *in, f32 *out);
extern f32 fn_80291FF4(f32 x);
extern f32 lbl_803E6C38;
extern f32 lbl_803E6C6C;
extern f32 lbl_803E6C70;
extern f32 lbl_803E6C74;

#pragma scheduling off
void fn_80221F14(int out, f32 *v1, f32 *v2, f32 a, f32 b, f32 c)
{
    f32 mtx[12];
    f32 n1[3];
    f32 n2[3];
    f32 cross[3];
    f32 mag1, mag2, t, ang;

    mag1 = PSVECMag(v1);
    if (mag1 > lbl_803E6C38) {
        t = lbl_803E6C6C / mag1;
        n1[0] = v1[0] * t;
        n1[1] = v1[1] * t;
        n1[2] = v1[2] * t;
        PSVECNormalize(n1, n1);
    } else {
        n1[0] = lbl_803E6C38;
        n1[1] = lbl_803E6C38;
        n1[2] = lbl_803E6C38;
    }
    mag2 = PSVECMag(v2);
    if (mag2 > lbl_803E6C38) {
        t = lbl_803E6C6C / mag2;
        n2[0] = v2[0] * t;
        n2[1] = v2[1] * t;
        n2[2] = v2[2] * t;
    } else {
        n2[0] = lbl_803E6C38;
        n2[1] = lbl_803E6C38;
        n2[2] = lbl_803E6C38;
    }
    PSVECCrossProduct(n1, n2, cross);
    if (PSVECMag(cross) > lbl_803E6C38) {
        ang = fn_80291FF4(PSVECDotProduct(n1, n2));
        if (ang > c) {
            PSMTXRotAxisRad(mtx, cross, c * (ang > lbl_803E6C38 ? lbl_803E6C6C : lbl_803E6C70));
            PSMTXMultVecSR2(mtx, n1, n2);
        }
    }
    t = mag2 * lbl_803E6C74;
    if (t > mag1 + b)
        t = mag1 + b;
    else if (t < mag1 - b)
        t = mag1 - b;
    if (t > a)
        t = a;
    *(f32 *)(out + 0x24) = n2[0] * t;
    *(f32 *)(out + 0x28) = n2[1] * t;
    *(f32 *)(out + 0x2c) = n2[2] * t;
}
#pragma scheduling reset

extern f32 lbl_803E6C60;
extern f32 lbl_803E6C64;
extern f32 lbl_803E6C78;
extern f32 lbl_803E6C7C;
extern f32 lbl_803E6C80;

#pragma dont_inline on
#pragma scheduling off
int fn_80222358(int p1, int p2, f32 a, f32 b, f32 c, int flag)
{
    f32 d[3];
    f32 dist, ang, scale;
    int result;

    result = 0;
    scale = c;
    d[0] = *(f32 *)(p1 + 0xc) - *(f32 *)(p2 + 0x68);
    d[2] = *(f32 *)(p1 + 0x14) - *(f32 *)(p2 + 0x70);
    dist = sqrtf(d[0] * d[0] + d[2] * d[2]);
    if (dist < b) {
        if (curveFn_80010320(p2, a) != 0 || *(int *)(p2 + 0x10) != 0) {
            if ((u8)(*(int (**)(int))(*gRomCurveInterface + 0x90))(p2) != 0)
                result = -1;
            else
                result = (s8)*(u8 *)(*(int *)(p2 + 0x9c) + 0x18);
        }
        scale = lbl_803E6C78 * a;
    }
    d[0] = *(f32 *)(p2 + 0x68) - *(f32 *)(p1 + 0xc);
    d[1] = *(f32 *)(p2 + 0x6c) - *(f32 *)(p1 + 0x10);
    d[2] = *(f32 *)(p2 + 0x70) - *(f32 *)(p1 + 0x14);
    if (flag == 0) {
        int state2 = *(int *)(p1 + 0xb8);
        d[0] = *(f32 *)(p1 + 0xc) - *(f32 *)(p2 + 0x68);
        d[2] = *(f32 *)(p1 + 0x14) - *(f32 *)(p2 + 0x70);
        ang = lbl_803E6C60 * (f32)(-(s16)getAngle(d[0], d[2])) / lbl_803E6C64;
        *(f32 *)(state2 + 0x290) = scale * -fn_80293E80(ang);
        *(f32 *)(state2 + 0x28c) = scale * -sin(ang);
    } else {
        fn_80221F14(p1, (f32 *)(p1 + 0x24), d, scale, scale / lbl_803E6C7C, lbl_803E6C80);
    }
    return result;
}
#pragma scheduling reset
#pragma dont_inline reset

#pragma scheduling off
int fn_80222160(int p1, int p2, f32 a, f32 b, f32 c, int flag, int *p6)
{
    f32 d[3];
    f32 dist, ang, scale;
    int result;

    result = 0;
    scale = c;
    d[0] = *(f32 *)(p1 + 0xc) - *(f32 *)(p2 + 0x68);
    d[2] = *(f32 *)(p1 + 0x14) - *(f32 *)(p2 + 0x70);
    dist = sqrtf(d[0] * d[0] + d[2] * d[2]);
    if (dist < b) {
        if (curveFn_80010320(p2, a) != 0 || *(int *)(p2 + 0x10) != 0) {
            if ((u8)(*(int (**)(int, int))(*gRomCurveInterface + 0x9c))(p2, *p6) != 0)
                result = -1;
            else
                result = (s8)*(u8 *)(*(int *)(p2 + 0x9c) + 0x18);
            *p6 = 0;
        }
        scale = lbl_803E6C78 * a;
    }
    d[0] = *(f32 *)(p2 + 0x68) - *(f32 *)(p1 + 0xc);
    d[1] = *(f32 *)(p2 + 0x6c) - *(f32 *)(p1 + 0x10);
    d[2] = *(f32 *)(p2 + 0x70) - *(f32 *)(p1 + 0x14);
    if (flag == 0) {
        int state2 = *(int *)(p1 + 0xb8);
        d[0] = *(f32 *)(p1 + 0xc) - *(f32 *)(p2 + 0x68);
        d[2] = *(f32 *)(p1 + 0x14) - *(f32 *)(p2 + 0x70);
        ang = lbl_803E6C60 * (f32)(-(s16)getAngle(d[0], d[2])) / lbl_803E6C64;
        *(f32 *)(state2 + 0x290) = scale * -fn_80293E80(ang);
        *(f32 *)(state2 + 0x28c) = scale * -sin(ang);
    } else {
        fn_80221F14(p1, (f32 *)(p1 + 0x24), d, scale, scale / lbl_803E6C7C, lbl_803E6C80);
    }
    return result;
}
#pragma scheduling reset
#pragma dont_inline reset

typedef struct {
    u8 f80 : 1;
    u8 f40 : 1;
    u8 f20 : 1;
    u8 f10 : 1;
    u8 f08 : 1;
    u8 : 3;
} SquadCmdFlags;
extern f32 lbl_803E716C;
extern f32 lbl_803E7170;

#pragma dont_inline on
#pragma scheduling off
void arwsquadron_applyCommandParams(int p1, int p2)
{
    SquadCmdFlags *flags = (SquadCmdFlags *)(p2 + 0x160);
    int cmds = *(int *)(p2 + 0x9c);
    int i;

    if ((s8)*(u8 *)(cmds + 0x19) == 0x28) {
        for (i = 0; i < 2; i++) {
            int cmd;
            f32 val;
            if (i == 0) {
                cmd = *(u8 *)(cmds + 0x18);
                val = (f32)(s8)*(u8 *)(cmds + 0x1a);
            } else {
                cmd = *(u8 *)(cmds + 0x2f);
                val = (f32)*(u8 *)(cmds + 0x30);
            }
            switch ((u8)cmd) {
            case 3:
                *(f32 *)(p2 + 0x10c) = val * lbl_803E716C;
                break;
            case 1:
                if (!flags->f80) {
                    int s = *(int *)(p1 + 0x4c);
                    flags->f80 = 1;
                    if (*(u8 *)(p2 + 0x15c) == 1) {
                        flags->f20 = 0;
                        storeZeroToFloatParam((void *)(p2 + 0x124));
                        s16toFloat((void *)(p2 + 0x124), *(u8 *)(s + 0x2c));
                    }
                }
                break;
            case 2:
                flags->f80 = 0;
                break;
            case 4:
                if (!flags->f08) {
                    flags->f08 = 1;
                    *(s16 *)(p2 + 0x144) = lbl_803E7170 * val;
                }
                break;
            case 5:
                flags->f08 = 0;
                break;
            }
        }
    }
}
#pragma scheduling reset

extern void fn_80222550(int a, int b, int c, f32 d, f32 e);
extern f32 lbl_803E7168;
extern f32 lbl_803E719C;
extern f32 lbl_803E71A0;
extern f32 lbl_803E71A4;

#pragma scheduling off
void arwsquadron_followPath(int p1, int p2)
{
    int state = *(int *)(p1 + 0x4c);
    int r;

    r = fn_80222358(p1, p2, *(f32 *)(p2 + 0x108), lbl_803E719C, *(f32 *)(p2 + 0x108), 1);
    if (r == -1) {
        *(s16 *)(p1 + 6) |= 0x4000;
        ObjHits_DisableObject(p1);
        *(u8 *)(p2 + 0x159) = 4;
    } else {
        if (r != 0)
            arwsquadron_applyCommandParams(p1, p2);
        if (*(u8 *)(state + 0x2f) == 2) {
            if (*(u8 *)(p2 + 0x15c) == 2)
                fn_80222550(p1, p1 + 0x24, 0xf, lbl_803E71A0, lbl_803E7188);
            else
                fn_80222550(p1, p1 + 0x24, 0xf,
                            ((SquadCmdFlags *)(p2 + 0x160))->f08 ? lbl_803E7168 : lbl_803E71A0,
                            lbl_803E7188);
        }
        *(f32 *)(p2 + 0x108) += interpolate(*(f32 *)(p2 + 0x10c) - *(f32 *)(p2 + 0x108),
                                            lbl_803E71A4, timeDelta);
        objMove(p1, *(f32 *)(p1 + 0x24) * timeDelta, *(f32 *)(p1 + 0x28) * timeDelta,
                *(f32 *)(p1 + 0x2c) * timeDelta);
    }
}
#pragma scheduling reset

#pragma scheduling off
void arwsquadron_updateVolley(int p1, int p2, int p3)
{
    SquadCmdFlags *flags = (SquadCmdFlags *)(p2 + 0x160);

    if (!flags->f20) {
        if (timerCountDown((void *)(p2 + 0x124)) != 0) {
            flags->f20 = 1;
            storeZeroToFloatParam((void *)(p2 + 0x128));
            s16toFloat((void *)(p2 + 0x128), *(u8 *)(p3 + 0x2d));
            *(u8 *)(p2 + 0x155) = (s8)*(u8 *)(p3 + 0x2e);
            *(s16 *)(p2 + 0x14e) = -*(u16 *)(p3 + 0x2a);
        }
    } else if (timerCountDown((void *)(p2 + 0x128)) != 0) {
        arwsquadron_spawnProjectile(p1, 0, *(s16 *)(p2 + 0x14e),
                                    (s8)*(u8 *)(p2 + 0x155) == *(u8 *)(p3 + 0x2e) ? 1 : 0);
        if (*(u8 *)(p2 + 0x15b) > 1)
            arwsquadron_spawnProjectile(p1, 1, *(s16 *)(p2 + 0x14e), 0);
        *(u8 *)(p2 + 0x155) = *(u8 *)(p2 + 0x155) - 1;
        storeZeroToFloatParam((void *)(p2 + 0x128));
        s16toFloat((void *)(p2 + 0x128), *(u8 *)(p3 + 0x2d));
        *(s16 *)(p2 + 0x14e) = *(s16 *)(p2 + 0x14e) + *(u16 *)(p3 + 0x2a) * 2 / *(u8 *)(p3 + 0x2e);
        if ((s8)*(u8 *)(p2 + 0x155) <= 0) {
            flags->f20 = 0;
            storeZeroToFloatParam((void *)(p2 + 0x124));
            s16toFloat((void *)(p2 + 0x124), *(u8 *)(p3 + 0x2c));
        }
    }
}
#pragma scheduling reset

extern void ObjPath_GetPointLocalPosition(int obj, int idx, f32 *x, f32 *y, f32 *z);

typedef struct {
    s16 s0, s2, s4, s6;
    f32 f8;
    f32 fx, fy, fz;
} SquadPfx;

#pragma scheduling off
void arwsquadron_emitEffects(int p1, int p2)
{
    u8 flag = 1;
    SquadPfx pfx;

    if ((s8)*(u8 *)(p2 + 0x15e) <= 2) {
        int cnt = *(u8 *)(p2 + 0x15f);
        *(u8 *)(p2 + 0x15f) = cnt + 1;
        if (cnt % 2 != 0) {
            ObjPath_GetPointLocalPosition(p2, 4, &pfx.fx, &pfx.fy, &pfx.fz);
            pfx.f8 = *(f32 *)(p2 + 0x11c);
            pfx.s6 = ((s8)*(u8 *)(p2 + 0x15e) <= 1) ? 0x61a8 : -0x63c0;
            (*(void (**)(int, int, void *, int, int, void *))(*gPartfxInterface + 8))(
                p1, 0x7d0, &pfx, 4, -1, &flag);
        }
    }
    if ((s8)*(u8 *)(p2 + 0x15e) <= 1) {
        pfx.s6 = 0xc0a;
        ObjPath_GetPointLocalPosition(p2, 5, &pfx.fx, &pfx.fy, &pfx.fz);
        pfx.f8 = *(f32 *)(p2 + 0x120);
        (*(void (**)(int, int, void *, int, int, void *))(*gPartfxInterface + 8))(
            p1, 0x7d1, &pfx, 4, -1, &flag);
    }
    if (*(u8 *)(p2 + 0x15a) != 0 && (s8)*(u8 *)(p2 + 0x15e) > 1) {
        pfx.s0 = 0;
        pfx.s2 = 0;
        pfx.s4 = 0;
        pfx.f8 = lbl_803E7168;
        ObjPath_GetPointLocalPosition(p2, 2, &pfx.fx, &pfx.fy, &pfx.fz);
        fn_8009837C(p1, *(f32 *)(p2 + 0x114), 2, 0, 0, *(f32 *)(p2 + 0x118), (int)&pfx);
    }
    if (*(u8 *)(p2 + 0x15a) > 1 && (s8)*(u8 *)(p2 + 0x15e) > 1) {
        ObjPath_GetPointLocalPosition(p2, 3, &pfx.fx, &pfx.fy, &pfx.fz);
        fn_8009837C(p1, *(f32 *)(p2 + 0x114), 2, 0, 0, *(f32 *)(p2 + 0x118), (int)&pfx);
    }
}
#pragma scheduling reset

extern f32 lbl_803E71AC;
extern f32 lbl_803E71B0;
extern f32 lbl_803E71B4;

#pragma scheduling off
void arwsquadron_handleDamage(int obj, int state)
{
    SquadCmdFlags *flags = (SquadCmdFlags *)(state + 0x160);
    int hitObj;
    int hitVol;
    int arwing;

    if (*(void **)(obj + 0x54) == NULL)
        return;
    if (*(u8 *)(state + 0x154) != 0) {
        *(f32 *)(state + 0x110) -= timeDelta;
        if (*(f32 *)(state + 0x110) <= lbl_803E7168)
            *(u8 *)(state + 0x154) = 0;
        if (flags->f10) {
            *(s16 *)(state + 0x150) = lbl_803E71AC * timeDelta + (f32)*(u16 *)(state + 0x150);
            *(s16 *)(state + 0x152) = lbl_803E71B0 * timeDelta + (f32)*(u16 *)(state + 0x152);
        }
    }
    if (ObjHits_GetPriorityHit(obj, &hitObj, 0, &hitVol) != 0 ||
        *(void **)(*(int *)(obj + 0x54) + 0x50) != NULL) {
        if (flags->f10) {
            if (*(u8 *)(state + 0x154) == 0)
                Sfx_PlayFromObjectLimited(obj, 0x29e, 4);
            Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
            *(f32 *)(state + 0x110) = lbl_803E71B4;
            *(u8 *)(state + 0x154) = 1;
            *(s16 *)(state + 0x150) = 0;
            *(s16 *)(state + 0x152) = 0;
            *(u8 *)(state + 0x15e) = *(u8 *)(state + 0x15e) - hitVol;
            if ((s8)*(u8 *)(state + 0x15e) <= 0) {
                storeZeroToFloatParam((void *)(state + 0x12c));
                s16toFloat((void *)(state + 0x12c), 0x78);
                if (*(u8 *)(state + 0x15c) == 1) {
                    spawnExplosion(obj, lbl_803E719C, 1, 0, 1, 1, 0, 0, 0);
                    *(s16 *)(obj + 6) |= 0x4000;
                    ObjHits_DisableObject(obj);
                    *(u8 *)(state + 0x159) = 4;
                    *(u8 *)(state + 0x159) = 3;
                    if (*(u8 *)(state + 0x15d) == 3)
                        gameTextFn_80125ba4(0xe);
                } else {
                    spawnExplosion(obj, lbl_803E719C, 1, 0, 0, 1, 0, 0, 3);
                    *(s16 *)(obj + 6) |= 0x4000;
                    ObjHits_DisableObject(obj);
                    *(u8 *)(state + 0x159) = 3;
                }
                arwing = getArwing();
                if (arwing != 0)
                    fn_8022D520(arwing, *(u8 *)(state + 0x157));
            } else {
                arwing = getArwing();
                if (arwing != 0)
                    fn_8022D520(arwing, *(u8 *)(state + 0x158));
            }
        } else if (*(u8 *)(state + 0x154) == 0) {
            Sfx_PlayFromObjectLimited(obj, 0x2b3, 4);
        }
    }
}
#pragma scheduling reset

extern void setMatrixFromObjectTransposed(void *transform, f32 *mtx);
extern f32 lbl_803E718C;
extern f32 lbl_803E7190;
extern f32 lbl_803E7194;
extern f32 lbl_803E7198;

#pragma scheduling off
void arwsquadron_followLeader(int p1, int p2)
{
    int leader = *(int *)(p2 + 0x13c);
    int leaderState = *(int *)(leader + 0xb8);
    int wstate = *(int *)(p1 + 0x4c);
    ArwProjPosSrc src;
    f32 mtx[12];
    f32 out[3];

    *(s16 *)(p2 + 0x146) = (f32)*(u16 *)(p2 + 0x14a) * timeDelta + (f32)*(u16 *)(p2 + 0x146);
    *(s16 *)(p2 + 0x148) = (f32)*(u16 *)(p2 + 0x14c) * timeDelta + (f32)*(u16 *)(p2 + 0x148);
    src.pos[0] = *(f32 *)(leader + 0xc);
    src.pos[1] = *(f32 *)(leader + 0x10);
    src.pos[2] = *(f32 *)(leader + 0x14);
    src.scale = lbl_803E7188;
    src.rot[0] = *(s16 *)(leader + 0);
    src.rot[1] = *(s16 *)(leader + 2);
    src.rot[2] = *(s16 *)(leader + 4);
    out[0] = lbl_803E7190 * fn_80293E80(lbl_803E7194 * (f32)*(u16 *)(p2 + 0x146) / lbl_803E7198) +
             lbl_803E718C * (f32)(s8)*(u8 *)(wstate + 0x26);
    out[1] = lbl_803E7190 * fn_80293E80(lbl_803E7194 * (f32)*(u16 *)(p2 + 0x148) / lbl_803E7198) +
             lbl_803E718C * (f32)(s8)*(u8 *)(wstate + 0x27);
    out[2] = lbl_803E718C * (f32)(s8)*(u8 *)(wstate + 0x1e);
    setMatrixFromObjectTransposed(&src, mtx);
    PSMTXMultVec(mtx, out, (void *)(p1 + 0xc));
    *(f32 *)(p1 + 0x24) = *(f32 *)(leader + 0x24);
    *(f32 *)(p1 + 0x28) = *(f32 *)(leader + 0x28);
    *(f32 *)(p1 + 0x2c) = *(f32 *)(leader + 0x2c);
    *(s16 *)(p1 + 0) = *(s16 *)(leader + 0);
    *(s16 *)(p1 + 2) = *(s16 *)(leader + 2);
    if (!((SquadCmdFlags *)(p2 + 0x160))->f08) {
        *(s16 *)(p1 + 4) =
            *(f32 *)(leaderState + 0x138) *
                fn_80293E80(lbl_803E7194 * (f32)*(u16 *)(p2 + 0x146) / lbl_803E7198) +
            (f32)*(s16 *)(leader + 4);
    }
    ((SquadCmdFlags *)(p2 + 0x160))->f80 = ((SquadCmdFlags *)(leaderState + 0x160))->f80;
    if (*(s16 *)(p2 + 0x144) > 0)
        ((SquadCmdFlags *)(p2 + 0x160))->f08 = ((SquadCmdFlags *)(leaderState + 0x160))->f08;
    if (*(u8 *)(leaderState + 0x159) == 4) {
        *(s16 *)(p1 + 6) |= 0x4000;
        ObjHits_DisableObject(p1);
        *(u8 *)(p2 + 0x159) = 4;
        *(u8 *)(p2 + 0x159) = 4;
    }
}
#pragma scheduling reset

extern f32 lbl_803E7164;
extern f32 lbl_803E71B8;
extern f32 lbl_803E71BC;

#pragma scheduling off
void arwsquadron_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    SquadCmdFlags *flags = (SquadCmdFlags *)(state + 0x160);
    u8 s = *(u8 *)(state + 0x159);

    if (s == 4 || s == 3)
        return;

    if (*(u8 *)(state + 0x15d) == 1) {
        int aim = getArwing();
        f32 d;
        int inRange;
        if (aim == 0)
            aim = Obj_GetPlayerObject();
        d = *(f32 *)(obj + 0x14) - *(f32 *)(aim + 0x14);
        inRange = (d < lbl_803E71B8 && d > lbl_803E7164);
        if (inRange) {
            if (randomGetRange(0, 1) != 0)
                gameTextFn_80125ba4(0x10);
            else
                gameTextFn_80125ba4(0xd);
            *(u8 *)(state + 0x15d) = 0;
        }
    }

    switch (*(u8 *)(state + 0x159)) {
    case 0: {
        int setupL = *(int *)(obj + 0x4c);
        int leader = obj;
        int enable;
        getArwing();
        if (*(int *)(setupL + 0x20) > 0) {
            if (*(int *)(state + 0x13c) == 0)
                *(int *)(state + 0x13c) = ObjList_FindObjectById(*(int *)(setupL + 0x20));
            leader = *(int *)(state + 0x13c);
        }
        if (leader == 0) {
            enable = 0;
        } else {
            f32 thr = *(f32 *)(state + 0x130);
            int aim = getArwing();
            f32 d;
            int inRange;
            if (aim == 0)
                aim = Obj_GetPlayerObject();
            d = *(f32 *)(leader + 0x14) - *(f32 *)(aim + 0x14);
            inRange = (d < thr && d > lbl_803E7164);
            if (!inRange) {
                enable = 0;
            } else if (*(s16 *)(setupL + 0x32) > 0) {
                enable = GameBit_Get(*(s16 *)(setupL + 0x32)) != 0;
            } else {
                f32 thr2 = *(f32 *)(state + 0x134);
                int aim2 = getArwing();
                f32 d2;
                int inRange2;
                if (aim2 == 0)
                    aim2 = Obj_GetPlayerObject();
                d2 = *(f32 *)(leader + 0x14) - *(f32 *)(aim2 + 0x14);
                inRange2 = (d2 < thr2 && d2 > lbl_803E7164);
                if (!inRange2)
                    enable = GameBit_Get(*(s16 *)(setupL + 0x32)) != 0;
                else
                    enable = 1;
            }
        }
        if (enable) {
            *(s16 *)(obj + 6) &= ~0x4000;
            ObjHits_EnableObject(obj);
            *(u8 *)(state + 0x159) = 1;
            setupL = *(int *)(obj + 0x4c);
            if (*(u8 *)(state + 0x15c) == 1) {
                flags->f20 = 0;
                storeZeroToFloatParam((void *)(state + 0x124));
                s16toFloat((void *)(state + 0x124), *(u8 *)(setupL + 0x2c));
            }
        }
        return;
    }
    case 1: {
        int setupL = *(int *)(obj + 0x4c);
        int leader = obj;
        int disable;
        *(u8 *)(obj + 0x36) = 0xff;
        getArwing();
        if (*(int *)(state + 0x13c) != 0)
            leader = *(int *)(state + 0x13c);
        if (leader == 0) {
            disable = 0;
        } else {
            f32 thr = *(f32 *)(state + 0x130);
            int aim = getArwing();
            f32 d;
            int inRange;
            if (aim == 0)
                aim = Obj_GetPlayerObject();
            d = *(f32 *)(leader + 0x14) - *(f32 *)(aim + 0x14);
            inRange = (d < thr && d > lbl_803E7164);
            if (inRange) {
                disable = 0;
            } else if (*(s16 *)(setupL + 0x32) > 0) {
                disable = GameBit_Get(*(s16 *)(setupL + 0x32)) != 0;
            } else {
                f32 thr2 = *(f32 *)(state + 0x134);
                int aim2 = getArwing();
                f32 d2;
                int inRange2;
                if (aim2 == 0)
                    aim2 = Obj_GetPlayerObject();
                d2 = *(f32 *)(leader + 0x14) - *(f32 *)(aim2 + 0x14);
                inRange2 = (d2 < thr2 && d2 > lbl_803E7164);
                if (!inRange2)
                    disable = GameBit_Get(*(s16 *)(setupL + 0x32)) != 0;
                else
                    disable = 1;
            }
        }
        if (disable) {
            *(s16 *)(obj + 6) |= 0x4000;
            ObjHits_DisableObject(obj);
            *(u8 *)(state + 0x159) = 4;
            return;
        }
        if (*(u8 *)(state + 0x15c) != 2) {
            if (*(u8 *)(setup + 0x2f) != 2) {
                *(s16 *)(obj + 0) =
                    (f32)*(s16 *)(state + 0x140) * timeDelta + (f32)*(s16 *)(obj + 0);
                *(s16 *)(obj + 2) =
                    (f32)*(s16 *)(state + 0x142) * timeDelta + (f32)*(s16 *)(obj + 2);
            }
            if (flags->f08 || *(u8 *)(setup + 0x2f) != 2) {
                *(s16 *)(obj + 4) =
                    (f32)*(s16 *)(state + 0x144) * timeDelta + (f32)*(s16 *)(obj + 4);
            }
        }
        if (*(int *)(state + 0x13c) != 0) {
            arwsquadron_followLeader(obj, state);
        } else if (flags->f40) {
            arwsquadron_followPath(obj, state);
        }
        if (flags->f80) {
            setupL = *(int *)(obj + 0x4c);
            ObjHits_SetHitVolumeSlot(obj, 0x13, *(u8 *)(state + 0x156), 0);
            if (*(u8 *)(state + 0x15c) == 1)
                arwsquadron_updateVolley(obj, state, setupL);
        }
        break;
    }
    case 3:
    case 4:
        return;
    default:
        break;
    }

    arwsquadron_handleDamage(obj, state);
    if (*(u8 *)(state + 0x15c) == 1)
        arwsquadron_emitEffects(obj, state);
    if (*(int *)(*(int *)(obj + 0x50) + 0x44) == 0)
        ObjAnim_AdvanceCurrentMove(lbl_803E71BC, timeDelta, obj, 0);
}
#pragma scheduling reset

extern f32 lbl_803E6C68;
#pragma scheduling off
void fn_80221E94(int obj, f32 *p2)
{
    struct {
        f32 _pad[3];
        f32 vec[3];
    } s;

    s.vec[0] = p2[0] + playerMapOffsetX;
    s.vec[1] = p2[1];
    s.vec[2] = p2[2] + playerMapOffsetZ;
    objLightFn_8009a1dc(obj, lbl_803E6C68, &s, 1, 0);
    Obj_SetModelColorFadeRecursive(obj, 0x5a, 0xc8, 0, 0, 1);
}
#pragma scheduling reset

typedef struct DrMusicContFlags {
    u8 b_state : 1;
    u8 pad8_lo : 1;
    u8 b_e30 : 1;
    u8 b_e31 : 1;
    u8 b_e32 : 1;
    u8 b_e33 : 1;
    u8 b_e9c : 1;
    u8 b_e38 : 1;
    u8 b_e3c : 1;
    u8 b_e3d : 1;
    u8 b_e3e : 1;
    u8 b_e39 : 1;
    u8 b_9e0 : 1;
    u8 b_9e1 : 1;
    u8 b_9e2 : 1;
    u8 b_9e7 : 1;
} DrMusicContFlags;

#pragma peephole on
#pragma scheduling off
void drmusiccont_init(int obj)
{
    int state = *(int *)(obj + 0xb8);
    DrMusicContFlags *f = (DrMusicContFlags *)(state + 0x8);

    f->b_e30 = (u8)GameBit_Get(0xe30);
    f->b_e31 = (u8)GameBit_Get(0xe31);
    f->b_e32 = (u8)GameBit_Get(0xe32);
    f->b_e33 = (u8)GameBit_Get(0xe33);
    f->b_e9c = (u8)GameBit_Get(0xe9c);
    f->b_e38 = (u8)GameBit_Get(0xe38);
    f->b_e3c = (u8)GameBit_Get(0xe3c);
    f->b_e3d = (u8)GameBit_Get(0xe3d);
    f->b_e3e = (u8)GameBit_Get(0xe3e);
    f->b_e39 = (u8)GameBit_Get(0xe39);
    f->b_9e0 = (u8)GameBit_Get(0x9e0);
    f->b_9e1 = (u8)GameBit_Get(0x9e1);
    f->b_9e2 = (u8)GameBit_Get(0x9e2);
    f->b_9e7 = (u8)GameBit_Get(0x9e7);
}
#pragma scheduling reset
#pragma peephole reset

extern void fn_80094378(int obj, f32 a, f32 b, f32 c);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void skyFn_80088e54(int a, f32 b);
extern void SCGameBitLatch_Update(int state, int a, int b, int c, int d, int e);
extern void SCGameBitLatch_UpdateInverted(int state, int a, int b, int c, int d, int e);
extern f32 lbl_803E6BCC;
extern f32 lbl_803E6BD0;
extern f32 lbl_803E6BD4;
extern f32 lbl_803E6BD8;
extern f32 lbl_803E6BDC;
extern f32 lbl_803E6BE0;
extern f32 lbl_803E6BE4;
extern f32 lbl_803E6BE8;

#pragma peephole off
#pragma scheduling off
void drmusiccont_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    DrMusicContFlags *f = (DrMusicContFlags *)(state + 0x8);
    u32 a;
    u32 b;
    u32 c;
    u32 d;

    fn_80094378(obj, lbl_803E6BCC, lbl_803E6BD0, lbl_803E6BD4);
    if (*(int *)(obj + 0xf4) == 0) {
        if ((u32)GameBit_Get(0xe7b) == 0) {
            getEnvfxActImmediately(obj, obj, 0x210, 0);
            getEnvfxActImmediately(obj, obj, 0x20f, 0);
            getEnvfxActImmediately(obj, obj, 0x212, 0);
            getEnvfxActImmediately(obj, obj, 0x1ea, 0);
            skyFn_80088e54(0, lbl_803E6BD8);
            GameBit_Set(0xe7b, 1);
        }
        *(int *)(obj + 0xf4) = 1;
    }

    SCGameBitLatch_Update(state, 2, 0x1a7, 0x64b, 0xf0e, 0xe5);
    SCGameBitLatch_UpdateInverted(state, 1, -1, -1, 0xe26, 0xb8);
    SCGameBitLatch_Update(state, 4, -1, -1, 0xcbb, 0xc4);

    a = (u8)GameBit_Get(0xe30);
    b = (u8)GameBit_Get(0xe31);
    c = (u8)GameBit_Get(0xe32);
    d = (u8)GameBit_Get(0xe33);
    if (f->b_e9c == 0 && a && b && c && d) {
        f->b_e9c = 1;
        GameBit_Set(0xe9c, 1);
        Sfx_PlayFromObject(0, 0x7e);
    } else if (a != f->b_e30 || b != f->b_e31 || c != f->b_e32 || d != f->b_e33) {
        Sfx_PlayFromObject(0, 0x109);
    }
    f->b_e30 = a;
    f->b_e31 = b;
    f->b_e32 = c;
    f->b_e33 = d;

    a = (u8)GameBit_Get(0xe38);
    b = (u8)GameBit_Get(0xe3c);
    c = (u8)GameBit_Get(0xe3d);
    d = (u8)GameBit_Get(0xe3e);
    if (f->b_e39 == 0 && a && b && c && d) {
        f->b_e39 = 1;
        Sfx_PlayFromObject(0, 0x7e);
    } else if (a != f->b_e38 || b != f->b_e3c || c != f->b_e3d || d != f->b_e3e) {
        Sfx_PlayFromObject(0, 0x109);
    }
    f->b_e38 = a;
    f->b_e3c = b;
    f->b_e3d = c;
    f->b_e3e = d;

    a = (u8)GameBit_Get(0x9e0);
    b = (u8)GameBit_Get(0x9e1);
    c = (u8)GameBit_Get(0x9e2);
    d = (u8)GameBit_Get(0x9e7);
    if (!(a && b && c && d)) {
        if (a != f->b_9e0 || b != f->b_9e1 || c != f->b_9e2 || d != f->b_9e7) {
            *(f32 *)(state + 4) = lbl_803E6BDC;
        }
    }
    {
        f32 zero = lbl_803E6BD8;
        if (*(f32 *)(state + 4) > zero) {
            *(f32 *)(state + 4) = *(f32 *)(state + 4) - timeDelta;
            if (*(f32 *)(state + 4) <= zero) {
                Sfx_PlayFromObject(0, 0x4bd);
            }
        }
    }
    f->b_9e0 = a;
    f->b_9e1 = b;
    f->b_9e2 = c;
    f->b_9e7 = d;

    if (f->b_state != 0) {
        if ((u32)GameBit_Get(0x9f0) == 0 || (u32)GameBit_Get(0x632) != 0) {
            (*(void (**)(void))(*gMapEventInterface + 0x2c))();
            f->b_state = 0;
        }
    } else {
        if ((u32)GameBit_Get(0x9f0) != 0 && (u32)GameBit_Get(0x632) == 0) {
            f32 vec[3];
            vec[0] = lbl_803E6BE0;
            vec[1] = lbl_803E6BE4;
            vec[2] = lbl_803E6BE8;
            (*(void (**)(f32 *, int, int, int))(*gMapEventInterface + 0x24))(vec, 0x7fff, 0, 0);
            f->b_state = 1;
        }
    }
}
#pragma scheduling on
#pragma peephole on

extern f32 lbl_803E6CA4;
extern f32 lbl_803E6CD0;

#pragma peephole off
#pragma scheduling off
void drbarrelgr_init(int obj, int setup)
{
    int one;
    int state;

    one = 1;
    state = *(int *)(obj + 0xb8);
    if (*(u8 *)(setup + 0x19) == 0) {
        *(u8 *)(setup + 0x19) = 0xa;
    }
    if (*(s16 *)(setup + 0x1a) <= 0) {
        *(s16 *)(setup + 0x1a) = 0x64;
    }
    *(int *)(state + 0) = 5;
    *(int *)(state + 8) = 0;
    ((DrBarrelGrFlags *)(state + 0x12a))->bit80 = 0;
    *(s16 *)(state + 0x128) = *(u8 *)(setup + 0x19);
    *(f32 *)(state + 0x10) = lbl_803E6CA4;
    *(int *)(state + 4) = -3;
    ((DrBarrelGrFlags *)(state + 0x12a))->bit40 = 0;
    storeZeroToFloatParam((void *)(state + 0xc));
    s16toFloat((void *)(state + 0xc), *(s16 *)(setup + 0x1a));
    *(s16 *)obj = (s16)((s8)*(s8 *)(setup + 0x18) << 8);
    (*(void (**)(int, int, f32, int *, int))(*gRomCurveInterface + 0x8c))(
        state + 0x20, obj, lbl_803E6CD0, &one, 0);
    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x88);
    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x90);
    *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x8c);
}
#pragma scheduling on
#pragma peephole on

extern int gunpowderbarrel_isHeld(int obj);
extern int gunpowderbarrel_canBeGrabbed(int obj);
extern void gunpowderbarrel_setScale(int obj, void *vec);
extern void gunpowderbarrel_setHeldState(int obj);
extern int timerCountDown(void *timer);
extern void PSVECNormalize(void *src, void *dst);
extern void PSVECScale(void *dst, void *src, f32 scale);
extern f32 PSVECDistance(void *a, void *b);
extern int fn_80222358(int obj, int p2, f32 a, f32 b, f32 c, int p6);
extern void fn_80221D6C(void *p1, void *p2);
extern void PSVECSubtract(void *a, void *b, void *ab);
extern int ObjGroup_FindNearestObject(int group, int obj, f32 *out);
extern f32 lbl_803E6CA0;
extern f32 lbl_803E6CA8;
extern f32 lbl_803E6CB0;
extern f32 lbl_803E6CB4;
extern f32 lbl_803E6CB8;
extern f32 lbl_803E6CBC;
extern f32 lbl_803E6CC0;
extern f32 lbl_803DC3B0;
extern f32 lbl_803DC3B4;

#pragma peephole off
#pragma scheduling off
void drbarrelgr_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    int newMode = -1;
    DrBarrelGrFlags *flags = (DrBarrelGrFlags *)(state + 0x12a);
    int nearest;
    int match;
    int gbId;
    f32 vec[3];
    f32 tmp[3];

    if (*(void **)(state + 8) != 0) {
        nearest = ObjGroup_FindNearestObject(25, obj, 0);
        match = 0;
        if ((u32)nearest != 0 && *(u32 *)(state + 8) == (u32)nearest) {
            match = 1;
        }
        if (match == 0 ||
            (flags->bit80 != 0 && gunpowderbarrel_isHeld(*(int *)(state + 8)) == 0)) {
            *(int *)(state + 8) = 0;
            flags->bit80 = 0;
        }
    }

    gbId = *(s16 *)(setup + 0x20);
    if (gbId != -1 && (u32)GameBit_Get(gbId) == 0) {
        flags->bit40 = 0;
        return;
    }
    flags->bit40 = 1;
    Sfx_KeepAliveLoopedObjectSound(obj, 958);

    switch (*(int *)(state + 0)) {
    case 0:
        if (*(void **)(state + 8) == 0) {
            nearest = ObjGroup_FindNearestObject(25, obj, 0);
            if ((u32)nearest != 0 &&
                Vec_xzDistance(obj + 24, nearest + 24) < lbl_803E6CB0 &&
                *(f32 *)(nearest + 16) < *(f32 *)(obj + 16)) {
                vec[0] = *(f32 *)(nearest + 12);
                vec[1] = lbl_803E6CB4 + *(f32 *)(nearest + 16);
                vec[2] = *(f32 *)(nearest + 20);
                if (((int (*)(void *, void *))fn_80221D6C)((void *)(obj + 12), vec) != 0 &&
                    gunpowderbarrel_canBeGrabbed(nearest) != 0) {
                    Sfx_PlayFromObject(obj, 959);
                    newMode = 4;
                    *(int *)(state + 8) = nearest;
                }
                break;
            }
        }
        if (timerCountDown((void *)(state + 12)) != 0) {
            newMode = 5;
        }
        break;
    case 4:
        if (*(void **)(state + 8) == 0 ||
            gunpowderbarrel_canBeGrabbed(*(int *)(state + 8)) == 0) {
            *(int *)(state + 0) = 0;
            *(int *)(state + 8) = 0;
            flags->bit80 = 0;
            break;
        }
        if (Vec_xzDistance(obj + 24, *(int *)(state + 8) + 24) > lbl_803E6CB0) {
            newMode = *(int *)(state + 4);
            flags->bit80 = 0;
            *(int *)(state + 8) = 0;
            break;
        }
        PSVECSubtract((void *)(state + 0x14), (void *)(*(int *)(state + 8) + 12), tmp);
        if (tmp[0] != lbl_803E6CA4 || tmp[1] != lbl_803E6CA4 || tmp[2] != lbl_803E6CA4) {
            PSVECNormalize(tmp, tmp);
        }
        PSVECScale(tmp, tmp, lbl_803DC3B0);
        gunpowderbarrel_setScale(*(int *)(state + 8), tmp);
        if (PSVECDistance((void *)(state + 0x14), (void *)(*(int *)(state + 8) + 12)) < lbl_803E6CA0 ||
            *(f32 *)(*(int *)(state + 8) + 16) > *(f32 *)(state + 24)) {
            Sfx_PlayFromObject(obj, 960);
            gunpowderbarrel_setHeldState(*(int *)(state + 8));
            newMode = *(int *)(state + 4);
            flags->bit80 = 1;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6CA4, 0);
        }
        break;
    case 5: {
        int r = fn_80222358(obj, state + 0x20,
                            lbl_803E6CB8 * (f32)*(s16 *)(state + 0x128) * timeDelta,
                            lbl_803E6CBC, lbl_803E6CB4, 1);
        objMove(obj, *(f32 *)(obj + 36), *(f32 *)(obj + 40), *(f32 *)(obj + 44));
        if (r != 0) {
            newMode = r - 1;
            storeZeroToFloatParam((void *)(state + 12));
            s16toFloat((void *)(state + 12), *(s16 *)(setup + 0x1a));
            *(f32 *)(obj + 36) = lbl_803E6CA4;
            *(f32 *)(obj + 40) = lbl_803E6CA4;
            *(f32 *)(obj + 44) = lbl_803E6CA4;
        }
        break;
    }
    case 2:
        if (*(s16 *)(state + 0x128) == *(u8 *)(setup + 0x19)) {
            *(s16 *)(state + 0x128) =
                (int)((f32)*(s16 *)(state + 0x128) * lbl_803E6CA8);
        } else {
            *(s16 *)(state + 0x128) = *(u8 *)(setup + 0x19);
        }
        storeZeroToFloatParam((void *)(state + 12));
        newMode = 5;
        break;
    case 1:
        if (*(void **)(state + 8) != 0) {
            newMode = 3;
        } else if (timerCountDown((void *)(state + 12)) != 0) {
            newMode = 5;
        }
        break;
    case 3:
        if (*(void **)(state + 8) != 0) {
            gunpowderbarrel_clearHeldState(*(int *)(state + 8));
            flags->bit80 = 0;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6CA4, 0);
        }
        *(int *)(state + 8) = 0;
        newMode = *(int *)(state + 4);
        break;
    }

    ObjAnim_AdvanceCurrentMove(lbl_803E6CC0, timeDelta, obj, 0);
    if (newMode != -1 && newMode != *(int *)(state + 0)) {
        *(int *)(state + 4) = *(int *)(state + 0);
        *(int *)(state + 0) = newMode;
    }
    if ((*(u16 *)(obj + 0xb0) & 0x800) == 0 && *(void **)(state + 8) != 0) {
        *(f32 *)(state + 0x14) = *(f32 *)(obj + 12);
        *(f32 *)(state + 0x18) = *(f32 *)(obj + 16) + lbl_803DC3B4;
        *(f32 *)(state + 0x1c) = *(f32 *)(obj + 20);
        *(f32 *)(*(int *)(state + 8) + 12) = *(f32 *)(state + 0x14);
        *(f32 *)(*(int *)(state + 8) + 16) = *(f32 *)(state + 0x18);
        *(f32 *)(*(int *)(state + 8) + 20) = *(f32 *)(state + 0x1c);
    }
}
#pragma scheduling on
#pragma peephole on

extern void PSVECSubtract(void *a, void *b, void *ab);
extern int ObjGroup_FindNearestObject(int group, int obj, f32 *out);
extern f32 lbl_803E6CA0;
extern f32 lbl_803E6CA8;
extern f32 lbl_803E6CAC;

typedef struct DrBarrelGrRenderParams {
    s16 a;
    s16 b;
    s16 c;
    f32 d;
} DrBarrelGrRenderParams;

#pragma scheduling off
void drbarrelgr_render(int obj, int p2, int p3, int p4, int p5)
{
    int state = *(int *)(obj + 0xb8);
    int i;
    int objRef;
    int nearest;
    int match;
    f32 dval;
    f32 vec[3];
    DrBarrelGrRenderParams params;

    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6CA0);
    ObjPath_GetPointWorldPosition(obj, 0, (f32 *)(state + 0x14), (f32 *)(state + 0x18),
                                  (f32 *)(state + 0x1c), 0);
    params.a = 0;
    params.c = 0;
    params.b = 0x4000;
    dval = lbl_803E6CA4;
    for (i = 0; i < 4; i++) {
        ObjPath_GetPointWorldPosition(obj, i + 1, &vec[0], &vec[1], &vec[2], 0);
        PSVECSubtract(&vec[0], (void *)(obj + 0xc), &vec[0]);
        params.d = dval;
        fn_8009837C(obj, lbl_803E6CA8, 3, 0, 0, lbl_803E6CAC, (int)&params);
    }
    objRef = *(int *)(state + 8);
    if (objRef != 0) {
        match = 0;
        nearest = ObjGroup_FindNearestObject(0x19, obj, 0);
        if (nearest != 0 && nearest == objRef) {
            match = 1;
        }
        if (match && *(int *)state != 4) {
            *(f32 *)(*(int *)(state + 8) + 0xc) = *(f32 *)(state + 0x14);
            *(f32 *)(*(int *)(state + 8) + 0x10) = *(f32 *)(state + 0x18);
            *(f32 *)(*(int *)(state + 8) + 0x14) = *(f32 *)(state + 0x1c);
            objRenderFn_8003b8f4(*(int *)(state + 8), p2, p3, p4, p5, lbl_803E6CA0);
        }
    }
}
#pragma scheduling on

extern int dll_2E_func0A(int a, void *out);
extern void *fn_8008FB20(f32 *pos, f32 *dir, f32 a, f32 b, u16 angle, int c, int d);
extern f32 lbl_803E6BB8;
extern f32 lbl_803E6BBC;
extern f32 lbl_803E6BC0;

#pragma peephole off
#pragma scheduling off
void drlightbea_render(int obj, int p2, int p3, int p4, int p5)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    int player;
    int connectId;
    f32 buf[6];
    f32 vecA[3];
    f32 vecB[3];

    if (((DrLightBeaFlags *)(state + 4))->bit80) {
        *(f32 *)(*(int *)state + 0) = *(f32 *)(obj + 0xc);
        *(f32 *)(*(int *)state + 4) = *(f32 *)(obj + 0x10);
        *(f32 *)(*(int *)state + 8) = *(f32 *)(obj + 0x14);
        if (*(s8 *)(setup + 0x19) == 0) {
            player = Obj_GetPlayerObject();
            *(f32 *)(*(int *)state + 0xc) = *(f32 *)(player + 0xc);
            *(f32 *)(*(int *)state + 0x10) = lbl_803E6BB8 + *(f32 *)(player + 0x10);
            *(f32 *)(*(int *)state + 0x14) = *(f32 *)(player + 0x14);
        }
        renderFn_8008f904(*(void **)state);
        *(u16 *)(*(int *)state + 0x20) += 1;
        if (*(u16 *)(*(int *)state + 0x20) >= *(u16 *)(*(int *)state + 0x22)) {
            mm_free(*(void **)state);
            *(int *)state = 0;
            ((DrLightBeaFlags *)(state + 4))->bit80 = 0;
            if (*(u32 *)(setup + 0x14) == 0xffffffff) {
                ((DrLightBeaFlags *)(state + 4))->bit40 = 1;
            }
        }
    } else {
        if (*(void **)state != NULL) {
            mm_free(*(void **)state);
            *(int *)state = 0;
        }
        ((DrLightBeaFlags *)(state + 4))->bit80 = (u8)GameBit_Get(*(s16 *)(setup + 0x20));
        if (((DrLightBeaFlags *)(state + 4))->bit80) {
            Sfx_PlayFromObject(obj, 0x30f);
            vecA[0] = *(f32 *)(obj + 0xc);
            vecA[1] = *(f32 *)(obj + 0x10);
            vecA[2] = *(f32 *)(obj + 0x14);
            connectId = *(s8 *)(setup + 0x19);
            if (connectId != 0 && dll_2E_func0A(connectId, buf) != 0) {
                vecB[0] = buf[3];
                vecB[1] = buf[4];
                vecB[2] = buf[5];
            } else {
                player = Obj_GetPlayerObject();
                vecB[0] = *(f32 *)(player + 0xc);
                vecB[1] = lbl_803E6BB8 + *(f32 *)(player + 0x10);
                vecB[2] = *(f32 *)(player + 0x14);
            }
            *(void **)state = fn_8008FB20(vecA, vecB, lbl_803E6BBC, lbl_803E6BC0,
                                         (u16)randomGetRange(5, 0xf), 0x60, 0);
        }
    }
}
#pragma scheduling on
#pragma peephole on

extern void *fn_802972A8(void);
extern void setAButtonIcon(int icon);
extern void objParticleFn_80097734(int obj, int enabled, f32 radius, int particleKind,
                                   int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                   f32 scaleZ, void *args, int arg9);
extern f32 lbl_803E6C08;
extern f32 lbl_803E6C0C;
extern f32 lbl_803E6C10;
extern f32 lbl_803E6C14;
extern f32 lbl_803E6C18;
extern f32 lbl_803E6C1C;

#pragma peephole off
#pragma scheduling off
void drearthcal_update(int obj)
{
    int player;
    int i;
    struct {
        f32 _pad[3];
        f32 vec[3];
    } part;
    f32 searchDist;

    player = Obj_GetPlayerObject();
    searchDist = lbl_803E6C08;
    if (fn_802972A8() != NULL) {
        *(u8 *)(obj + 0xaf) &= ~0x18;
        if ((*(u8 *)(obj + 0xaf) & 0x4) != 0) {
            setAButtonIcon(0x15);
        }
        if (ObjTrigger_IsSet(obj) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
        }
    } else {
        *(u8 *)(obj + 0xaf) |= 0x8;
        for (i = 0; i < *(s8 *)(*(int *)(obj + 0x58) + 0x10f); i++) {
            if (*(int *)(0x100 + i * 4 + *(int *)(obj + 0x58)) == player) {
                *(u8 *)(obj + 0xaf) &= ~0x8;
            }
        }
        if ((u32)ObjGroup_FindNearestObject(0xa, obj, &searchDist) == 0) {
            *(u8 *)(obj + 0xaf) |= 0x10;
        } else {
            *(u8 *)(obj + 0xaf) &= ~0x10;
        }
        if ((*(u8 *)(obj + 0xaf) & 0x4) != 0) {
            setAButtonIcon(0x14);
        }
        if (ObjTrigger_IsSet(obj) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(2, obj, -1);
        }
    }
    if ((*(u16 *)(obj + 0xb0) & 0x800) != 0) {
        part.vec[0] = lbl_803E6C0C;
        part.vec[1] = lbl_803E6C10;
        part.vec[2] = lbl_803E6C0C;
        objParticleFn_80097734(obj, 5, lbl_803E6C14, 2, 2, 0xf, lbl_803E6C18, lbl_803E6C18,
                               lbl_803E6C1C, &part, 0);
    }
}
#pragma scheduling on
#pragma peephole on

extern void voxmaps_worldToGrid(void *world, void *grid);
extern int voxmaps_traceLine(void *from, void *to, void *out, int p4, int p5);
extern f32 lbl_803E6C58;

extern void mm_free_(void *ptr);
extern f32 lbl_803E6C3C;
extern f32 lbl_803E6C40;
extern f32 lbl_803E6C44;
extern f32 lbl_803DC3A0;
extern f32 lbl_803DC3A4;
extern f32 lbl_803DC3A8;
extern u16 lbl_803DC3AC;

#pragma scheduling off
int fn_80221978(int obj, void **entries, int count, void **light, f32 intensity)
{
    int i;
    int spawned;
    void **p;
    f32 pos[3];

    spawned = 0;
    if (lbl_803E6C38 == intensity) {
        spawned = 0;
        for (i = 0, p = entries; i < count; p++, i++) {
            if (*p != 0) {
                mm_free_(*p);
                *p = 0;
            }
        }
        if (*light != 0) {
            fn_8001CB3C((int)light);
        }
        return 0;
    }

    for (i = 0, p = entries; i < count; p++, i++) {
        if (*p != 0) {
            renderFn_8008f904(*p);
            *(u16 *)((char *)*p + 0x20) += framesThisStep;
            if ((f32)(u32)*(u16 *)((char *)*p + 0x20) > lbl_803DC3A8) {
                mm_free_(*p);
                *p = 0;
            }
        } else if (spawned == 0) {
            pos[0] = *(f32 *)(obj + 0xc);
            pos[1] = *(f32 *)(obj + 0x10);
            pos[2] = *(f32 *)(obj + 0x14);
            pos[0] += lbl_803E6C3C * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            pos[1] += lbl_803E6C3C * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            pos[2] += lbl_803E6C3C * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            *p = fn_8008FB20((f32 *)(obj + 0xc), pos, lbl_803DC3A0, lbl_803DC3A4,
                             (int)lbl_803DC3A8, (u8)lbl_803DC3AC, 0);
            spawned = 1;
        }
    }

    if (*light == 0) {
        *light = (void *)fn_8001CC9C(obj, 0x80, 0x80, 0xff, 0);
        if (*light != 0) {
            lightVecFn_8001dd88(*light, lbl_803E6C38, intensity * lbl_803E6C40, lbl_803E6C38);
            lightDistAttenFn_8001dc38(*light, intensity, lbl_803E6C44 + intensity);
        }
    }
    return 1;
}
#pragma scheduling reset

extern f32 lbl_803E6C5C;
extern f32 lbl_803E6C84;
extern f32 lbl_803E6C88;
extern f32 lbl_803E6C8C;
extern f32 lbl_803E6C90;
extern f32 lbl_803E6C94;
extern f32 lbl_803E6C98;

#pragma scheduling off
void fn_80222550(int a, int b, int c, f32 d, f32 e)
{
    f32 rate;
    f32 delta;
    f32 clamped;
    f32 dist;
    int tmp;

    rate = timeDelta / (f32)(u32)(u16)c;
    if (rate > lbl_803E6C6C) {
        rate = lbl_803E6C6C;
    }

    delta = (f32)(int)((u16)getAngle(-*(f32 *)(b + 0), -*(f32 *)(b + 8)) - (u16)*(s16 *)(a + 0));
    if (delta > lbl_803E6C64) {
        delta = lbl_803E6C84 + delta;
    }
    if (delta < lbl_803E6C8C) {
        delta = lbl_803E6C88 + delta;
    }
    delta *= rate;
    if (delta < lbl_803E6C90) {
        clamped = lbl_803E6C90;
    } else if (delta > lbl_803E6C94) {
        clamped = lbl_803E6C94;
    } else {
        clamped = delta;
    }
    *(s16 *)(a + 0) = *(s16 *)(a + 0) + (int)clamped;

    if (d != lbl_803E6C38) {
        *(s16 *)(a + 4) = (int)(lbl_803E6C98 * (f32)*(s16 *)(a + 4));
        *(s16 *)(a + 4) = (int)(oneOverTimeDelta * (lbl_803E6C5C * (clamped * d)) + (f32)*(s16 *)(a + 4));
        tmp = *(s16 *)(a + 4);
        if (tmp < -0x2000) {
            tmp = -0x2000;
        } else if (tmp > 0x2000) {
            tmp = 0x2000;
        }
        *(s16 *)(a + 4) = (s16)tmp;
    }

    if (lbl_803E6C38 != e) {
        dist = sqrtf(*(f32 *)(b + 0) * *(f32 *)(b + 0) + *(f32 *)(b + 8) * *(f32 *)(b + 8));
        delta = (f32)(int)((u16)getAngle(*(f32 *)(b + 4) * e, dist) - (u16)*(s16 *)(a + 2));
        if (delta > lbl_803E6C64) {
            delta = lbl_803E6C84 + delta;
        }
        if (delta < lbl_803E6C8C) {
            delta = lbl_803E6C88 + delta;
        }
        *(s16 *)(a + 2) = *(s16 *)(a + 2) + (int)(delta * rate);
    }
}
#pragma scheduling reset

#pragma scheduling off
int fn_80221C18(int obj, f32 dt, int p3, int p4)
{
    f32 vel[3];
    f32 step[3];
    f32 pos[3];
    int gridA[2];
    int gridB[2];
    int gridOut[3];
    int i;

    if ((u32)obj != (u32)Obj_GetPlayerObject()) {
        PSVECSubtract((void *)(obj + 0xc), (void *)(obj + 0x80), vel);
    } else {
        vel[0] = *(f32 *)(obj + 0x24);
        vel[1] = *(f32 *)(obj + 0x28);
        vel[2] = *(f32 *)(obj + 0x2c);
    }
    PSVECScale(vel, vel, oneOverTimeDelta);
    pos[0] = *(f32 *)(obj + 0xc);
    pos[1] = lbl_803E6C58 + *(f32 *)(obj + 0x10);
    pos[2] = *(f32 *)(obj + 0x14);
    for (i = 0; i < 5; i++) {
        PSVECScale(vel, step, PSVECDistance(pos, (void *)p3) / dt);
        PSVECAdd(obj + 0xc, (int)step, (int)pos);
    }
    *(f32 *)(p4 + 0) = pos[0];
    *(f32 *)(p4 + 4) = pos[1];
    *(f32 *)(p4 + 8) = pos[2];
    voxmaps_worldToGrid((void *)p3, gridA);
    voxmaps_worldToGrid(pos, gridB);
    return voxmaps_traceLine(gridA, gridB, gridOut, 0, 0) != 0;
}
#pragma scheduling reset

#pragma scheduling off
void fn_80221D6C(void *p1, void *p2)
{
    int grid1[2];
    int grid2[2];
    int out[2];

    voxmaps_worldToGrid(p1, grid1);
    voxmaps_worldToGrid(p2, grid2);
    voxmaps_traceLine(grid1, grid2, out, 0, 0);
}
#pragma scheduling on

extern void voxmaps_gridToWorld(void *grid, void *out);

#pragma scheduling off
void fn_80221DC0(int p1, void *p2, f32 *p3, f32 scale)
{
    f32 endPos[3];
    f32 scaled[3];
    int gridA[2];
    int gridB[2];
    int gridOut[2];
    int e0;
    int e1;

    PSVECNormalize(p3, p3);
    PSVECScale(p3, scaled, scale);
    PSVECAdd((int)scaled, (int)p2, (int)endPos);
    voxmaps_worldToGrid(p2, gridA);
    voxmaps_worldToGrid(endPos, gridB);
    if (voxmaps_traceLine(gridA, gridB, gridOut, 0, 0) == 0)
        voxmaps_gridToWorld(endPos, gridOut);
    e0 = *(int *)&endPos[0];
    e1 = *(int *)&endPos[1];
    *(int *)(p1 + 0) = e0;
    *(int *)(p1 + 4) = e1;
    *(int *)(p1 + 8) = *(int *)&endPos[2];
}
#pragma scheduling on

extern f32 lbl_803E70A0;
extern f32 lbl_803E70B4;
extern f32 lbl_803E70B8;
extern f32 lbl_803E70BC;
extern f32 lbl_803E70C0;
extern f32 lbl_803E70C4;
extern f32 lbl_803E70C8;
extern f32 lbl_803E70CC;
extern int getArwing(void);
extern int Obj_GetPlayerObject(void);
extern void PSMTXMultVecSR(f32 *mtx, f32 *in, f32 *out);
extern f32 sin(f32 x);
extern f32 fn_80293E80(f32 x);

typedef struct {
    /* 0x0 */ int f0;
    /* 0x4 */ int f4;
    /* 0x8 */ int f8;
    /* 0xc */ int fc;
    /* 0x10 */ int f10;
    /* 0x14 */ f32 f14;
} RingTable;
extern RingTable lbl_8032B720[];

#pragma scheduling off
void ring_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int arwing;
    int setup = *(int *)(obj + 0x4c);
    int bit;
    int r;
    int hitA;
    int hitB;
    int hit;
    int ang;
    f32 dir[3];
    f32 spawnBuf[6];
    f32 mtx[12];

    arwing = getArwing();
    if (arwing == 0)
        arwing = Obj_GetPlayerObject();

    switch (*(u8 *)(state + 0x15)) {
    case 0:
        r = (int)((f32)(u32) * (u8 *)(obj + 0x36) - lbl_803E70B4 * timeDelta);
        if (r < 0) {
            r = 0;
            *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) | 0x4000);
        }
        *(u8 *)(obj + 0x36) = (u8)r;
        bit = *(s16 *)(setup + 0x20);
        if (bit > -1) {
            if (GameBit_Get(bit) != 0) {
                *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) & ~0x4000);
                *(u8 *)(state + 0x15) = 1;
            }
        } else {
            if (getArwing() != 0) {
                *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) & ~0x4000);
                *(u8 *)(state + 0x15) = 1;
            }
        }
        return;
    case 1:
        r = (int)((f32)(u32) * (u8 *)(obj + 0x36) + lbl_803E70B4 * timeDelta);
        if (r > 0xff) r = 0xff;
        *(u8 *)(obj + 0x36) = (u8)r;
        bit = *(s16 *)(setup + 0x20);
        if (bit > -1) {
            if (GameBit_Get(bit) == 0)
                *(u8 *)(state + 0x15) = 1;
        }
        switch (*(u8 *)(state + 1)) {
        case 3:
        case 5:
            if (ObjHits_GetPriorityHit(obj, &hitA, 0, 0) != 0 && (hit = hitA) != 0 &&
                (*(s16 *)(hit + 0x46) == 0x604 || *(s16 *)(hit + 0x46) == 0x605)) {
                getArwing();
                fn_8022D520(getArwing(), 0xf);
                *(f32 *)(obj + 8) = *(f32 *)(*(int *)(obj + 0x50) + 4);
                Obj_SetActiveModelIndex(obj, 0);
                ObjHits_DisableObject(obj);
                *(u8 *)(state + 0x14) |= 0x80;
                if (*(void **)(state + 0x20) != NULL) {
                    ModelLightStruct_free(*(void **)(state + 0x20));
                    *(int *)(state + 0x20) = 0;
                }
            }
            fn_8022FA00(obj, state);
            break;
        case 2:
            if (ObjHits_GetPriorityHit(obj, &hitB, 0, 0) != 0 && (hit = hitB) != 0 &&
                (*(s16 *)(hit + 0x46) == 0x604 || *(s16 *)(hit + 0x46) == 0x605)) {
                getArwing();
                fn_8022D520(getArwing(), 0xf);
                *(f32 *)(obj + 8) = *(f32 *)(*(int *)(obj + 0x50) + 4);
                Obj_SetActiveModelIndex(obj, 0);
                ObjHits_DisableObject(obj);
                *(u8 *)(state + 0x14) |= 0x80;
                if (*(void **)(state + 0x20) != NULL) {
                    ModelLightStruct_free(*(void **)(state + 0x20));
                    *(int *)(state + 0x20) = 0;
                }
            }
            break;
        case 1:
        case 4:
            fn_8022FA00(obj, state);
            break;
        }
        if ((*(u8 *)(state + 0x14) & 0x80) != 0) {
            if (fn_8022D750(arwing) == 0 && fn_8022D710(arwing) == 0 &&
                fn_8022FCD8(obj, state, arwing) != 0) {
                fn_8022FB5C(obj, state, arwing);
            }
        }
        *(s16 *)(obj + 0) =
            (s16)(int)((f32)(int) * (s16 *)(obj + 0) + lbl_803E70B8 * timeDelta);
        break;
    case 2:
        if (*(f32 *)(state + 0x18) > lbl_803E70A0) {
            if (arwing != 0) {
                *(f32 *)(obj + 0x24) =
                    oneOverTimeDelta * (*(f32 *)(arwing + 0xc) - *(f32 *)(obj + 0xc));
                *(f32 *)(obj + 0x28) =
                    oneOverTimeDelta *
                    (*(f32 *)(state + 0x10) + (*(f32 *)(arwing + 0x10) - *(f32 *)(obj + 0x10)));
                *(f32 *)(obj + 0x2c) =
                    oneOverTimeDelta * (*(f32 *)(arwing + 0x14) - *(f32 *)(obj + 0x14));
                objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
                        *(f32 *)(obj + 0x2c) * timeDelta);
            }
            if (*(f32 *)(state + 0x18) > lbl_803E70BC) {
                *(s16 *)(obj + 0) =
                    (s16)(*(s16 *)(obj + 0) + lbl_8032B720[*(u8 *)(state)].f10);
                *(f32 *)(obj + 8) = (*(f32 *)(state + 0x18) - lbl_803E70BC) / lbl_803E70BC *
                                    *(f32 *)(*(int *)(obj + 0x50) + 4);
                if (lbl_803E70C0 != *(f32 *)(state + 0x18)) {
                    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
                    for (ang = -0x7fff; ang < 0x7fff;
                         ang += lbl_8032B720[*(u8 *)(state)].f8) {
                        dir[0] = lbl_803E70C4 *
                                 sin(lbl_803E70C8 *
                                     (f32)(ang +
                                           (int)(*(f32 *)(state + 0x18) *
                                                 lbl_8032B720[*(u8 *)(state)].f14)) /
                                     lbl_803E70CC);
                        dir[1] = lbl_803E70C4 *
                                 fn_80293E80(lbl_803E70C8 *
                                             (f32)(ang +
                                                   (int)(*(f32 *)(state + 0x18) *
                                                         lbl_8032B720[*(u8 *)(state)].f14)) /
                                             lbl_803E70CC);
                        dir[2] = lbl_803E70A0;
                        PSMTXMultVecSR(mtx, dir, dir);
                        spawnBuf[3] = dir[0] + *(f32 *)(obj + 0xc);
                        spawnBuf[4] = dir[1] + *(f32 *)(obj + 0x10);
                        spawnBuf[5] = dir[2] + *(f32 *)(obj + 0x14);
                        (*(void (**)(int, int, f32 *, int, int, int))(*gPartfxInterface + 8))(
                            obj, lbl_8032B720[*(u8 *)(state)].f0, spawnBuf, 0x200001, -1,
                            obj + 0x24);
                        (*(void (**)(int, int, f32 *, int, int, int))(*gPartfxInterface + 8))(
                            obj, lbl_8032B720[*(u8 *)(state)].f0, spawnBuf, 0x200001, -1,
                            obj + 0x24);
                    }
                }
                *(u8 *)(state + 0x14) |= 0x40;
            } else {
                if ((*(u8 *)(state + 0x14) & 0x40) != 0) {
                    for (ang = 0; ang < lbl_8032B720[*(u8 *)(state)].fc; ang++) {
                        (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(
                            obj, lbl_8032B720[*(u8 *)(state)].f4, 0, 2, -1, 0);
                    }
                }
                *(u8 *)(state + 0x14) &= ~0x40;
                *(u8 *)(obj + 0x36) = 0;
            }
            *(f32 *)(state + 0x18) -= timeDelta;
            if (*(f32 *)(state + 0x18) <= lbl_803E70A0) {
                *(f32 *)(state + 0x18) = lbl_803E70A0;
                *(f32 *)(obj + 0xc) = *(f32 *)(setup + 8);
                *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc);
                *(f32 *)(obj + 0x14) = *(f32 *)(setup + 0x10);
                *(s16 *)(obj + 0) = 0;
                *(u8 *)(obj + 0x36) = 0xff;
                *(f32 *)(obj + 8) = *(f32 *)(*(int *)(obj + 0x50) + 4);
                *(f32 *)(obj + 0x24) = lbl_803E70A0;
                *(f32 *)(obj + 0x28) = lbl_803E70A0;
                *(f32 *)(obj + 0x2c) = lbl_803E70A0;
                *(u8 *)(state + 0x15) = 3;
                *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) | 0x4000);
            }
        } else {
            *(f32 *)(state + 0x18) = lbl_803E70C0;
        }
        break;
    }

    if (*(void **)(state + 0x20) != NULL && fn_8001DB64(*(void **)(state + 0x20)) != 0) {
        lightFn_8001d6b0(*(void **)(state + 0x20));
    }
}
#pragma scheduling reset

extern f32 lbl_803E6EC8;
extern f32 lbl_803E6ED4;
extern f32 lbl_803E6ED8;
extern void debugPrintSetColor(int r, int g, int b, int a);
extern int padGetStickX(int controller);
extern int padGetStickY(int controller);
extern int padGetRTrigger(int controller);
extern int padGetLTrigger(int controller);
extern int getButtonsJustPressedIfNotBusy(int controller);
extern int getButtonsHeld(int controller);
extern f32 lbl_8032B4A8[];

#pragma scheduling off
void fn_8022A670(int obj, int state)
{
    f32 nx;
    f32 ny;
    f32 tv;
    int btn;

    debugPrintSetColor(0xff, 0xff, 0xff, 0xff);
    *(f32 *)(state + 0x3e4) = (f32)(s8)padGetStickX(0) / lbl_803E6EC8;
    *(f32 *)(state + 0x3e8) = (f32)(s8)padGetStickY(0) / lbl_803E6EC8;
    if (*(f32 *)(state + 0x328) > lbl_803E6ECC) {
        nx = -*(f32 *)(state + 0x32c);
        ny = -*(f32 *)(state + 0x330);
        *(f32 *)(state + 0x328) = *(f32 *)(state + 0x328) - timeDelta;
        tv = lbl_8032B4A8[(int)*(f32 *)(state + 0x328)];
        if (*(f32 *)(state + 0x328) <= lbl_803E6ECC) {
            *(u8 *)(state + 0x338) = 0;
            (*(void (**)(int, int))(*gPathControlInterface + 0x20))(obj, state + 0xc0);
        }
        *(f32 *)(state + 0x3e4) =
            *(f32 *)(state + 0x3e4) * (lbl_803E6ED0 - tv) + nx * tv;
        *(f32 *)(state + 0x3e8) =
            *(f32 *)(state + 0x3e8) * (lbl_803E6ED0 - tv) + ny * tv;
    }
    *(f32 *)(state + 0x3ec) = (f32)(u32)(u8)padGetRTrigger(0) / lbl_803E6ED4;
    if (*(f32 *)(state + 0x3ec) < lbl_803E6ECC)
        *(f32 *)(state + 0x3ec) = lbl_803E6ECC;
    else if (*(f32 *)(state + 0x3ec) > lbl_803E6ED0)
        *(f32 *)(state + 0x3ec) = lbl_803E6ED0;
    *(f32 *)(state + 0x3f0) = -(f32)(u32)(u8)padGetLTrigger(0) / lbl_803E6ED4;
    if (*(f32 *)(state + 0x3f0) < lbl_803E6ED8)
        *(f32 *)(state + 0x3f0) = lbl_803E6ED8;
    else if (*(f32 *)(state + 0x3f0) > lbl_803E6ECC)
        *(f32 *)(state + 0x3f0) = lbl_803E6ECC;
    *(u16 *)(state + 0x3f4) = (u16)getButtonsJustPressed(0);
    *(u16 *)(state + 0x3f6) = (u16)getButtonsJustPressedIfNotBusy(0);
    *(u16 *)(state + 0x3f8) = (u16)getButtonsHeld(0);
    if (*(u8 *)(state + 0x478) == 0) {
        btn = *(u16 *)(state + 0x3f4);
        if ((btn & 0x20) != 0) {
            Sfx_PlayFromObject(obj, 0x2a4);
            *(u8 *)(state + 0x478) = 1;
            *(int *)(state + 0x398) = *(s16 *)(obj + 4);
            *(f32 *)(state + 0x3a0) = *(f32 *)(state + 0x39c);
            *(f32 *)(state + 0x3a8) = lbl_803E6ED0;
            *(f32 *)(state + 0x54) = *(f32 *)(state + 0x54) * *(f32 *)(state + 0x3ac);
            *(f32 *)(state + 0x60) = *(f32 *)(state + 0x60) * *(f32 *)(state + 0x3b0);
            arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 1, 0);
        } else if ((btn & 0x40) != 0) {
            Sfx_PlayFromObject(obj, 0x2a4);
            *(u8 *)(state + 0x478) = 1;
            *(int *)(state + 0x398) = *(s16 *)(obj + 4);
            *(f32 *)(state + 0x3a0) = -*(f32 *)(state + 0x39c);
            *(f32 *)(state + 0x3a8) = lbl_803E6ED0;
            *(f32 *)(state + 0x54) = *(f32 *)(state + 0x54) * *(f32 *)(state + 0x3ac);
            *(f32 *)(state + 0x60) = *(f32 *)(state + 0x60) * *(f32 *)(state + 0x3b0);
            arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 1, 1);
        }
    }
}
#pragma scheduling reset

extern f32 lbl_803E6EF8;

#pragma scheduling off
void fn_8022AB68(int obj, int state)
{
    int tgt;
    int cur;
    int d;

    *(int *)(state + 0x398) =
        (int)(timeDelta * (*(f32 *)(state + 0x3a0) * *(f32 *)(state + 0x3a8)) +
              (f32) * (int *)(state + 0x398));
    *(s16 *)(obj + 4) =
        (s16)(int)(timeDelta * (*(f32 *)(state + 0x3a0) * *(f32 *)(state + 0x3a8)) +
                   (f32) * (s16 *)(obj + 4));
    if (*(f32 *)(state + 0x3a0) > lbl_803E6ECC) {
        tgt = *(int *)(state + 0x380);
        cur = *(int *)(state + 0x398);
        if (cur > tgt + 0xffff) {
            *(u8 *)(state + 0x478) = 0;
            *(int *)(state + 0x380) = *(int *)(state + 0x398) - 0xffff;
            *(f32 *)(state + 0x38c) = lbl_803E6ECC;
            *(f32 *)(state + 0x54) = *(f32 *)(state + 0x54) / *(f32 *)(state + 0x3ac);
            *(f32 *)(state + 0x60) = *(f32 *)(state + 0x60) / *(f32 *)(state + 0x3b0);
            arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
        } else if (cur > tgt + 0x8000) {
            d = cur - (u16)tgt;
            if (d > 0x8000) d -= 0xffff;
            if (d < -0x8000) d += 0xffff;
            if (d < 0) d = -d;
            *(f32 *)(state + 0x3a8) = (f32)d / *(f32 *)(state + 0x3a4);
            if (*(f32 *)(state + 0x3a8) < lbl_803E6EF8)
                *(f32 *)(state + 0x3a8) = lbl_803E6EF8;
            else if (*(f32 *)(state + 0x3a8) > lbl_803E6ED0)
                *(f32 *)(state + 0x3a8) = lbl_803E6ED0;
        }
    } else {
        tgt = *(int *)(state + 0x380);
        cur = *(int *)(state + 0x398);
        if (cur < tgt - 0xffff) {
            *(u8 *)(state + 0x478) = 0;
            *(int *)(state + 0x380) = *(int *)(state + 0x398) + 0xffff;
            *(f32 *)(state + 0x38c) = lbl_803E6ECC;
            *(f32 *)(state + 0x54) = *(f32 *)(state + 0x54) / *(f32 *)(state + 0x3ac);
            *(f32 *)(state + 0x60) = *(f32 *)(state + 0x60) / *(f32 *)(state + 0x3b0);
            arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
        } else if (cur > tgt - 0x8000) {
            d = cur - (u16)tgt;
            if (d > 0x8000) d -= 0xffff;
            if (d < -0x8000) d += 0xffff;
            if (d < 0) d = -d;
            *(f32 *)(state + 0x3a8) = (f32)d / *(f32 *)(state + 0x3a4);
            if (*(f32 *)(state + 0x3a8) < lbl_803E6EF8)
                *(f32 *)(state + 0x3a8) = lbl_803E6EF8;
            else if (*(f32 *)(state + 0x3a8) > lbl_803E6ED0)
                *(f32 *)(state + 0x3a8) = lbl_803E6ED0;
        }
    }
}
#pragma scheduling reset
