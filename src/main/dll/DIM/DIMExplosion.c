#include "ghidra_import.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DIM/DIMExplosion.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"

extern undefined4 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern void ObjHitbox_SetStateIndex(int obj, ObjHitsPriorityState *hitState, int stateIndex);
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293900();
extern int FUN_80294dbc();

extern undefined4 DAT_80324800;
extern undefined4 DAT_80324802;
extern undefined4 DAT_80324804;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcb50;
extern f64 DOUBLE_803e54f0;
extern f64 DOUBLE_803e5500;
extern f64 DOUBLE_803e5508;
extern f64 DOUBLE_803e5528;
extern f32 lbl_803DC078;
extern f32 lbl_803E54E4;
extern f32 lbl_803E54E8;
extern f32 lbl_803E54EC;
extern f32 lbl_803E54FC;
extern f32 lbl_803E5510;
extern f32 lbl_803E5518;
extern f32 lbl_803E551C;
extern f32 lbl_803E5520;

/* Trivial 4b 0-arg blr leaves. */
void dimsnowball1c2_free(void) {}
void dimsnowball1c2_hitDetect(void) {}
void dimsnowball1c2_release(void) {}
void dimsnowball1c2_initialise(void) {}
void dimgate_free(void) {}
void dimgate_hitDetect(void) {}
void dimgate_release(void) {}
void dimgate_initialise(void) {}
void dimbarrier_free(void) {}
void dimbarrier_hitDetect(void) {}
void dimbarrier_release(void) {}
void dimbarrier_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int dimsnowball1c2_getObjectTypeId(void) { return 0x0; }
int dimgate_SeqFn(void) { return 0x0; }
int dimgate_getExtraSize(void) { return 0x1; }
int dimgate_getObjectTypeId(void) { return 0x0; }
int dimicewall_getExtraSize(void) { return 0x2; }
int dimbarrier_getExtraSize(void) { return 0x4; }
int dimbarrier_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4860;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4878;
extern f32 lbl_803E4898;
void dimsnowball1c2_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4860); }
void dimgate_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4878); }
void dimbarrier_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4898); }

void dimsnowball1c2_init(int obj, u8 *p) {
    char *inner;
    *(s16 *)obj = (s16)((u32)p[0x1c] << 8);
    inner = ((GameObject *)obj)->extra;
    *(s16 *)(inner + 2) = *(s16 *)(p + 0x18);
    *(s16 *)inner = *(s16 *)(p + 0x18);
    ((GameObject *)obj)->objectFlags |= 0x6000;
}
void dimicewall_init(int obj, s8 *p) {
    char *inner = ((GameObject *)obj)->extra;
    *(s8 *)(inner + 0) = (s8)*(s16 *)(p + 0x1a);
    if (*(s16 *)(p + 0x1e) != -1) {
        *(u8 *)(inner + 1) = (u8)GameBit_Get(*(s16 *)(p + 0x1e));
    }
    *(s16 *)obj = (s16)((s32)p[0x18] << 8);
    ((GameObject *)obj)->objectFlags |= 0x4000;
}
void dimgate_init(int obj, s8 *p_unused_passthrough) {
    char *inner;
    char *param;
    param = *(char **)&((GameObject *)obj)->anim.placementData;
    inner = ((GameObject *)obj)->extra;
    if (GameBit_Get(*(s16 *)(param + 0x1e)) != 0) {
        inner[0] = 2;
        ((GameObject *)obj)->anim.currentMoveProgress = lbl_803E4878;
    } else {
        inner[0] = 0;
    }
    ((GameObject *)obj)->animEventCallback = (void *)dimgate_SeqFn;
    *(s16 *)obj = (s16)((s32)param[0x18] << 8);
    ((GameObject *)obj)->objectFlags |= 0x6000;
}
void dimbarrier_init(int obj, s8 *p) {
    char *inner;
    *(s16 *)obj = (s16)((s32)p[0x18] << 8);
    ((GameObject *)obj)->objectFlags |= 0x6000;
    inner = ((GameObject *)obj)->extra;
    inner[3] = 1;
    inner[2] = 0;
    if (GameBit_Get(*(s16 *)(p + 0x1e)) != 0) {
        ObjHitsPriorityState *hitState;
        inner[3] = 0;
        hitState = (ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject *)obj)->anim.alpha = 0;
        inner[2] = 2;
    }
}

int fn_801B17F4(int obj, int delta) {
    s8 *inner = ((GameObject *)obj)->extra;
    inner[0] = (s8)(inner[0] - delta);
    return inner[0] <= 0;
}

/* dimgate_update: open the gate (hitbox state 1->2) once a type-399 object is
 * present in the trigger list, latching the gamebit. */
void dimgate_update(int *obj)
{
    int *extra = ((GameObject *)obj)->extra;
    int *def = *(int **)&((GameObject *)obj)->anim.placementData;
    switch (*(s8 *)extra) {
    case 0: {
        ObjHitsPriorityState *hitState = (ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState;
        int *list;
        int found;
        int i;
        if (hitState->stateIndex != 1) {
            ObjHitbox_SetStateIndex((int)obj, hitState, 1);
        }
        found = 0;
        list = *(int **)((char *)obj + 0x58);
        for (i = 0; i < *(s8 *)((char *)list + 0x10f); i++) {
            if (*(s16 *)((char *)*(int **)((char *)list + 0x100 + i * 4) + 0x46) == 399) {
                found = 1;
                break;
            }
        }
        if (found) {
            GameBit_Set(*(s16 *)((char *)def + 0x1e), 1);
            if (hitState->stateIndex != 2) {
                ObjHitbox_SetStateIndex((int)obj, hitState, 2);
            }
            *(s8 *)extra = 2;
        }
        break;
    }
    case 1:
        break;
    case 2: {
        ObjHitsPriorityState *hitState = (ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState;
        if (hitState->stateIndex != 2) {
            ObjHitbox_SetStateIndex((int)obj, hitState, 2);
        }
        break;
    }
    }
}

extern int Sfx_PlayFromObject(int obj, int sfx);
extern u8 framesThisStep;

/* dimbarrier_update: while a live type-470 object is in the list, count down the
 * arm timer; on expiry fade the barrier out and latch its gamebit. */
void dimbarrier_update(int *obj)
{
    int *def = *(int **)&((GameObject *)obj)->anim.placementData;
    int *extra = ((GameObject *)obj)->extra;
    switch (*(u8 *)((char *)extra + 2)) {
    case 0: {
        int *list = *(int **)((char *)obj + 0x58);
        int found = 0;
        int i;
        for (i = 0; i < *(s8 *)((char *)list + 0x10f); i++) {
            int *entry = *(int **)((char *)list + 0x100 + i * 4);
            if (*(s16 *)((char *)entry + 0x46) == 470 &&
                *(u8 *)((char *)*(int **)((char *)entry + 0xb8) + 4) != 0) {
                found = 1;
                break;
            }
        }
        if (found) {
            s8 v = *(u8 *)((char *)extra + 3) - 1;
            *(s8 *)((char *)extra + 3) = v;
            if (v <= 0) {
                *(s8 *)((char *)extra + 2) = 1;
                *(s16 *)extra = 30;
                Sfx_PlayFromObject((int)obj, SFXthorntail_chew1);
            } else {
                Sfx_PlayFromObject((int)obj, SFXthorntail_chew2);
            }
        }
        break;
    }
    case 1: {
        int v = ((GameObject *)obj)->anim.alpha - framesThisStep * 16;
        if (v < 0) {
            v = 0;
        }
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~1;
        ((GameObject *)obj)->anim.alpha = v;
        *(s16 *)extra = *(s16 *)extra - framesThisStep;
        if (*(s16 *)extra <= 0) {
            GameBit_Set(*(s16 *)((char *)def + 0x1e), 1);
            *(s8 *)((char *)extra + 2) = 2;
        }
        break;
    }
    }
}

extern u8 Obj_IsLoadingLocked(void);
extern int fn_802972A8(int player);
extern int Obj_AllocObjectSetup(int kind, int id);
extern int Obj_SetupObject(int handle, int a, int b, int c, int d);
extern f32 lbl_803E4864;

/* dimsnowball1c2_update: on a timer, if loading allows and the player is clear,
 * spawn a rolling snowball seeded from the placement params. */
void dimsnowball1c2_update(int *obj)
{
    if (Obj_IsLoadingLocked()) {
        int *extra = ((GameObject *)obj)->extra;
        *(s16 *)extra = *(s16 *)extra - framesThisStep;
        if (*(s16 *)extra <= 0) {
            if (fn_802972A8(Obj_GetPlayerObject()) == 0) {
                int *def = *(int **)&((GameObject *)obj)->anim.placementData;
                int *np = (int *)Obj_AllocObjectSetup(36, 406);
                *(u8 *)((char *)np + 4) = *(u8 *)((char *)def + 4);
                *(u8 *)((char *)np + 6) = *(u8 *)((char *)def + 6);
                *(u8 *)((char *)np + 5) = *(u8 *)((char *)def + 5);
                *(u8 *)((char *)np + 7) = *(u8 *)((char *)def + 7);
                *(f32 *)((char *)np + 8) = ((GameObject *)obj)->anim.localPosX;
                *(f32 *)((char *)np + 0xc) = ((GameObject *)obj)->anim.localPosY;
                *(f32 *)((char *)np + 0x10) = ((GameObject *)obj)->anim.localPosZ;
                *(int *)((char *)np + 0x14) = *(int *)((char *)def + 0x14);
                *(s8 *)((char *)np + 0x18) = *(s8 *)((char *)def + 0x1c);
                *(s16 *)((char *)np + 0x1a) = *(u8 *)((char *)def + 0x1a);
                *(s16 *)((char *)np + 0x1c) =
                    (int)((f32)(u32)*(u8 *)((char *)def + 0x1b) +
                          (f32)(int)randomGetRange(0, 100) / lbl_803E4864);
                Obj_SetupObject((int)np, 5, ((GameObject *)obj)->anim.mapEventSlot, -1, 0);
                *(s16 *)extra = *(s16 *)((char *)extra + 2);
            }
        }
    }
}

extern void objMove(int *obj, f32 x, f32 y, f32 z);
extern void ObjHits_SetHitVolumeSlot(int *obj, int a, int b, int c);
extern void ObjHitbox_SetSphereRadius(int *obj, int radius);
extern void spawnExplosion(int *obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern void Obj_FreeObject(int *obj);
extern f32 timeDelta;
extern f32 lbl_803E48A0;
extern f32 lbl_803E48A4;
extern f32 lbl_803E48A8;
extern f32 lbl_803DBEF0;

/* DIMwooddoor_updateFallingDebris: integrate the falling debris under gravity, spin it, and on
 * contact (or scripted trigger) fire the explosion and start the despawn timer. */
void DIMwooddoor_updateFallingDebris(int *obj)
{
    int *extra = ((GameObject *)obj)->extra;
    switch (*(u8 *)((char *)extra + 8)) {
    case 0: {
        f32 oldvy = ((GameObject *)obj)->anim.velocityY;
        ObjHitsPriorityState *hitState;
        ((GameObject *)obj)->anim.velocityY = lbl_803E48A4 * -lbl_803DBEF0 * timeDelta + oldvy;
        objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta,
                lbl_803E48A8 * (oldvy + ((GameObject *)obj)->anim.velocityY) * timeDelta,
                ((GameObject *)obj)->anim.velocityZ * timeDelta);
        ((GameObject *)obj)->anim.rotZ = ((GameObject *)obj)->anim.rotZ + *(s8 *)((char *)extra + 9) * 10;
        ((GameObject *)obj)->anim.rotY = ((GameObject *)obj)->anim.rotY + *(s8 *)((char *)extra + 0xa) * 10;
        *(s16 *)obj = *(s16 *)obj + *(s8 *)((char *)extra + 0xb) * 10;
        hitState = (ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState;
        if (hitState != NULL) {
            int *vol;
            ObjHits_SetHitVolumeSlot(obj, 5, *(s8 *)((char *)extra + 6), 0);
            vol = (int *)hitState->lastHitObject;
            if (vol != NULL && vol != *(int **)extra) {
                ObjHitbox_SetSphereRadius(obj, *(s8 *)((char *)extra + 5));
                spawnExplosion(obj, lbl_803E48A0, 2, 1, 0, 1, 1, 1, 0);
                ((GameObject *)obj)->unkF4 = 1180;
                *(s8 *)((char *)extra + 8) = 1;
                ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
        if ((GameBit_Get(2142) != 0 && GameBit_Get(3117) == 0) ||
            (GameBit_Get(2164) != 0 && GameBit_Get(3118) == 0)) {
            ((GameObject *)obj)->unkF4 = 1200;
        }
        if (hitState->contactFlags != 0) {
            ObjHitbox_SetSphereRadius(obj, *(s8 *)((char *)extra + 5));
            spawnExplosion(obj, lbl_803E48A0, 2, 1, 0, 1, 1, 1, 0);
            ((GameObject *)obj)->unkF4 = 1180;
            *(s8 *)((char *)extra + 8) = 1;
            ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        break;
    }
    case 1:
        break;
    }
    ((GameObject *)obj)->unkF4 = ((GameObject *)obj)->unkF4 + framesThisStep;
    if (((GameObject *)obj)->unkF4 > 1200) {
        Obj_FreeObject(obj);
    } else if (*(u8 *)((char *)extra + 7) != 0) {
        *(s8 *)((char *)extra + 7) = 0;
    }
}

extern int *getTrickyObject(void);
extern void objRenderFn_80041018(int *obj);
extern EffectInterface **gPartfxInterface;
extern f32 lbl_803E4880;
extern f32 lbl_803E4884;
extern f32 lbl_803E4888;

/* dimicewall_update: on shatter, emit two snow particle bursts and latch the
 * gamebit; otherwise let Tricky push through it. */
void dimicewall_update(int *obj)
{
    int *extra = ((GameObject *)obj)->extra;
    int *def = *(int **)&((GameObject *)obj)->anim.placementData;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    if (*(u8 *)((char *)extra + 1) == 0) {
        if (*(s8 *)extra <= 0) {
            f32 desc[6];
            int i;
            desc[2] = (f32)(s8)*(s8 *)((char *)def + 0x19) / lbl_803E4880;
            desc[5] = lbl_803E4884;
            for (i = 45; i != 0; i--) {
                desc[3] = desc[2] * (lbl_803E4888 * (f32)(int)randomGetRange(-250, 250));
                desc[4] = desc[2] * (lbl_803E4888 * (f32)(int)randomGetRange(0, 450));
                (*gPartfxInterface)->spawnObject(obj, 2041, desc, 2, -1, NULL);
            }
            for (i = 25; i != 0; i--) {
                desc[3] = desc[2] * (lbl_803E4888 * (f32)(int)randomGetRange(-250, 250));
                desc[4] = desc[2] * (lbl_803E4888 * (f32)(int)randomGetRange(0, 450));
                (*gPartfxInterface)->spawnObject(obj, 2042, desc, 2, -1, NULL);
            }
            if (*(int *)((char *)def + 0x14) != 7433) {
                Sfx_PlayFromObject((int)obj, 1147);
            }
            *(u8 *)((char *)extra + 1) = 1;
            if (*(s16 *)((char *)def + 0x1e) != -1) {
                GameBit_Set(*(s16 *)((char *)def + 0x1e), 1);
            }
        } else {
            int *tricky = getTrickyObject();
            if (tricky != NULL) {
                if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0) {
                    (*(void (**)(int *, int *, int, int))(**(int **)((char *)tricky + 0x68) + 0x28))(tricky, obj, 1, 4);
                }
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
                objRenderFn_80041018(obj);
            }
        }
    }
}
