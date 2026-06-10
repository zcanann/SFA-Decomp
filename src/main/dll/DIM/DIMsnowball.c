#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objanim.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/dll/DIM/DIMsnowball.h"

extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern undefined4 FUN_80006c88();
extern undefined4 FUN_80017680();
extern undefined4 FUN_80017688();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017708();
extern double FUN_80017714();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a6c();
extern undefined4 FUN_80017a78();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern int ObjHits_PollPriorityHitWithCooldown();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern int ObjTrigger_IsSetById();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern void objRenderFn_8003b8f4(f32);
extern undefined4 FUN_80048000();
extern undefined4 FUN_8004800c();
extern undefined4 FUN_80080f14();
extern undefined4 FUN_800810e8();
extern undefined4 FUN_800810f8();
extern undefined4 FUN_80081120();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_801141e8();
extern undefined4 FUN_801149bc();
extern undefined4 FUN_80114b10();
extern undefined4 dll_2E_func03();
extern void dll_2E_func06(int *obj, void *state, int flags);
extern undefined4 FUN_801150ac();
extern undefined4 FUN_8012f744();
extern char FUN_80132034();
extern double FUN_8014cbcc();
extern undefined4 FUN_8014ccac();
extern undefined4 FUN_801aa4a4();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern undefined4 FUN_80286834();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern byte FUN_80294c20();
extern int FUN_80294c54();

extern undefined4 DAT_80324048;
extern undefined4 DAT_80324058;
extern undefined4 DAT_80324068;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd718;
extern undefined4 DAT_803de7b8;
extern undefined4 DAT_803e52e8;
extern undefined4 DAT_803e52ec;
extern undefined4 DAT_803e52f0;
extern undefined4 DAT_803e52f4;
extern f64 DOUBLE_803e52e0;
extern f64 DOUBLE_803e5338;
extern f32 lbl_803DC074;
extern f32 lbl_803E52B0;
extern f32 lbl_803E52B4;
extern f32 lbl_803E4660;
extern f32 lbl_803E52BC;
extern f32 lbl_803E52C0;
extern f32 lbl_803E52C4;
extern f32 lbl_803E52C8;
extern f32 lbl_803E52CC;
extern f32 lbl_803E52D0;
extern f32 lbl_803E52D4;
extern f32 lbl_803E52D8;
extern f32 lbl_803E52FC;
extern f32 lbl_803E5300;
extern f32 lbl_803E5308;
extern f32 lbl_803E530C;
extern f32 lbl_803E5310;
extern f32 lbl_803E5314;
extern f32 lbl_803E5318;
extern f32 lbl_803E531C;
extern f32 lbl_803E5320;
extern f32 lbl_803E5324;
extern f32 lbl_803E5328;
extern f32 lbl_803E5330;
extern f32 lbl_803E5340;
extern f32 lbl_803E5344;
extern f32 lbl_803E5348;
extern f32 lbl_803E534C;
extern f32 lbl_803E5350;
extern f32 lbl_803E5354;
extern f32 lbl_803E5358;
extern f32 lbl_803E535C;
extern f32 lbl_803E5360;
extern f32 lbl_803E5368;

/*
 * --INFO--
 *
 * Function: ccqueen_render
 * EN v1.0 Address: 0x801AA560
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x801AA584
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ccqueen_render(int *obj, int p2, int p3, int p4, int p5, s8 visible)
{
  void *state = ((GameObject *)obj)->extra;
  objRenderFn_8003b8f4(lbl_803E4660);
  dll_2E_func06(obj, state, 0);
}

/*
 * --INFO--
 *
 * Function: FUN_801aa684
 * EN v1.0 Address: 0x801AA684
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801AA6C0
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801aaa6c
 * EN v1.0 Address: 0x801AAA6C
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801AAE2C
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aaa6c(double param_1,int param_2,int param_3)
{
  if ((double)lbl_803E530C == param_1) {
    *(undefined *)(param_2 + 0x10) = 0xc;
    return;
  }
  if ((*(byte *)(param_2 + 0x11) & 2) != 0) {
    *(undefined *)(param_2 + 0x10) = 1;
    return;
  }
  if ((double)lbl_803E5310 <= param_1) {
    *(undefined *)(param_2 + 0x10) = 2;
    return;
  }
  if ((*(short *)(param_3 + 0xa0) == 0x18) && (lbl_803E5314 < *(float *)(param_3 + 0x98))) {
    *(undefined *)(param_2 + 0x10) = 8;
    return;
  }
  if (*(short *)(param_3 + 0xa0) == 0x19) {
    *(undefined *)(param_2 + 0x10) = 5;
    return;
  }
  *(undefined *)(param_2 + 0x10) = 0xb;
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_801abf38
 * EN v1.0 Address: 0x801ABF38
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x801AC038
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801abf38(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,ObjAnimUpdateState *animUpdate)
{
  if (animUpdate->eventCount != 0) {
    FUN_8008112c((double)lbl_803E5360,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,1,1,0,1,1,1,0);
  }
  return 0;
}


/* 8b "li r3, N; blr" returners. */
int cclightfoot_getExtraSize(void) { return 0x18; }
int ccsharpclawpad_getExtraSize(void) { return 0x4; }
int ccpedstal_getExtraSize(void) { return 0x8; }
int cclevcontrol_getExtraSize(void) { return 0x10; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E46CC;
void cclevcontrol_render(void) { objRenderFn_8003b8f4(lbl_803E46CC); }

/* Drift-recovery: add new fns with v1.0 names. */
extern void envFxActFn_800887f8(int a);
extern void Music_Trigger(int a, int b);
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern f32 lbl_803E46C8;


#pragma scheduling off
#pragma peephole off
void ccsharpclawpad_init(int* obj, int* def)
{
    *(s16*)obj = (s16)((u32)*(u8*)((char*)def + 24) << 8);
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x4000);
}

void cclevcontrol_free(void)
{
    envFxActFn_800887f8(0);
    Music_Trigger(200, 0);
}

void cclightfoot_init(int* obj, int* def)
{
    *(s16*)obj = (s16)((u32)*(u8*)((char*)def + 26) << 8);
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x4000);
    ((GameObject *)obj)->animEventCallback = (void *)ccqueen_SeqFn;
}

int cclevcontrol_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
    if (animUpdate->eventCount != 0) {
        spawnExplosion(obj, lbl_803E46C8, 1, 1, 0, 1, 1, 1, 0);
    }
    return 0;
}

/* ObjLink_DetachChild and Obj_FreeObject already declared in earlier extern blocks */

void cclightfoot_free(int* obj, int p2)
{
    int* state = ((GameObject *)obj)->extra;
    int* sub = (int*)state[0];
    if (sub != NULL) {
        if (((GameObject *)obj)->unkC8 != NULL) {
            ObjLink_DetachChild(obj, sub);
        }
        if (p2 == 0) {
            Obj_FreeObject((int*)state[0]);
        }
    }
}

extern void fn_80088870(void *a, void *b, void *c, void *d);
extern int getSaveGameLoadStatus(void);
extern void getEnvfxActImmediately(void *obj, void *target, int animId, int flags);
extern void getEnvfxAct(int obj, int target, int id, int p);
extern MapEventInterface **gMapEventInterface;
extern int lbl_80323548[];
extern f32 lbl_803E46D4;
extern void ccpedstal_updateGameBitGate(int obj, u8* state2);
extern void ccpedstal_updateAltVariant(int obj, u8* state2);
extern void fn_8002B6D8(void *obj, int p2, int p3, int p4, int p5, int p6);

void ccpedstal_init(int *obj, u8 *params) {
    u8 *state = ((GameObject *)obj)->extra;
    *(s16 *)obj = (s16)((u32)params[0x1a] << 8);
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x4000);
    switch (*(int *)(params + 0x14)) {
    case 0x45f1a:
        *(void **)state = (void *)ccpedstal_updateAltVariant;
        *(s16 *)(state + 4) = 0xaa;
        fn_8002B6D8(obj, 0, 0, 0, 0, 3);
        break;
    case 0x45f1b:
        *(void **)state = (void *)ccpedstal_updateGameBitGate;
        *(s16 *)(state + 4) = 0xf1;
        break;
    case 0x45f1c:
        *(void **)state = (void *)ccpedstal_updateGameBitGate;
        *(s16 *)(state + 4) = 0xfe;
        break;
    }
}

void cclevcontrol_init(int *obj) {
    void *envfxTable;
    int *state;
    envfxTable = lbl_80323548;
    state = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->animEventCallback = (void *)cclevcontrol_SeqFn;
    fn_80088870((char *)envfxTable + 0x38, envfxTable, (char *)envfxTable + 0x70, (char *)envfxTable + 0xa8);
    if (getSaveGameLoadStatus() != 0) {
        envFxActFn_800887f8(0x3f);
        getEnvfxActImmediately((void *)0, (void *)0, 0x242, 0);
    } else {
        envFxActFn_800887f8(0x1f);
        getEnvfxAct(0, 0, 0x242, 0);
    }
    *(f32 *)state = lbl_803E46D4;
    state[2] = -1;
    state[3] = (u32)(u8)(*gMapEventInterface)->getMode(((GameObject *)obj)->anim.mapEventSlot);
}


extern f32 lbl_803E4674;
extern f32 lbl_803E4678;
extern f32 lbl_803E467C;

#pragma dont_inline on
#pragma scheduling on
void fn_801AA878(u8* p1, int* p2, f32 v) {
    s16 t;
    if (lbl_803E4674 == v) {
        p1[16] = 12;
        return;
    }
    if ((p1[17] & 2) != 0) {
        p1[16] = 1;
        return;
    }
    if (v < lbl_803E4678) {
        t = *(s16*)((char*)p2 + 160);
        if (t == 24 && *(f32*)((char*)p2 + 152) > lbl_803E467C) {
            p1[16] = 8;
            return;
        }
        if (t == 25) {
            p1[16] = 5;
            return;
        }
        p1[16] = 11;
        return;
    }
    p1[16] = 2;
}
#pragma dont_inline reset

extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void gameBitDecrement(int id);

/* ccpedstal_updateGameBitGate: state2-driven model + trigger gate. If state2's gamebit at
 * +0x4 is set, latches obj[0xaf] bit 8 and selects model index 1.
 * Otherwise selects model 0, then consults gbit 0xa9: if set, clears the
 * 0x10 flag and (if the obj's trigger 0xa9 is set) fires vtable[0x12],
 * decrements the gamebit, and flags state2[0x6] bit 0. If gbit 0xa9 is
 * clear, sets the obj[0xaf] 0x10 flag instead. */
#pragma scheduling off
void ccpedstal_updateGameBitGate(int obj, u8* state2) {
    if (GameBit_Get(*(s16*)(state2 + 0x4)) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8);
        Obj_SetActiveModelIndex(obj, 1);
    } else {
        int doMark;
        Obj_SetActiveModelIndex(obj, 0);
        if (GameBit_Get(0xa9) != 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x10);
            if (ObjTrigger_IsSetById(obj, 0xa9) != 0) {
                (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
                gameBitDecrement(0xa9);
                doMark = 1;
                goto check;
            }
        } else {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x10);
        }
        doMark = 0;
    check:
        if (doMark != 0) {
            state2[0x6] = (u8)(state2[0x6] | 1);
        }
    }
}

extern int ObjTrigger_IsSet(int obj);
extern void gameBitIncrement(int id);

/* ccpedstal_updateAltVariant: ccpedstal alt-variant think-routine. Toggles obj[0xaf]
 * bit 8 from gbit 0xdc5, then reads state2's gamebit at +0x4: if set,
 * sets bit 8 again and selects model 0; if clear, selects model 1 and
 * (when the obj's pending trigger is asserted) fires vtable[0x12] with
 * id=1, increments gbit 0xa9, and latches state2[0x6] bit 0. Mirrors
 * the no-mark branches into a shared r0=0/cmpwi end-check via goto to
 * match target's layout. */
void ccpedstal_updateAltVariant(int obj, u8* state2) {
    if (GameBit_Get(0xdc5) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8);
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~8);
    }
    if (GameBit_Get(*(s16*)(state2 + 0x4)) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8);
        Obj_SetActiveModelIndex(obj, 0);
    } else {
        int doMark;
        Obj_SetActiveModelIndex(obj, 1);
        if (ObjTrigger_IsSet(obj) != 0) {
            (*gObjectTriggerInterface)->runSequence(1, (void *)obj, -1);
            gameBitIncrement(0xa9);
            doMark = 1;
            goto check;
        }
        doMark = 0;
    check:
        if (doMark != 0) {
            state2[0x6] = (u8)(state2[0x6] | 1);
        }
    }
}

extern WaterfxInterface **gWaterfxInterface;
extern f32 lbl_803E4670;

extern void dll_2E_func05(int *obj, u8 *sub, int a, int b, int c);
extern void dll_2E_func08(u8 *sub, int a, int b);
extern void dll_2E_func09(u8 *sub, void *a, void *b, int c);

typedef struct { s16 v[3]; } _S16x3;
extern _S16x3 lbl_803E4650;
extern _S16x3 lbl_803E4658;

void ccqueen_init(int *obj, u8 *init) {
    u8 *sub;
    _S16x3 buf2;
    _S16x3 buf1;
    sub = ((GameObject *)obj)->extra;
    buf2 = lbl_803E4650;
    buf1 = lbl_803E4658;
    *(s16*)obj = (s16)(init[0x1a] << 8);
    dll_2E_func05(obj, sub, 0x71c7, 0x3555, 3);
    dll_2E_func08(sub, 0x258, 0xf0);
    dll_2E_func09(sub, &buf1, &buf2, 3);
    sub[0x611] = (u8)(sub[0x611] | 0xa);
}
extern f32 lbl_803E4664;
extern f32 lbl_803E4668;
extern f32 timeDelta;
extern f32 vec3f_distanceSquared(f32* p1, f32* p2);
extern void characterDoEyeAnims(int obj, void* p);
extern void *Obj_GetPlayerObject(void);
extern void ObjHits_DisableObject_xx(int *obj);

void ccqueen_update(int *obj) {
    u8 *sub;
    int *player;

    sub = ((GameObject *)obj)->extra;
    if (GameBit_Get(0x1c2) == 0 && GameBit_Get(0xa3) != 0) {
        player = (int*)Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&((GameObject *)obj)->anim.worldPosX, &((GameObject *)player)->anim.worldPosX) < lbl_803E4664) {
            GameBit_Set(0x1c2, 1);
        }
    }
    if (GameBit_Get(0x1c3) != 0) {
        ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x8000);
        ObjHits_DisableObject(obj);
    } else {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E4668, timeDelta, NULL);
        dll_2E_func03(obj, sub);
        characterDoEyeAnims((int)obj, sub + 0x624);
    }
}

int ccqueen_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate) {
    int* state = ((GameObject *)obj)->extra;
    if (animUpdate->eventCount != 0) {
        int i;
        for (i = 0; (u8)i < animUpdate->eventCount; i++) {
            int cmd = animUpdate->eventIds[(u8)i];
            switch (cmd) {
            case 1:
                if (((GameObject *)obj)->unkC8 != NULL) {
                    ObjLink_DetachChild(obj, *(int*)state);
                }
                break;
            case 2:
                (*gWaterfxInterface)->spawnSplashBurst(
                    (void *)obj, ((GameObject *)obj)->anim.worldPosX,
                    ((GameObject *)obj)->anim.worldPosY,
                    ((GameObject *)obj)->anim.worldPosZ, lbl_803E4670);
                break;
            }
        }
    }
    return 0;
}

void ccpedstal_update(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    if (*(u8 *)(state + 6) != 0) {
        if (*(u8 *)(state + 6) & 1) {
            GameBit_Set(*(s16 *)(state + 4), 1);
        } else {
            GameBit_Set(*(s16 *)(state + 4), 0);
        }
        *(u8 *)(state + 6) = 0;
        if (GameBit_Get(0xdf0) == 0 && GameBit_Get(0xaa) != 0) {
            GameBit_Set(0xdf0, 1);
        }
    }
    (*(void (*)(int, int))*(int *)state)(obj, state);
}

extern void *fn_802972A8(void *obj);
extern int mapGetDirIdx(int a);
extern void lockLevel(int idx, int flag);

#pragma peephole on
void fn_801AC01C(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    int r;
    void *res;
    GameBit_Set(0x3a3, 0);
    GameBit_Set(0x3a2, 0);
    res = fn_802972A8(Obj_GetPlayerObject());
    if (res != 0) {
        r = (*(int (**)(int))(*(int *)(*(int *)((char *)res + 0x68)) + 0x48))((int)res);
    } else {
        r = 0;
    }
    lockLevel(mapGetDirIdx(0x17), 1);
    if (r == 1) {
        (*gGameUIInterface)->setShowWorldMapHud(1);
        *(u8 *)(state + 0) = 5;
        GameBit_Set(0x37b, 1);
    } else {
        *(u8 *)(state + 0) = 6;
        GameBit_Set(0xce, 1);
    }
    GameBit_Set(0x378, 0);
    GameBit_Set(0x3b9, 0);
}

void fn_801AC108(int obj, int param2)
{
    int r;
    void *res;
    (*gGameUIInterface)->setShowWorldMapHud(0);
    if (GameBit_Get(0x3a3) != 0) {
        GameBit_Set(0x3a3, 0);
        GameBit_Set(0x3a2, 0);
        GameBit_Set(0x378, 0);
        GameBit_Set(0x3b9, 0);
        res = fn_802972A8(Obj_GetPlayerObject());
        if (res != 0) {
            r = (*(int (**)(int))(*(int *)(*(int *)((char *)res + 0x68)) + 0x48))((int)res);
        } else {
            r = 0;
        }
        GameBit_Set(0x4e5, 1);
        (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 1, 1);
        if (r == 1) {
            (*gGameUIInterface)->setShowWorldMapHud(1);
            *(u8 *)(param2 + 0) = 5;
            GameBit_Set(0x379, 1);
        } else {
            *(u8 *)(param2 + 0) = 6;
            GameBit_Set(0xcb, 1);
        }
    }
}

extern f32 lbl_803E46A8;
extern f32 lbl_803E46AC;
extern f32 lbl_803E46B0;
extern f32 lbl_803E46B4;
extern f32 lbl_803E46B8;
extern f32 lbl_803E46BC;
extern f32 lbl_803E46C0;
extern f32 lbl_803E46C4;
extern u8 fn_801334E0(void);
extern void showHelpText(int textId);
extern int playerIsDisguised(int obj);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void *args, int arg9);

typedef struct SharpClawPadParticleArgs {
    u8 pad00[0xc];
    f32 offset[3];
} SharpClawPadParticleArgs;

#pragma peephole off
void ccsharpclawpad_update(int obj)
{
    SharpClawPadParticleArgs particleArgs;
    f32 *state;
    int *player;

    if (GameBit_Get(*(s16 *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x1a)) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        particleArgs.offset[0] = lbl_803E46A8;
        particleArgs.offset[1] = lbl_803E46AC;
        particleArgs.offset[2] = lbl_803E46B0;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 2, 2, 0x19, lbl_803E46B8,
                              *(f32 *)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
        particleArgs.offset[0] = lbl_803E46AC;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 2, 2, 0x19, lbl_803E46B8,
                              *(f32 *)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
        if (GameBit_Get(0x40) == 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
        } else {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x10;
        }
        state = ((GameObject *)obj)->extra;
        if (ObjTrigger_IsSet(obj) != 0 && fn_801334E0() == 0) {
            *state = lbl_803E46C0;
        }
        if (*state > lbl_803E46B0) {
            if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) == 0) {
                *state = lbl_803E46B0;
            } else {
                *state -= timeDelta;
                showHelpText(*(s16 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x7c));
            }
        }
        player = (int *)Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&((GameObject *)obj)->anim.worldPosX, &((GameObject *)player)->anim.worldPosX) < lbl_803E46C4
            && playerIsDisguised((int)player) != 0) {
            Sfx_PlayFromObject(obj, 0x109);
            GameBit_Set(*(s16 *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x1a), 1);
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        }
        particleArgs.offset[0] = lbl_803E46A8;
        particleArgs.offset[1] = lbl_803E46AC;
        particleArgs.offset[2] = lbl_803E46B0;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 5, 2, 0x19, lbl_803E46B8,
                              *(f32 *)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
        particleArgs.offset[0] = lbl_803E46AC;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 5, 2, 0x19, lbl_803E46B8,
                              *(f32 *)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
    }
}

#include "main/dll/SC/SCtotemlogpuz.h"

typedef struct CclightfootState {
    u8 unk0;
    u8 pad1[0x4 - 0x1];
    s16 unk4;
    u8 unk6;
    u8 pad7[0x18 - 0x7];
} CclightfootState;


typedef struct CcpedstalState {
    u8 unk0;
    u8 pad1[0x4 - 0x1];
    s16 unk4;
    u8 unk6;
    u8 pad7[0x8 - 0x7];
} CcpedstalState;

extern f32 lbl_803E46D0;
extern void gameTextShow(int textId);
extern void *getTrickyObject(void);
extern int *gSHthorntailAnimationInterface;

void cclevcontrol_update(int obj)
{
    int *state = ((GameObject *)obj)->extra;
    int *tricky;
    u32 a;
    u32 b;

    if (*(f32 *)state > lbl_803E46D0) {
        gameTextShow(0x34c);
        *(f32 *)state -= timeDelta;
        if (*(f32 *)state < lbl_803E46D0) {
            *(f32 *)state = *(f32 *)&lbl_803E46D0;
        }
    }
    if ((*(int (**)(int))(*(int *)gSHthorntailAnimationInterface + 0x24))(0) != 0) {
        if (state[2] != -1) {
            state[2] = -1;
            if (state[1] & 0x20) {
                Music_Trigger(0xc8, 0);
            }
        }
    } else {
        if (state[2] != 0xc8) {
            state[2] = 0xc8;
            if (state[1] & 0x20) {
                Music_Trigger(0xc8, 1);
            }
        }
    }
    SCGameBitLatch_Update((SCGameBitLatchState *)(state + 1), 2, -1, -1, 0xb72, 0x95);
    SCGameBitLatch_Update((SCGameBitLatchState *)(state + 1), 0x20, -1, -1, 0xc47, state[2]);
    SCGameBitLatch_Update((SCGameBitLatchState *)(state + 1), 4, -1, -1, 0xb45, 0x37);
    SCGameBitLatch_Update((SCGameBitLatchState *)(state + 1), 8, -1, -1, 0xb73, 0xbf);
    SCGameBitLatch_Update((SCGameBitLatchState *)(state + 1), 0x10, -1, -1, 0xb24, 0xc0);
    SCGameBitLatch_Update((SCGameBitLatchState *)(state + 1), 0x40, -1, -1, 0x19e, 0xcd);
    if (state[3] == 2) {
        SCGameBitLatch_UpdateInverted((SCGameBitLatchState *)(state + 1), 0x80, -1, -1, 0x24, 0xea);
    }
    if (GameBit_Get(0x3d6) != 0
        && (*gMapEventInterface)->getAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 0x1f) != 0) {
        (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 0x1f, 0);
    }
    if (GameBit_Get(0x161) != 0
        && (*gMapEventInterface)->getAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 0x1e) == 0) {
        (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 0x1e, 1);
    }
    if (GameBit_Get(0x3d7) != 0
        && (*gMapEventInterface)->getAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 0x1d) == 0) {
        (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 0x1d, 1);
    }
    tricky = (int *)getTrickyObject();
    if (state[1] & 1) {
        if (GameBit_Get(0x22d) != 0 || GameBit_Get(0x22e) == 0
            || (*(u16 *)((char *)tricky + 0xb0) & 0x1000) != 0) {
            state[1] &= ~1;
            (*gCameraInterface)->loadTriggeredCamAction(0, 1, 0);
        }
    } else {
        if (GameBit_Get(0x22d) == 0 && GameBit_Get(0x22a) != 0 && GameBit_Get(0x22e) != 0
            && GameBit_Get(0x160) == 0) {
            state[1] |= 1;
            (*gCameraInterface)->loadTriggeredCamAction(1, 1, 0);
        }
    }
    a = GameBit_Get(0x3f0);
    b = GameBit_Get(0xaf7);
    if (b + a == 4 && GameBit_Get(0xf26) == 0) {
        Sfx_PlayFromObject(obj, 0x7e);
        GameBit_Set(0xf26, 1);
    }
}

extern f32 lbl_803E4680;
extern f32 lbl_803E4684;
extern f32 lbl_803E4688;
extern f32 lbl_803E468C;
extern f32 lbl_803E4690;
extern f32 lbl_803E4694;
extern f32 lbl_803E4698;
extern u8 lbl_80323408[];
extern u8 lbl_803DDB38[8];
extern f32 getXZDistance(void *a, void *b);
extern int getAngle(f32 dx, f32 dz);
extern f32 fn_8014C5D0(int obj);
extern void fn_8014C66C(int obj, int target);
extern void *fn_80296118(int p);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);
extern int Obj_FreeObject(int o);
extern void Obj_SetModelColorFadeRecursive(int obj, int frames, int red, int green, int blue, int startAtHalf);
extern int ObjList_FindObjectById(int id);
extern void objfx_spawnHitEmitterAtPos(f32 *p, int a, int b, int c, int d);

typedef struct LightfootAnimTable {
    u8 stateFlags[0x10];
    u8 animIds[0x10];
    f32 animSpeeds[15];
} LightfootAnimTable;

void cclightfoot_update(int obj)
{
    LightfootAnimTable *tbl = (LightfootAnimTable *)lbl_80323408;
    u32 fallback;
    int *state = ((GameObject *)obj)->extra;
    u32 targetObj;
    s16 angle;
    u32 o2;
    u32 o1;
    u32 oFar;
    u32 oNear;
    s16 diff;
    int valid;
    u32 off;
    u8 i;
    f32 dist;
    int hitObj;
    f32 dists[2];
    f32 hitPos[3];
    int animId;
    s16 t;
    u8 m;

    fallback = 0;
    if (tbl->stateFlags[*((u8 *)state + 0x10)] & 1) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
    }
    o1 = state[2];
    if (o1 != 0) {
        if (!(fn_8014C5D0(o1) > lbl_803E4680)) {
            valid = 0;
        } else {
            valid = GameBit_Get(*(s16 *)(*(int *)(o1 + 0x4c) + 0x18)) != 0 ? 0 : 1;
        }
        if (valid != 0) {
            o2 = state[3];
            if (!(fn_8014C5D0(o2) > lbl_803E4680)) {
                valid = 0;
            } else {
                valid = GameBit_Get(*(s16 *)(*(int *)(o2 + 0x4c) + 0x18)) != 0 ? 0 : 1;
            }
        }
        if (valid != 0) {
            dist = getXZDistance((f32 *)(state[1] + 0x18), (f32 *)(state[3] + 0x18));
            if (getXZDistance((f32 *)(state[1] + 0x18), (f32 *)(state[2] + 0x18)) < dist) {
                oNear = state[2];
                oFar = state[3];
            } else {
                oNear = state[3];
                oFar = state[2];
            }
            if ((getXZDistance((f32 *)(obj + 0x18), (f32 *)(state[1] + 0x18)) < lbl_803E4684
                 || fn_80296118(state[1]) == *(void **)(state + 2)
                 || fn_80296118(state[1]) == *(void **)(state + 3))
                && playerIsDisguised(state[1]) == 0) {
                if (fn_80296118(state[1]) == (void *)oFar) {
                    u32 tmp = oFar ^ oNear;
                    oNear = oNear ^ tmp;
                    oFar = tmp ^ oNear;
                }
                fn_8014C66C(oNear, state[1]);
                fn_8014C66C(oFar, obj);
                targetObj = oFar;
                dist = getXZDistance((f32 *)(obj + 0x18), (f32 *)(oFar + 0x18));
            } else {
                for (i = 0; i < 2; i++) {
                    off = i * 4;
                    *(f32 *)((u8 *)dists + off) =
                        getXZDistance((f32 *)(obj + 0x18), (f32 *)(*(int *)((u8 *)state + off + 8) + 0x18));
                    fn_8014C66C(*(int *)((u8 *)state + off + 8), obj);
                }
                if (dists[0] < dists[1]) {
                    targetObj = state[2];
                    dist = dists[0];
                } else {
                    targetObj = state[3];
                    dist = dists[1];
                }
            }
        } else {
            o2 = state[2];
            if (!(fn_8014C5D0(o2) > lbl_803E4680)) {
                valid = 0;
            } else {
                valid = GameBit_Get(*(s16 *)(*(int *)(o2 + 0x4c) + 0x18)) != 0 ? 0 : 1;
            }
            if (valid != 0) {
                fallback = state[2];
            }
            o2 = state[3];
            if (!(fn_8014C5D0(o2) > lbl_803E4680)) {
                valid = 0;
            } else {
                valid = GameBit_Get(*(s16 *)(*(int *)(o2 + 0x4c) + 0x18)) != 0 ? 0 : 1;
            }
            if (valid != 0) {
                fallback = state[3];
            }
            if (fallback != 0) {
                dist = getXZDistance((f32 *)(state[1] + 0x18), (f32 *)(fallback + 0x18));
                if ((getXZDistance((f32 *)(obj + 0x18), (f32 *)(fallback + 0x18)) < dist
                     && fn_80296118(state[1]) != (void *)fallback)
                    || playerIsDisguised(state[1]) != 0) {
                    fn_8014C66C(fallback, obj);
                } else {
                    fn_8014C66C(fallback, state[1]);
                }
                targetObj = fallback;
                dist = getXZDistance((f32 *)(obj + 0x18), (f32 *)(fallback + 0x18));
            } else {
                targetObj = state[1];
                dist = lbl_803E4674;
            }
        }
        angle = (s16)getAngle(-(((GameObject *)targetObj)->anim.localPosX - ((GameObject *)obj)->anim.localPosX),
                              -(((GameObject *)targetObj)->anim.localPosZ - ((GameObject *)obj)->anim.localPosZ));
        diff = (s16)(*(s16 *)obj - (u16)angle);
        if (diff > 0x8000) {
            diff = (s16)(diff - 0xffff);
        }
        if (diff < -0x8000) {
            diff = (s16)(diff + 0xffff);
        }
        if (diff > 0x1000) {
            *((u8 *)state + 0x11) |= 2;
        } else if (diff < -0x1000) {
            *((u8 *)state + 0x11) |= 2;
        } else {
            *((u8 *)state + 0x11) &= ~2;
        }
    }
    if (*((u8 *)state + 0x10) <= 0xb) {
        *(f32 *)(state + 5) -= timeDelta;
        if (*(f32 *)(state + 5) < lbl_803E4680) {
            *(f32 *)(state + 5) = (f32)(int)randomGetRange(0xb4, 0x12c);
            Sfx_PlayFromObject(obj, 0x134);
        }
    }
    switch (*((u8 *)state + 0x10)) {
    case 0:
        if (GameBit_Get(9) != 0) {
            *((u8 *)state + 0x10) = 0xe;
        } else {
            if (Obj_IsLoadingLocked() != 0) {
                state[0] = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x6f1), 5, -1, -1,
                                           *(int *)&((GameObject *)obj)->anim.parent);
                ObjLink_AttachChild(obj, state[0], 0);
            }
            state[1] = (int)Obj_GetPlayerObject();
            state[2] = ObjList_FindObjectById(0x45d7d);
            state[3] = ObjList_FindObjectById(0x45d7f);
            *((u8 *)state + 0x10) = 1;
            *(f32 *)(state + 5) = (f32)(int)randomGetRange(0xb4, 0x12c);
        }
        break;
    case 1:
        if (((GameObject *)obj)->anim.currentMoveProgress > lbl_803E467C && ((GameObject *)obj)->anim.currentMoveProgress < lbl_803E4688) {
            if (diff > 0x400) {
                *(s16 *)obj = (s16)(*(s16 *)obj - (int)(lbl_803E468C * timeDelta));
            } else if (diff < -0x400) {
                *(s16 *)obj = (s16)(*(s16 *)obj + (int)(lbl_803E468C * timeDelta));
            } else {
                *(s16 *)obj = angle;
            }
        }
        if (*((u8 *)state + 0x11) & 1) {
            fn_801AA878((u8 *)state, (int *)targetObj, dist);
        }
        break;
    case 2:
        if (*((u8 *)state + 0x11) & 1) {
            if (dist < lbl_803E4678) {
                *((u8 *)state + 0x10) = 4;
            } else {
                *((u8 *)state + 0x10) = 3;
            }
        }
        break;
    case 3:
        if (*((u8 *)state + 0x11) & 1) {
            *((u8 *)state + 0x10) = 4;
        }
        break;
    case 4:
        if (*((u8 *)state + 0x11) & 1) {
            fn_801AA878((u8 *)state, (int *)targetObj, dist);
        }
        break;
    case 5:
        if (((GameObject *)targetObj)->anim.currentMove != 0x19) {
            *((u8 *)state + 0x10) = 7;
        }
        if (*((u8 *)state + 0x11) & 1) {
            *((u8 *)state + 0x10) = 6;
        }
        break;
    case 6:
        if (((GameObject *)targetObj)->anim.currentMove != 0x19) {
            *((u8 *)state + 0x10) = 7;
        }
        break;
    case 7:
        t = ((GameObject *)targetObj)->anim.currentMove;
        if (t == 0x18 && ((GameObject *)targetObj)->anim.currentMoveProgress > lbl_803E467C) {
            *((u8 *)state + 0x10) = 8;
        } else if (t == 0x19) {
            *((u8 *)state + 0x10) = 5;
        } else if (*((u8 *)state + 0x11) & 1) {
            fn_801AA878((u8 *)state, (int *)targetObj, dist);
        }
        break;
    case 8:
        t = ((GameObject *)targetObj)->anim.currentMove;
        if (t != 0x18 ||
            (t == 0x18 && ((GameObject *)targetObj)->anim.currentMoveProgress < lbl_803E467C)) {
            *((u8 *)state + 0x10) = 0xa;
        }
        if (*((u8 *)state + 0x11) & 1) {
            *((u8 *)state + 0x10) = 9;
        }
        break;
    case 9:
        t = ((GameObject *)targetObj)->anim.currentMove;
        if (t != 0x18 ||
            (t == 0x18 && ((GameObject *)targetObj)->anim.currentMoveProgress < lbl_803E467C)) {
            *((u8 *)state + 0x10) = 0xa;
        }
        break;
    case 10:
        t = ((GameObject *)targetObj)->anim.currentMove;
        if (t == 0x18 && ((GameObject *)targetObj)->anim.currentMoveProgress > lbl_803E467C) {
            *((u8 *)state + 0x10) = 8;
        } else if (t == 0x19) {
            *((u8 *)state + 0x10) = 5;
        } else if (*((u8 *)state + 0x11) & 1) {
            fn_801AA878((u8 *)state, (int *)targetObj, dist);
        }
        break;
    case 0xb:
        fn_801AA878((u8 *)state, (int *)targetObj, dist);
        break;
    case 0xc:
        if (GameBit_Get(9) != 0) {
            if (GameBit_Get(0x24) != 0) {
                *((u8 *)state + 0x10) = 0xe;
            }
        } else {
            if (ObjTrigger_IsSet(obj) != 0) {
                GameBit_Set(9, 1);
            } else if (*((u8 *)state + 0x11) & 2) {
                *((u8 *)state + 0x10) = 0xd;
            }
        }
        break;
    case 0xd:
        if (((GameObject *)obj)->anim.currentMoveProgress > lbl_803E467C && ((GameObject *)obj)->anim.currentMoveProgress < lbl_803E4688) {
            if (diff > 0x400) {
                *(s16 *)obj = (s16)(*(s16 *)obj - (int)(lbl_803E468C * timeDelta));
            } else if (diff < -0x400) {
                *(s16 *)obj = (s16)(*(s16 *)obj + (int)(lbl_803E468C * timeDelta));
            } else {
                *(s16 *)obj = angle;
            }
        }
        if (*((u8 *)state + 0x11) & 1) {
            *((u8 *)state + 0x10) = 0xc;
        }
        break;
    case 0xe:
        if ((u32)state[0] != 0) {
            if (((GameObject *)obj)->unkC8 != NULL) {
                ObjLink_DetachChild(obj, state[0]);
            }
            Obj_FreeObject(state[0]);
            state[0] = 0;
        }
        ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x8000);
        ObjHits_DisableObject(obj);
        return;
    }
    m = *((u8 *)state + 0x10);
    if (m >= 5 && m <= 0xa) {
        if (ObjHits_PollPriorityHitWithCooldown(obj, lbl_803DDB38, 0, hitPos) != 0) {
            if (getXZDistance((f32 *)(obj + 0x18), (f32 *)(state[1] + 0x18)) < lbl_803E4690) {
                objfx_spawnHitEmitterAtPos(hitPos, 8, 0xff, 0xff, 0x78);
                objLightFn_8009a1dc((void *)obj, lbl_803E4694, hitPos, 4, 0);
            }
            Sfx_PlayFromObject(obj, 0x129);
        }
    } else {
        if (ObjHits_GetPriorityHit(obj, &hitObj, 0, 0) != 0) {
            t = *(s16 *)(hitObj + 0x46);
            if (t == 0x11 || t == 0x33) {
                Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
            }
        }
    }
    m = *((u8 *)state + 0x10);
    {
        u8 *pa = &tbl->stateFlags[m];
        animId = pa[0x10];
        if (animId != ((GameObject *)obj)->anim.currentMove) {
            if (pa[0] & 2) {
                ObjAnim_SetCurrentMove(obj, animId, lbl_803E4698, 0);
            } else {
                ObjAnim_SetCurrentMove(obj, animId, lbl_803E4680, 0);
            }
        }
    }
    if (((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, tbl->animSpeeds[*((u8 *)state + 0x10)], timeDelta,
                                   NULL) != 0) {
        *((u8 *)state + 0x11) |= 1;
    } else {
        *((u8 *)state + 0x11) &= ~1;
    }
}
