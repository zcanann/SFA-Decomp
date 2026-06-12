/* === moved from main/dll/DIM/DIMlogfire.c [801AA558-801AA560) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/DIM/dimlogfire.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"











extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjLink_AttachChild();

extern ObjectTriggerInterface** gObjectTriggerInterface;

/*
 * --INFO--
 *
 * Function: FUN_801a8f88
 * EN v1.0 Address: 0x801A8F88
 * EN v1.0 Size: 836b
 * EN v1.1 Address: 0x801A9044
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801a9408
 * EN v1.0 Address: 0x801A9408
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x801A953C
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */







#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

/* 8b "li r3, N; blr" returners. */
int ccqueen_getExtraSize(void) { return 0x654; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E45C8;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off

#pragma peephole reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma scheduling reset

/* call(x, N) wrappers. */
#pragma scheduling off
#pragma scheduling reset

/* MoonSeedPlantingSpot_SeqFn: leaf flag-set on obj's extra struct, returns 0. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

/* CCGasVentControl_SeqFn: trampoline to CCGasVentControlFn_801a9fd0 passing (obj, obj->extra), returns 0. */
#pragma scheduling off
#pragma scheduling reset

extern f32 timeDelta;
extern void Sfx_PlayFromObject(int obj, int id);

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int allocResult, int a, int b, int c, int d);

#pragma scheduling off
#pragma dont_inline on
#pragma dont_inline reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/dll/DIM/DIMsnowball.h"

extern undefined4 ObjHits_DisableObject();
extern int ObjHits_PollPriorityHitWithCooldown();
extern int ObjTrigger_IsSetById();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8008112c();
extern undefined4 dll_2E_func03();
extern void dll_2E_func06(int* obj, void* state, int flags);

extern f32 lbl_803E4660;
extern f32 lbl_803E530C;
extern f32 lbl_803E5310;
extern f32 lbl_803E5314;
extern f32 lbl_803E5360;

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
void ccqueen_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern undefined4 ccqueen_render();
    void* state = ((GameObject*)obj)->extra;
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
void FUN_801aaa6c(double param_1, int param_2, int param_3)
{
    if ((double)lbl_803E530C == param_1)
    {
        *(u8*)(param_2 + 0x10) = 0xc;
        return;
    }
    if ((*(byte*)(param_2 + 0x11) & 2) != 0)
    {
        *(u8*)(param_2 + 0x10) = 1;
        return;
    }
    if ((double)lbl_803E5310 <= param_1)
    {
        *(u8*)(param_2 + 0x10) = 2;
        return;
    }
    if ((*(short*)(param_3 + 0xa0) == 0x18) && (lbl_803E5314 < *(float*)(param_3 + 0x98)))
    {
        *(u8*)(param_2 + 0x10) = 8;
        return;
    }
    if (*(short*)(param_3 + 0xa0) == 0x19)
    {
        *(u8*)(param_2 + 0x10) = 5;
        return;
    }
    *(u8*)(param_2 + 0x10) = 0xb;
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
FUN_801abf38(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9,
             undefined4 param_10, ObjAnimUpdateState* animUpdate)
{
    if (animUpdate->eventCount != 0)
    {
        FUN_8008112c((double)lbl_803E5360, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 1, 1, 0, 1, 1, 1, 0);
    }
    return 0;
}


/* 8b "li r3, N; blr" returners. */
int cclightfoot_getExtraSize(void);
int ccsharpclawpad_getExtraSize(void);
int ccpedstal_getExtraSize(void);
int cclevcontrol_getExtraSize(void);

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E46CC;
void cclevcontrol_render(void);

/* Drift-recovery: add new fns with v1.0 names. */
extern void envFxActFn_800887f8(int a);
extern void Music_Trigger(int a, int b);
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern f32 lbl_803E46C8;


#pragma scheduling off
#pragma peephole off
void ccsharpclawpad_init(int* obj, int* def);

void cclevcontrol_free(void);

void cclightfoot_init(int* obj, int* def);

int cclevcontrol_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

/* ObjLink_DetachChild and Obj_FreeObject already declared in earlier extern blocks */

void cclightfoot_free(int* obj, int p2);

extern void fn_80088870(void* a, void* b, void* c, void* d);
extern int getSaveGameLoadStatus(void);
extern void getEnvfxActImmediately(void* obj, void* target, int animId, int flags);
extern void getEnvfxAct(int obj, int target, int id, int p);
extern int lbl_80323548[];
extern f32 lbl_803E46D4;
extern void ccpedstal_updateGameBitGate(int obj, u8* state2);
extern void ccpedstal_updateAltVariant(int obj, u8* state2);
extern void fn_8002B6D8(void* obj, int p2, int p3, int p4, int p5, int p6);

void ccpedstal_init(int* obj, u8* params);

void cclevcontrol_init(int* obj);


extern f32 lbl_803E4674;
extern f32 lbl_803E4678;
extern f32 lbl_803E467C;

#pragma dont_inline on
#pragma scheduling on
void fn_801AA878(u8* p1, int* p2, f32 v);
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
void ccpedstal_updateGameBitGate(int obj, u8* state2);

extern int ObjTrigger_IsSet(int obj);
extern void gameBitIncrement(int id);

/* ccpedstal_updateAltVariant: ccpedstal alt-variant think-routine. Toggles obj[0xaf]
 * bit 8 from gbit 0xdc5, then reads state2's gamebit at +0x4: if set,
 * sets bit 8 again and selects model 0; if clear, selects model 1 and
 * (when the obj's pending trigger is asserted) fires vtable[0x12] with
 * id=1, increments gbit 0xa9, and latches state2[0x6] bit 0. Mirrors
 * the no-mark branches into a shared r0=0/cmpwi end-check via goto to
 * match target's layout. */
void ccpedstal_updateAltVariant(int obj, u8* state2);

extern WaterfxInterface** gWaterfxInterface;
extern f32 lbl_803E4670;

extern void dll_2E_func05(int* obj, u8* sub, int a, int b, int c);
extern void dll_2E_func08(u8* sub, int a, int b);
extern void dll_2E_func09(u8* sub, void* a, void* b, int c);

typedef struct
{
    s16 v[3];
} _S16x3;

extern _S16x3 lbl_803E4650;
extern _S16x3 lbl_803E4658;

void ccqueen_init(int* obj, u8* init)
{
    u8* sub;
    _S16x3 buf2;
    _S16x3 buf1;
    sub = ((GameObject*)obj)->extra;
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
extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2);
extern void characterDoEyeAnims(int obj, void* p);

void ccqueen_update(int* obj)
{
    extern void* Obj_GetPlayerObject(void);
    u8* sub;
    int* player;

    sub = ((GameObject*)obj)->extra;
    if (GameBit_Get(0x1c2) == 0 && GameBit_Get(0xa3) != 0)
    {
        player = (int*)Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            lbl_803E4664)
        {
            GameBit_Set(0x1c2, 1);
        }
    }
    if (GameBit_Get(0x1c3) != 0)
    {
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x8000);
        ObjHits_DisableObject(obj);
    }
    else
    {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E4668, timeDelta, NULL);
        dll_2E_func03(obj, sub);
        characterDoEyeAnims((int)obj, sub + 0x624);
    }
}

int ccqueen_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

void ccpedstal_update(int obj);

extern void* fn_802972A8(void* obj);
extern int mapGetDirIdx(int a);
extern void lockLevel(int idx, int flag);

#pragma peephole on
void fn_801AC01C(int obj);

void fn_801AC108(int obj, int param2);

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
                                  f32 scaleZ, void* args, int arg9);

typedef struct SharpClawPadParticleArgs
{
    u8 pad00[0xc];
    f32 offset[3];
} SharpClawPadParticleArgs;

#pragma peephole off
void ccsharpclawpad_update(int obj);

#include "main/dll/SC/SCtotemlogpuz.h"




extern f32 lbl_803E46D0;
extern void gameTextShow(int textId);
extern int* gSHthorntailAnimationInterface;

void cclevcontrol_update(int obj);

extern f32 lbl_803E4680;
extern f32 lbl_803E4684;
extern f32 lbl_803E4688;
extern f32 lbl_803E468C;
extern f32 lbl_803E4690;
extern f32 lbl_803E4694;
extern f32 lbl_803E4698;
extern u8 lbl_80323408[];
extern u8 lbl_803DDB38[8];
extern int getAngle(f32 dx, f32 dz);
extern f32 fn_8014C5D0(int obj);
extern void fn_8014C66C(int obj, int target);
extern void* fn_80296118(int p);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);
extern int Obj_FreeObject(int o);
extern void Obj_SetModelColorFadeRecursive(int obj, int frames, int red, int green, int blue, int startAtHalf);
extern int ObjList_FindObjectById(int id);
extern void objfx_spawnHitEmitterAtPos(f32* p, int a, int b, int c, int d);

typedef struct LightfootAnimTable
{
    u8 stateFlags[0x10];
    u8 animIds[0x10];
    f32 animSpeeds[15];
} LightfootAnimTable;

void cclightfoot_update(int obj);
