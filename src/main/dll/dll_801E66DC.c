/* === moved from main/dll/TREX/TREX_levelcontrol.c [801E4288-801E42F8) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll_000A_expgfx.h"
#include "main/dll/TREX/TREX_levelcontrol.h"







extern u32 randomGetRange(int min, int max);
extern undefined4 ObjPath_GetPointWorldPosition();


/*
 * --INFO--
 *
 * Function: SB_ShipGun_update
 * EN v1.0 Address: 0x801E34C0
 * EN v1.0 Size: 2312b
 * EN v1.1 Address: 0x801E3AB0
 * EN v1.1 Size: 2132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Sfx_StopObjectChannel();
extern s16 getAngle(f32 dx, f32 dz);
extern u8 framesThisStep;
extern EffectInterface** gPartfxInterface;



/* Trivial 4b 0-arg blr leaves. */



/* 8b "li r3, N; blr" returners. */


int SB_FireBall_getExtraSize(void);
int SB_FireBall_getObjectTypeId(void);

void SB_FireBall_free(int obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E58B0;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E58D8;


void SB_FireBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

extern f32 timeDelta;






#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"
#include "main/dll/TREX/TREX_trex.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/objhits_types.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct SBShipGunBrokePlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} SBShipGunBrokePlacement;


typedef struct ShopBuyItemState
{
    u8 pad0[0x1 - 0x0];
    s8 unk1;
    u8 pad2[0x4 - 0x2];
    u8 unk4;
    u8 pad5[0x56 - 0x5];
    u8 unk56;
    u8 pad57[0x6E - 0x57];
    s16 unk6E;
    u8 pad70[0x90 - 0x70];
    u8 unk90;
    u8 pad91[0x9B0 - 0x91];
    s32 unk9B0;
    u8 pad9B4[0x9D6 - 0x9B4];
    u8 unk9D6;
    u8 pad9D7[0x9D8 - 0x9D7];
} ShopBuyItemState;


typedef struct LampObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    u8 unk1A;
    u8 pad1B[0x20 - 0x1B];
} LampObjectDef;


typedef struct SBSeqDoorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    s8 unk19;
    u8 unk1A;
    u8 pad1B[0x20 - 0x1B];
} SBSeqDoorObjectDef;


typedef struct ShipBattleObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x24 - 0x1C];
    u8 unk24;
    u8 pad25[0x28 - 0x25];
} ShipBattleObjectDef;


/*
 * Per-object extra state for the ShipBattle cloud-ball projectile
 * (SB_CloudBall_getExtraSize == 0x24).
 */
typedef struct SBCloudBallState
{
    f32 velX; /* captured from obj+0x24.. on launch */
    f32 velY;
    f32 velZ;
    f32 posX;
    f32 posY;
    f32 posZ;
    int light; /* objCreateLight handle */
    u8 launched;
    u8 pad1D[3];
    f32 fadeTimer; /* nonzero = despawning */
} SBCloudBallState;

STATIC_ASSERT(sizeof(SBCloudBallState) == 0x24);

/*
 * Per-object extra state for the ShipBattle fireball projectile
 * (SB_FireBall_getExtraSize == SB_FIREBALL_EXTRA_SIZE == 0x18).
 */
typedef struct SBFireBallState
{
    void* owner; /* taken from obj+0xF8 */
    s16 age; /* frames; gates the hitbox enable */
    u8 pad06[2];
    f32 velX;
    f32 velY;
    f32 velZ;
    u8 launched;
    u8 pad15[3];
} SBFireBallState;

STATIC_ASSERT(sizeof(SBFireBallState) == 0x18);

/*
 * Per-object extra state for the ShipBattle kyte cage
 * (SB_KyteCage_getExtraSize == 0x8).
 */
typedef struct SBKyteCageState
{
    void* kyte; /* attached objType-0x121 child */
    u8 seqLatch;
    u8 doorChoice; /* picks trigger 2 vs 1 on release */
    u8 pad06[2];
} SBKyteCageState;

STATIC_ASSERT(sizeof(SBKyteCageState) == 0x8);

/*
 * Per-object extra state for the ShipBattle chain segment
 * (ShipBattle_getExtraSize == 0x140). The head is handed to
 * gObjectTriggerInterface (+0x1C/+0x24) - interface-owned record;
 * only the locally-evidenced fields are named.
 */
typedef struct ShipBattleState
{
    u8 unk00[0x24];
    f32 unk24; /* lbl/(lbl + def[0x24]) damping factor */
    int unk28; /* -1 at init */
    u8 unk2C[0x6A - 0x2C];
    s16 unk6A; /* def+0x1A */
    u8 pad6C[2];
    s16 unk6E; /* -1 at init */
    u8 unk70[0x140 - 0x70];
} ShipBattleState;

STATIC_ASSERT(sizeof(ShipBattleState) == 0x140);


extern undefined4 getLActions();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern void playerAddMoney(int player, int amount);
extern void playerAddHealth(int player, int amount);
extern int gameBitIncrement(int bit);
extern u8 lbl_80327FD0[];
extern void* fn_802966CC(int player);
extern void fn_80295CF4(int player, int mode);
extern void skyFn_80088c94(int skyId, int enable);
extern void envFxActFn_800887f8(int id);
extern void getEnvfxAct(int obj, int target, int effectId, int flags);

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern ModgfxInterface** gModgfxInterface;
extern int* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy

/*
 * --INFO--
 *
 * Function: SB_FireBall_hitDetect
 * EN v1.0 Address: 0x801E42F8
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801E4330
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

void SB_FireBall_hitDetect(int* obj);

/*
 * --INFO--
 *
 * Function: FUN_801e4350
 * EN v1.0 Address: 0x801E4350
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E4384
 * EN v1.1 Size: 48b
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
 * Function: FUN_801e48f4
 * EN v1.0 Address: 0x801E48F4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801E4888
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801e4928
 * EN v1.0 Address: 0x801E4928
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E48B8
 * EN v1.1 Size: 48b
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
 * Function: FUN_801e521c
 * EN v1.0 Address: 0x801E521C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801E5194
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801e524c
 * EN v1.0 Address: 0x801E524C
 * EN v1.0 Size: 884b
 * EN v1.1 Address: 0x801E51CC
 * EN v1.1 Size: 644b
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
 * Function: FUN_801e55c0
 * EN v1.0 Address: 0x801E55C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E5450
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void FUN_801e55c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined2* param_9, int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e55c4
 * EN v1.0 Address: 0x801E55C4
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x801E5564
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void SB_FireBall_release(void);

void SB_FireBall_initialise(void);

void SB_CloudBall_release(void);

void SB_CloudBall_initialise(void);

void SB_KyteCage_render(void);

void SB_KyteCage_hitDetect(void);

void SB_KyteCage_release(void);

void SB_KyteCage_initialise(void);

void SB_CageKyte_free(void);

void SB_CageKyte_hitDetect(void);

void SB_CageKyte_release(void);

void SB_CageKyte_initialise(void);

void SB_SeqDoor_free(void);

void SB_SeqDoor_hitDetect(void);

void SB_SeqDoor_release(void);

void SB_SeqDoor_initialise(void);

void SB_MiniFire_hitDetect(void);

void SB_MiniFire_release(void);

void SB_MiniFire_initialise(void);

void ShipBattle_hitDetect(void);

void ShipBattle_release(void);

void ShipBattle_initialise(void);

void Flag_free(void);

void Flag_hitDetect(void);

void Flag_release(void);

void Flag_initialise(void);

void SB_ShipGunBroke_free(void);

void SB_ShipGunBroke_hitDetect(void);

void SB_ShipGunBroke_init(void);

void SB_ShipGunBroke_release(void);

void SB_ShipGunBroke_initialise(void);

void shop_hitDetect(void);

void shop_release(void);

void shop_initialise(void);

/* 8b "li r3, N; blr" returners. */
int SB_CloudBall_getExtraSize(void);
int SB_CloudBall_getObjectTypeId(void);
int SB_KyteCage_getExtraSize(void);
int SB_KyteCage_getObjectTypeId(void);
int SB_CageKyte_getExtraSize(void);
int SB_CageKyte_getObjectTypeId(void);
int SB_SeqDoor_getExtraSize(void);
int SB_SeqDoor_getObjectTypeId(void);
int SB_MiniFire_getExtraSize(void);
int SB_MiniFire_getObjectTypeId(void);
int ShipBattle_getExtraSize(void);
int ShipBattle_getObjectTypeId(void);
int Lamp_getExtraSize(void);
int Flag_getExtraSize(void);
int Flag_getObjectTypeId(void);
int SB_ShipGunBroke_getExtraSize(void);
int SB_ShipGunBroke_getObjectTypeId(void);
int shop_getExtraSize(void);
int shop_getObjectTypeId(void);
int fn_801E66DC(void) { return 0x0; }
int fn_801E66E4(void) { return 0x0; }

/* 16b chained patterns. */
s32 shop_getStateField1(int* obj);
s32 shop_setScale(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E58E8;
extern f32 lbl_803E5920;
extern f32 lbl_803E5978;
extern f32 lbl_803E59A8;
extern f32 lbl_803E59C8;
extern void Sfx_StopObjectChannel(int* obj, int channel);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern int GameBit_Get(int);
extern void GameBit_Set(int slot, int val);
extern void ObjGroup_RemoveObject(int* obj, int group);
extern void ObjGroup_AddObject(int obj, int group);
extern void Music_Trigger(int a, int b);
extern f32 lbl_803E5998;
extern f32 lbl_803E599C;
extern f32 lbl_803E59AC;
extern f32 lbl_803E59B0;
extern f32 lbl_803E5958;
extern f32 lbl_803E595C;
extern f32 lbl_803E5970;
extern f32 lbl_803E5974;
extern f32 lbl_803E5960;
extern f32 lbl_803E5918;
extern f32 lbl_803E59D8;
extern f32 lbl_803E59DC;
extern u8 lbl_803DB411;
extern f32 lbl_803DDC50;
extern int* gBoneParticleEffectInterface;
extern int Stack_IsEmpty(int stack);
extern int Stack_Pop(int stack, int* out);
int SB_SeqDoor_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int Lamp_SeqFn(int obj, int unused, int state);

void SB_CloudBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void SB_SeqDoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void Lamp_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void Flag_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void shop_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */
void Flag_init(int* obj, int* def);

void Flag_update(int obj);

int SB_KyteCage_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */
int SB_CageKyte_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);

int SB_SeqDoor_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

extern f32 lbl_803E597C;
extern f32 lbl_803E5980;
extern f32 lbl_803E5984;
extern f32 lbl_803E5988;
extern f32 lbl_803E598C;

int Lamp_SeqFn(int obj, int unused, int state);

int fn_801E66EC(int arg1, int arg2)
{
    int state;
    f32 local;
    int stk;
    int popOut;

    state = *(int*)(arg1 + 0xb8);
    local = lbl_803E59D8;

    if (*(s8*)(arg2 + 0x27a) != 0)
    {
        if ((*(u16*)(arg1 + 0xb0) & 0x800) != 0)
        {
            ((void (*)(int, int, f32*, int, int))((void**)*gBoneParticleEffectInterface)[3])(
                arg1, 2031, &local, 80, 0);
        }
    }

    *(u8*)(state + 0x9d6) = 0;
    *(f32*)(arg2 + 0x280) = lbl_803E59DC;
    if (*(u8*)(state + 0x9d6) == 0)
    {
        stk = *(int*)(state + 0x9b0);
        popOut = 0;
        if (Stack_IsEmpty(stk) == 0)
        {
            Stack_Pop(stk, &popOut);
        }
        return popOut + 1;
    }
    return 0;
}

void Lamp_free(int* obj);

void Lamp_init(int* obj, int* def);

void Lamp_update(int obj);

void SB_CageKyte_init(int p);

void SB_CageKyte_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void SB_CageKyte_update(int obj);

void SB_CloudBall_free(int* obj);

extern f32 lbl_803E58EC;
extern f32 lbl_803E58F0;
extern void projectileParticleFxFn_80099660(int* obj, f32 scale, int type);

void SB_CloudBall_hitDetect(int* obj);

extern f32 lbl_803E5910;
extern f32 lbl_803E5914;

void SB_CloudBall_init(int* obj);

extern f32 lbl_803E58F4;
extern f32 lbl_803E58F8;
extern f32 lbl_803E58FC;
extern f32 lbl_803E5900;
extern f32 lbl_803E5904;
extern f32 lbl_803E58DC;
extern f32 lbl_803E58E0;

void SB_CloudBall_update(int obj);

void SB_FireBall_init(int p);

void SB_FireBall_update(int obj);

/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */
void SB_KyteCage_free(int* obj);

void SB_KyteCage_init(int* obj, int* params);

extern void buttonDisable(int controller, int mask);
extern int* objModelGetVecFn_800395d8(int obj, int idx);
extern f32 lbl_803E591C;

void SB_KyteCage_update(int obj);

void SB_MiniFire_free(int* obj);

extern int lbl_803DC098;
extern f32 lbl_803E592C;
extern f32 lbl_803E5948;
extern f32 lbl_803E594C;
extern f32 lbl_803E5950;

void SB_MiniFire_init(int obj);

extern void fn_80053ED0(int);
extern void fn_80053EBC(int);
extern f32 lbl_803E5928;

void SB_MiniFire_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

extern f64 lbl_803E5940;
extern f32 lbl_803E5930;
extern f32 lbl_803E5934;
extern f32 lbl_803E5938;
extern f32 lbl_803E593C;

void SB_MiniFire_update(int obj);

void SB_SeqDoor_init(int* obj, int* def);

void SB_SeqDoor_update(int* obj);

extern f32 lbl_803E59C0;

void SB_ShipGunBroke_render(int* obj, int p2, int p3, int p4, int p5);

void SB_ShipGunBroke_update(int* obj);

void ShipBattle_free(int* obj);

void ShipBattle_init(int obj, int def);

void ShipBattle_render(int* obj);

void ShipBattle_update(int obj);

void shop_buyItem(int obj, int price);

void shop_free(int* obj);

void shop_func0B(int* obj, int v, int p3);

/* EN v1.0 0x801E60A4  size: 28b  shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash (s8)v in obj->_b8[4]. */
void shop_func15(int* obj, int v);

/* EN v1.0 0x801E607C  size: 40b  Increment-and-store: obj->_b8[2] += p3,
 * obj->_b8[3] += p2. */
void shop_func16(int* obj, int p2, int p3);

/* EN v1.0 0x801E6050  size: 44b  Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */
void shop_func17(int* obj, int* out_b3, int* out_b2, int* out_b4);

/* shop_getItem* helpers -- table lookup */
int shop_getItemPrice(int p, int idx);

s16 shop_getItemTextId(int p, int idx);

u8 shop_getItemField4(int p, int idx);

u8 shop_getItemMinPrice(int p, int idx);

void shop_init(int obj, int objDef);

/* EN v1.0 0x801E6358  size: 104b  Returns 1 unless the item's
 * "available" GameBit gate (lbl_80327FD0[idx*12 + 6]) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */
int shop_isItemAvailable(int p, int idx);

/* EN v1.0 0x801E62F0  size: 104b  Returns 1 when shop item's "bought"
 * GameBit (slot at lbl_80327FD0[idx*12 + 8]) is set; else 0. */
int shop_isItemBought(int p, int idx);

void shop_setStateField1(int* obj, int v);

void shop_update(int obj);
