#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"
#include "main/dll/TREX/TREX_trex.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/objanim_internal.h"
#include "main/objanim_update.h"
#include "main/objhits_types.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct SBShipGunBrokePlacement {
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} SBShipGunBrokePlacement;


typedef struct ShopBuyItemState {
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


typedef struct LampObjectDef {
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    u8 unk1A;
    u8 pad1B[0x20 - 0x1B];
} LampObjectDef;


typedef struct SBSeqDoorObjectDef {
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    s8 unk19;
    u8 unk1A;
    u8 pad1B[0x20 - 0x1B];
} SBSeqDoorObjectDef;


typedef struct ShipBattleObjectDef {
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
typedef struct SBCloudBallState {
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
typedef struct SBFireBallState {
    void *owner; /* taken from obj+0xF8 */
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
typedef struct SBKyteCageState {
    void *kyte; /* attached objType-0x121 child */
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
typedef struct ShipBattleState {
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
extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80006ba8();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int FUN_80017b00();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305c4();
extern undefined4 FUN_800305f8();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 ObjPath_GetPointWorldPosition();
extern int FUN_8003964c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8005335c();
extern undefined4 FUN_8005336c();
extern undefined4 FUN_8008110c();
extern undefined4 FUN_80081114();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined8 FUN_80294d28();
extern undefined4 FUN_80294d60();
extern MapEventInterface **gMapEventInterface;
extern void playerAddMoney(int player, int amount);
extern void playerAddHealth(int player, int amount);
extern int gameBitIncrement(int bit);
extern u8 lbl_80327FD0[];
extern void* fn_802966CC(int player);
extern void fn_80295CF4(int player, int mode);
extern void skyFn_80088c94(int skyId, int enable);
extern void envFxActFn_800887f8(int id);
extern void getEnvfxAct(int obj, int target, int effectId, int flags);

extern undefined4 DAT_80328c18;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc071;
extern undefined4 DAT_803dcd00;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern ModgfxInterface **gModgfxInterface;
extern int* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy
extern f64 DOUBLE_803e6558;
extern f64 DOUBLE_803e65a0;
extern f64 DOUBLE_803e65d8;
extern f64 DOUBLE_803e6600;
extern f64 DOUBLE_803e6628;
extern f64 DOUBLE_803e6638;
extern f64 DOUBLE_803e6650;
extern f32 lbl_803DC074;
extern f32 lbl_803DE8D0;
extern f32 lbl_803E654C;
extern f32 lbl_803E6550;
extern f32 lbl_803E6554;
extern f32 lbl_803E6560;
extern f32 lbl_803E6564;
extern f32 lbl_803E6568;
extern f32 lbl_803E6574;
extern f32 lbl_803E6578;
extern f32 lbl_803E6584;
extern f32 lbl_803E6588;
extern f32 lbl_803E658C;
extern f32 lbl_803E6590;
extern f32 lbl_803E6594;
extern f32 lbl_803E6598;
extern f32 lbl_803E659C;
extern f32 lbl_803E65A8;
extern f32 lbl_803E65AC;
extern f32 lbl_803E65B0;
extern f32 lbl_803E65B4;
extern f32 lbl_803E65C0;
extern f32 lbl_803E65C4;
extern f32 lbl_803E65C8;
extern f32 lbl_803E65CC;
extern f32 lbl_803E65D0;
extern f32 lbl_803E65D4;
extern f32 lbl_803E65E0;
extern f32 lbl_803E65E4;
extern f32 lbl_803E65E8;
extern f32 lbl_803E65F0;
extern f32 lbl_803E65F4;
extern f32 lbl_803E65F8;
extern f32 lbl_803E6608;
extern f32 lbl_803E660C;
extern f32 lbl_803E6614;
extern f32 lbl_803E6618;
extern f32 lbl_803E661C;
extern f32 lbl_803E6620;
extern f32 lbl_803E6624;
extern f32 lbl_803E6630;
extern f32 lbl_803E6634;
extern f32 lbl_803E6644;
extern f32 lbl_803E6648;
extern undefined4 uRam803de8d4;

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
extern EffectInterface **gPartfxInterface;

void SB_FireBall_hitDetect(int *obj)
{
    ObjHitsPriorityState *params = *(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState;
    int i;
    if (params->lastHitObject == 0) return;
    params->flags &= ~1;
    for (i = 50; i != 0; i--) {
        (*gPartfxInterface)->spawnObject(obj, 167, NULL, 1, -1, NULL);
    }
    for (i = 10; i != 0; i--) {
        (*gPartfxInterface)->spawnObject(obj, 171, NULL, 1, -1, NULL);
    }
}

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
void FUN_801e55c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)
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
void SB_FireBall_release(void) {}
void SB_FireBall_initialise(void) {}
void SB_CloudBall_release(void) {}
void SB_CloudBall_initialise(void) {}
void SB_KyteCage_render(void) {}
void SB_KyteCage_hitDetect(void) {}
void SB_KyteCage_release(void) {}
void SB_KyteCage_initialise(void) {}
void SB_CageKyte_free(void) {}
void SB_CageKyte_hitDetect(void) {}
void SB_CageKyte_release(void) {}
void SB_CageKyte_initialise(void) {}
void SB_SeqDoor_free(void) {}
void SB_SeqDoor_hitDetect(void) {}
void SB_SeqDoor_release(void) {}
void SB_SeqDoor_initialise(void) {}
void SB_MiniFire_hitDetect(void) {}
void SB_MiniFire_release(void) {}
void SB_MiniFire_initialise(void) {}
void ShipBattle_hitDetect(void) {}
void ShipBattle_release(void) {}
void ShipBattle_initialise(void) {}
void Flag_free(void) {}
void Flag_hitDetect(void) {}
void Flag_release(void) {}
void Flag_initialise(void) {}
void SB_ShipGunBroke_free(void) {}
void SB_ShipGunBroke_hitDetect(void) {}
void SB_ShipGunBroke_init(void) {}
void SB_ShipGunBroke_release(void) {}
void SB_ShipGunBroke_initialise(void) {}
void shop_hitDetect(void) {}
void shop_release(void) {}
void shop_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int SB_CloudBall_getExtraSize(void) { return 0x24; }
int SB_CloudBall_getObjectTypeId(void) { return 0x0; }
int SB_KyteCage_getExtraSize(void) { return 0x8; }
int SB_KyteCage_getObjectTypeId(void) { return 0x0; }
int SB_CageKyte_getExtraSize(void) { return 0x2; }
int SB_CageKyte_getObjectTypeId(void) { return 0x1; }
int SB_SeqDoor_getExtraSize(void) { return 0x0; }
int SB_SeqDoor_getObjectTypeId(void) { return 0x0; }
int SB_MiniFire_getExtraSize(void) { return 0x2; }
int SB_MiniFire_getObjectTypeId(void) { return 0x0; }
int ShipBattle_getExtraSize(void) { return 0x140; }
int ShipBattle_getObjectTypeId(void) { return 0xb; }
int Lamp_getExtraSize(void) { return 0x1; }
int Flag_getExtraSize(void) { return 0x0; }
int Flag_getObjectTypeId(void) { return 0x0; }
int SB_ShipGunBroke_getExtraSize(void) { return 0x1; }
int SB_ShipGunBroke_getObjectTypeId(void) { return 0x0; }
int shop_getExtraSize(void) { return 0x5; }
int shop_getObjectTypeId(void) { return 0x0; }
int fn_801E66DC(void) { return 0x0; }
int fn_801E66E4(void) { return 0x0; }

/* 16b chained patterns. */
s32 shop_getStateField1(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x1); }
s32 shop_setScale(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x0); }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E58E8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5920;
extern f32 lbl_803E5978;
extern f32 lbl_803E59A8;
extern f32 lbl_803E59C8;
extern void Sfx_StopObjectChannel(int* obj, int channel);
extern void Sfx_PlayFromObject(int* obj, int sfxId);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern int GameBit_Get(int);
extern void GameBit_Set(int slot, int val);
extern u8 framesThisStep;
extern void *Obj_GetPlayerObject(void);
extern f32 Vec_distance(void *a, void *b);
extern void ObjGroup_RemoveObject(int* obj, int group);
extern void ObjGroup_AddObject(int obj, int group);
extern void ModelLightStruct_free(int* p);
extern void Music_Trigger(int a, int b);
extern void objfx_spawnFlaggedTrailBurst(int* obj, f32 f, int a, int b, int c, void* d);
extern f32 lbl_803E5998;
extern f32 lbl_803E599C;
extern f32 lbl_803E59AC;
extern f32 lbl_803E59B0;
extern f32 lbl_803E5958;
extern f32 lbl_803E595C;
extern f64 lbl_803E5968;
extern f32 lbl_803E5970;
extern f32 lbl_803E5974;
extern f32 lbl_803E5960;
extern f32 lbl_803E5918;
extern f32 lbl_803E59D8;
extern f32 lbl_803E59DC;
extern f32 timeDelta;
extern u8 lbl_803DB411;
extern f32 lbl_803DDC50;
extern int* lbl_803DCAB4;
#define gBoneParticleEffectInterface lbl_803DCAB4
extern int Stack_IsEmpty(int stack);
extern int Stack_Pop(int stack, int *out);
int SB_SeqDoor_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
int Lamp_SeqFn(int obj, int unused, int state);
void SB_CloudBall_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E58E8); }
void SB_SeqDoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5920); }
void Lamp_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5978); }
void Flag_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E59A8); }
void shop_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E59C8); }

/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */
void Flag_init(int* obj, int* def)
{
    if (((GameObject *)obj)->anim.seqId != 0x803) {
        *(s16*)obj = (s16)((s32)*(s8*)((char*)def + 0x18) << 8);
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E5998, 0);
    }
}
void Flag_update(int obj)
{
    int linkedObj;

    if (((GameObject *)obj)->anim.seqId == 0x187) {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E59AC,
                                                                     (f32)(u32)framesThisStep,
                                                                     NULL);
    } else if (((GameObject *)obj)->anim.seqId == 0x803) {
        Obj_GetPlayerObject();
        linkedObj = *(int *)&((GameObject *)obj)->anim.parent;
        if ((((GameObject *)linkedObj)->objectFlags & 0x1000) != 0) {
            ((GameObject *)obj)->anim.velocityX = lbl_803E5998;
        } else {
            ((GameObject *)obj)->anim.velocityX = (f32)((GameObject *)linkedObj)->anim.rotZ * lbl_803E599C;
            ((GameObject *)obj)->anim.rotZ = (s16)((f32)((GameObject *)obj)->anim.rotZ + ((GameObject *)obj)->anim.velocityX);
        }
    } else {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E59B0,
                                                                     (f32)(u32)framesThisStep,
                                                                     NULL);
    }
}
int SB_KyteCage_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
    int i;
    int state;

    i = 0;
    state = *(int *)&((GameObject *)obj)->extra;
    while (i < animUpdate->eventCount) {
        u8 seqCode;

        seqCode = animUpdate->eventIds[i];
        if (seqCode == 1) {
            *(u8 *)(state + 4) = 1;
        } else if (seqCode == 2) {
            *(u8 *)(state + 4) = 2;
        }
        i++;
    }

    animUpdate->hitVolumePair = -4;
    if (((GameObject *)obj)->classIdB4 != -1) {
        animUpdate->hitVolumePair &= ~4;
        if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E5918,
                                                                         timeDelta, NULL) != 0) {
            Sfx_PlayFromObject((int *)obj, SFXfend_rob_beep2);
        }
    }

    animUpdate->sequenceEventActive = 0;
    return 0;
}
/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */
int SB_CageKyte_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate)
{
    int v = ((GameObject *)obj)->countF4;
    if (v > 0) {
        ((GameObject *)obj)->countF4 = v - 1;
    }
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x8;
    animUpdate->hitVolumePair = -2;
    animUpdate->sequenceEventActive = 0;
    return 0;
}
int SB_SeqDoor_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
    if (((GameObject *)obj)->anim.seqId != 0x173) {
        animUpdate->hitVolumePair = -2;
    }
    animUpdate->sequenceEventActive = 0;
    return 0;
}
extern f32 lbl_803E597C;
extern f32 lbl_803E5980;
extern f32 lbl_803E5984;
extern f32 lbl_803E5988;
extern f32 lbl_803E598C;
extern f64 lbl_803E5990;

int Lamp_SeqFn(int obj, int unused, int state)
{
    u8 effectArgs[0x18];
    int i;

    if ((s32)randomGetRange(0, 1) != 0) {
        *(u8 *)(state + 0x90) = 4;
    } else {
        *(u8 *)(state + 0x90) = 8;
    }
    *(u8 *)(state + 0x56) = 0;
    *(s16 *)(state + 0x6e) = -1;
    *(s16 *)(state + 0x6e) = (s16)(*(s16 *)(state + 0x6e) & ~0x20);

    if (Obj_GetPlayerObject() == NULL) {
        return 0;
    }
    if ((((GameObject *)obj)->objectFlags & 0x800) != 0) {
        *(f32 *)(effectArgs + 8) = lbl_803E597C;
        *(s16 *)(effectArgs + 6) = 0xc0d;
        *(f32 *)(effectArgs + 0xc) = *(f32 *)(effectArgs + 0xc) - ((GameObject *)obj)->anim.worldPosX;
        *(f32 *)(effectArgs + 0x10) = *(f32 *)(effectArgs + 0x10) - ((GameObject *)obj)->anim.worldPosY;
        *(f32 *)(effectArgs + 0x14) = *(f32 *)(effectArgs + 0x14) - ((GameObject *)obj)->anim.worldPosZ;
        for (i = 0; i < framesThisStep; i++) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x7a8, effectArgs, 6, -1, NULL);
        }
    }
    return 0;
}
int fn_801E66EC(int arg1, int arg2)
{
    int state;
    f32 local;
    int stk;
    int popOut;

    state = *(int *)(arg1 + 0xb8);
    local = lbl_803E59D8;

    if (*(s8 *)(arg2 + 0x27a) != 0) {
        if ((*(u16 *)(arg1 + 0xb0) & 0x800) != 0) {
            ((void (*)(int, int, f32 *, int, int))((void **)*gBoneParticleEffectInterface)[3])(
                arg1, 2031, &local, 80, 0);
        }
    }

    *(u8 *)(state + 0x9d6) = 0;
    *(f32 *)(arg2 + 0x280) = lbl_803E59DC;
    if (*(u8 *)(state + 0x9d6) == 0) {
        stk = *(int *)(state + 0x9b0);
        popOut = 0;
        if (Stack_IsEmpty(stk) == 0) {
            Stack_Pop(stk, &popOut);
        }
        return popOut + 1;
    }
    return 0;
}
void Lamp_free(int* obj)
{
    Sfx_StopObjectChannel(obj, 64);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}
void Lamp_init(int* obj, int* def)
{
    int* state = ((GameObject *)obj)->extra;
    if (((GameObject *)obj)->anim.seqId == 996) {
        *(s16*)obj = (s16)((u32)((LampObjectDef *)def)->unk1A << 8);
    } else {
        *(s16*)obj = (s16)((s32)((LampObjectDef *)def)->unk18 << 8);
    }
    ((GameObject *)obj)->anim.rotY = 0;
    ((GameObject *)obj)->anim.rotZ = 0;
    ((GameObject *)obj)->moveF8 = 0;
    *(s8*)state = 1;
    ((GameObject *)obj)->animEventCallback = (void *)Lamp_SeqFn;
}
void Lamp_update(int obj)
{
    u8 effectArgs[0x18];
    f32 distance;
    int i;

    distance = Vec_distance((void *)((int)Obj_GetPlayerObject() + 0x18), (void *)(obj + 0x18));
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x40) == 0) {
        if (distance < lbl_803E5980) {
            Sfx_PlayFromObject((int *)obj, SFXmn_eggylaugh216);
        }
    } else if (distance >= lbl_803E5980) {
        Sfx_StopObjectChannel((int *)obj, 0x40);
    }

    if (((GameObject *)obj)->anim.seqId != 0x3e4) {
        if (((GameObject *)obj)->moveF8 == 0) {
            ((GameObject *)obj)->moveF8 = 1;
            ObjAnim_SetMoveProgress((f32)(s32)randomGetRange(0, 90) / lbl_803E5980,
                                    (ObjAnimComponent *)obj);
        }
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E5984,
                                                                     timeDelta, NULL);
    }

    if ((((GameObject *)obj)->objectFlags & 0x800) != 0) {
        *(f32 *)(effectArgs + 8) = lbl_803E597C;
        *(s16 *)(effectArgs + 6) = 0xc0d;
        *(f32 *)(effectArgs + 0xc) = lbl_803E5988;
        *(f32 *)(effectArgs + 0x10) = lbl_803E598C;
        *(f32 *)(effectArgs + 0x14) = lbl_803E5988;
        ObjPath_GetPointWorldPosition(obj, 0, (f32 *)(effectArgs + 0xc), (f32 *)(effectArgs + 0x10),
                                      (f32 *)(effectArgs + 0x14), 1);
        if (((GameObject *)obj)->anim.parent != NULL) {
            *(f32 *)(effectArgs + 0xc) = *(f32 *)(effectArgs + 0xc) - ((GameObject *)obj)->anim.worldPosX;
            *(f32 *)(effectArgs + 0x10) = *(f32 *)(effectArgs + 0x10) - ((GameObject *)obj)->anim.worldPosY;
            *(f32 *)(effectArgs + 0x14) = *(f32 *)(effectArgs + 0x14) - ((GameObject *)obj)->anim.worldPosZ;
        } else {
            *(f32 *)(effectArgs + 0xc) = *(f32 *)(effectArgs + 0xc) - ((GameObject *)obj)->anim.localPosX;
            *(f32 *)(effectArgs + 0x10) = *(f32 *)(effectArgs + 0x10) - ((GameObject *)obj)->anim.localPosY;
            *(f32 *)(effectArgs + 0x14) = *(f32 *)(effectArgs + 0x14) - ((GameObject *)obj)->anim.localPosZ;
        }
        for (i = 0; i < framesThisStep; i++) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x7c7, effectArgs, 2, -1, NULL);
        }
    }
}
void SB_CageKyte_init(int p)
{
    ((GameObject *)p)->animEventCallback = (void *)SB_CageKyte_SeqFn;
    ((GameObject *)p)->objectFlags = (u16)((u32)((GameObject *)p)->objectFlags | 0x6000u);
}
void SB_CageKyte_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
void SB_CageKyte_update(int obj)
{
    s16 *state;
    int player;

    state = ((GameObject *)obj)->extra;
    if (((GameObject *)obj)->countF4 > 0) {
        ((GameObject *)obj)->countF4 = ((GameObject *)obj)->countF4 - 1;
    }

    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8;
    *state -= framesThisStep;
    player = (int)Obj_GetPlayerObject();
    Vec_distance((void *)&((GameObject *)obj)->anim.worldPosX, (void *)&((GameObject *)player)->anim.worldPosX);

    if (*state <= 0) {
        randomGetRange(0, 10);
        if ((u32)GameBit_Get(0xa71) == 0u) {
            Sfx_PlayFromObject((int *)obj, SFXfend_rob_beep3);
        }
        *state = (s16)randomGetRange(400, 600);
    }
}
void SB_CloudBall_free(int* obj)
{
    SBCloudBallState* state = ((GameObject *)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    {
        int* child = (int*)state->light;
        if (child != NULL) {
            ModelLightStruct_free(child);
            state->light = 0;
        }
    }
}
extern f32 lbl_803E58EC;
extern f32 lbl_803E58F0;
extern void projectileParticleFxFn_80099660(int *obj, f32 scale, int type);

void SB_CloudBall_hitDetect(int *obj)
{
    SBCloudBallState *state = ((GameObject *)obj)->extra;
    int *params = *(int **)&((GameObject *)obj)->anim.hitReactState;
    int *target = *(int **)&((ObjHitsPriorityState *)params)->lastHitObject;

    if ((void *)target == NULL) return;
    if (state->fadeTimer != lbl_803E58EC) return;
    if (*(s16 *)((char *)target + 0x46) == 142) {
        Sfx_PlayFromObject(obj, SFXen_rockshat16);
    }
    params = *(int **)&((GameObject *)obj)->anim.hitReactState;
    ((ObjHitsPriorityState *)params)->flags = (s16)(((ObjHitsPriorityState *)params)->flags & ~1);
    state->fadeTimer = lbl_803E58F0;
    ((GameObject *)obj)->anim.alpha = 0;
    projectileParticleFxFn_80099660(obj, lbl_803E58E8, 2);
}
extern int objCreateLight(int *obj, int mode);
extern void modelLightStruct_setLightKind(int light, int v);
extern void modelLightStruct_setDiffuseColor(int light, int p, int r, int g, int p2);
extern void lightSetFieldBC_8001db14(int light, int v);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
extern f32 lbl_803E5910;
extern f32 lbl_803E5914;

void SB_CloudBall_init(int *obj)
{
    SBCloudBallState *state = ((GameObject *)obj)->extra;
    int *params = *(int **)&((GameObject *)obj)->anim.hitReactState;

    ((ObjHitsPriorityState *)params)->flags = (s16)(((ObjHitsPriorityState *)params)->flags & ~1);
    params = *(int **)&((GameObject *)obj)->anim.hitReactState;
    ((ObjHitsPriorityState *)params)->trackContactMask = (u16)(((ObjHitsPriorityState *)params)->trackContactMask | 1);
    if ((void *)state->light == NULL) {
        state->light = objCreateLight(obj, 1);
        if ((void *)state->light != NULL) {
            modelLightStruct_setLightKind(state->light, 2);
            modelLightStruct_setDiffuseColor(state->light, 0, 90, 150, 0);
            lightSetFieldBC_8001db14(state->light, 1);
            modelLightStruct_setDistanceAttenuation(state->light, lbl_803E5910, lbl_803E5914);
        }
    }
}
extern f32 lbl_803E58F4;
extern f32 lbl_803E58F8;
extern f32 lbl_803E58FC;
extern f32 lbl_803E5900;
extern f32 lbl_803E5904;
extern f64 lbl_803E5908;
extern f32 lbl_803E58E8_;  // dummy to avoid duplicate
extern void Obj_FreeObject(int obj);
extern f32 lbl_803E58DC;
extern f32 lbl_803E58E0;
void SB_CloudBall_update(int obj)
{
    SBCloudBallState *state = ((GameObject *)obj)->extra;
    void *player = Obj_GetPlayerObject();
    f32 timer = state->fadeTimer;
    f32 zero = lbl_803E58EC;
    if (timer != zero) {
        state->fadeTimer = timer - timeDelta;
        if (state->fadeTimer <= zero) {
            state->fadeTimer = zero;
            Obj_FreeObject(obj);
        }
    } else {
        f32 particleVelocity[3];
        f32 velocityScale;
        ((GameObject *)obj)->anim.previousLocalPosX = ((GameObject *)obj)->anim.localPosX;
        ((GameObject *)obj)->anim.previousLocalPosY = ((GameObject *)obj)->anim.localPosY;
        ((GameObject *)obj)->anim.previousLocalPosZ = ((GameObject *)obj)->anim.localPosZ;
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E58F8 * (f32)(int)randomGetRange(-0x64, 0x64) + lbl_803E58F4;
        if (*(s8 *)&state->launched == 0) {
            state->velX = ((GameObject *)obj)->anim.velocityX;
            state->velY = ((GameObject *)obj)->anim.velocityY;
            state->velZ = ((GameObject *)obj)->anim.velocityZ;
            state->launched = 1;
            state->posX = ((GameObject *)obj)->anim.localPosX;
            state->posY = ((GameObject *)obj)->anim.localPosY;
            state->posZ = ((GameObject *)obj)->anim.localPosZ;
        }
        velocityScale = lbl_803E58FC;
        state->posX = velocityScale * (state->velX * timeDelta) + state->posX;
        state->posY = velocityScale * (state->velY * timeDelta) + state->posY;
        state->posZ = velocityScale * (state->velZ * timeDelta) + state->posZ;
        ((GameObject *)obj)->anim.localPosX = state->posX;
        ((GameObject *)obj)->anim.localPosY = state->posY;
        ((GameObject *)obj)->anim.localPosZ = state->posZ;
        ((GameObject *)obj)->countF4 = ((GameObject *)obj)->countF4 - framesThisStep;
        if (((GameObject *)obj)->countF4 < 0 || (player != NULL && (((GameObject *)player)->objectFlags & 0x1000) != 0)) {
            if (state->fadeTimer == lbl_803E58EC) {
                ((GameObject *)obj)->anim.alpha = 0;
                state->fadeTimer = lbl_803E58F0;
            }
        }
        *(s16 *)obj = (s16)getAngle(((GameObject *)obj)->anim.localPosX - ((GameObject *)obj)->anim.previousLocalPosX,
                                     ((GameObject *)obj)->anim.localPosZ - ((GameObject *)obj)->anim.previousLocalPosZ);
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->hitVolumePriority = 5;
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->hitVolumeId = 1;
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->objectHitMask = 0x10;
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->skeletonHitMask = 0x10;
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags |= 1;
        if ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->contactFlags != 0 && state->fadeTimer == lbl_803E58EC) {
            projectileParticleFxFn_80099660((int *)obj, lbl_803E58E8, 2);
            state->fadeTimer = lbl_803E58F0;
            ((GameObject *)obj)->anim.alpha = 0;
        }
        particleVelocity[0] = lbl_803E5900 * -state->velX;
        particleVelocity[1] = lbl_803E5900 * -state->velY;
        particleVelocity[2] = lbl_803E5900 * -state->velZ;
        objfx_spawnFlaggedTrailBurst((int *)obj, lbl_803E5904, 2, 0x156, 0xf, particleVelocity);
        objfx_spawnFlaggedTrailBurst((int *)obj, lbl_803E5904, 2, 0x156, 0xf, particleVelocity);
        objfx_spawnFlaggedTrailBurst((int *)obj, lbl_803E5904, 2, 0x156, 0xf, particleVelocity);
        (*gPartfxInterface)->spawnObject((void *)obj, 0xa8, NULL, 2, -1, NULL);
    }
}
void SB_FireBall_init(int p)
{
    SBFireBallState *state = ((GameObject *)p)->extra;
    ((GameObject *)p)->countF4 = 0x4b0;
    state->launched = 0;
}
void SB_FireBall_update(int obj)
{
    SBFireBallState *state;
    f32 particleArgs[7];

    state = ((GameObject *)obj)->extra;
    if (state->owner == NULL) {
        state->owner = *(void **)&((GameObject *)obj)->moveF8;
    }

    if (state->owner != NULL) {
        *(s16 *)obj = 0;
        ((GameObject *)obj)->anim.rotZ = (s16)(((GameObject *)obj)->anim.rotZ + framesThisStep * SB_FIREBALL_SPIN_STEP);
        ((GameObject *)obj)->countF4 -= framesThisStep;
        if (((GameObject *)obj)->countF4 < 0) {
            Obj_FreeObject(obj);
            return;
        }

        if (*(s8 *)&state->launched == 0) {
            state->velX = ((GameObject *)obj)->anim.velocityX;
            state->velY = ((GameObject *)obj)->anim.velocityY;
            state->velZ = ((GameObject *)obj)->anim.velocityZ;
            state->launched = 1;
        }

        ((GameObject *)obj)->anim.localPosX += state->velX * timeDelta;
        ((GameObject *)obj)->anim.localPosY += state->velY * timeDelta;
        ((GameObject *)obj)->anim.localPosZ += state->velZ * timeDelta;

        particleArgs[2] = lbl_803E58DC;
        objfx_spawnFlaggedTrailBurst((int *)obj, lbl_803E58E0, SB_FIREBALL_SETUP_SIZE,
                                     SB_FIREBALL_SETUP_MODEL_ID, SB_FIREBALL_SETUP_PARAM, NULL);
        (*gPartfxInterface)->spawnObject((void *)obj, SB_FIREBALL_TRAIL_PARTICLE_ID, particleArgs, 1, -1, NULL);

        if (state->age > SB_FIREBALL_HITBOX_ENABLE_DELAY) {
            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->hitVolumePriority = SB_FIREBALL_HITBOX_TYPE;
            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->hitVolumeId = SB_FIREBALL_HITBOX_PRIORITY;
            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->objectHitMask = SB_FIREBALL_HITBOX_SIZE;
            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->skeletonHitMask = SB_FIREBALL_HITBOX_SIZE;
            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags |= SB_FIREBALL_SOLID_HITBOX_FLAG;
        } else {
            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~SB_FIREBALL_SOLID_HITBOX_FLAG;
        }

        state->age += framesThisStep;
    }
}
/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */
void SB_KyteCage_free(int* obj)
{
    void *child = (*(SBKyteCageState**)&((GameObject *)obj)->extra)->kyte;
    if (child != NULL) {
        ObjLink_DetachChild(obj, child);
    }
}

void SB_KyteCage_init(int *obj, int *params)
{
    SBKyteCageState *state = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->animEventCallback = (void *)SB_KyteCage_SeqFn;
    *(s16 *)obj = (s16)((s8) * (s8 *)&((ObjHitsPriorityState *)params)->localPosZ << 8);
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x6000);
    state->seqLatch = 0;
    if ((u32)GameBit_Get(117) == 0u) {
        getLActions(obj, obj, 88, 0, 0, 0);
        getLActions(obj, obj, 109, 0, 0, 0);
    }
}
extern int *ObjList_GetObjects(int *out_head, int *out_count);
extern void buttonDisable(int controller, int mask);
extern int *objModelGetVecFn_800395d8(int obj, int idx);
extern f32 lbl_803E591C;
void SB_KyteCage_update(int obj)
{
    extern uint GameBit_Get(int);
    SBKyteCageState *state = ((GameObject *)obj)->extra;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x8);
    if (state->kyte == NULL) {
        int *head;
        int count;
        int i;
        head = ObjList_GetObjects(&i, &count);
        for (i = 0; i < count; i++) {
            int child = head[i];
            if (*(s16 *)(child + 0x46) == 0x121) {
                *(int *)&state->kyte = child;
                ObjLink_AttachChild(obj, *(int *)&state->kyte, 1);
                i = count;
            }
        }
    }
    if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0) {
        if (GameBit_Get(0x92a) == 0) {
            buttonDisable(0, 0x100);
            (*gObjectTriggerInterface)->setRunSequenceWorldSpace(obj, 0);
            (*gObjectTriggerInterface)->runSequence(3, (void *)obj, -1);
            GameBit_Set(0x92a, 1);
            return;
        }
    }
    if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0) {
        buttonDisable(0, 0x100);
        (*gObjectTriggerInterface)->setRunSequenceWorldSpace(obj, 0);
        if (state->doorChoice != 0) {
            (*gObjectTriggerInterface)->runSequence(2, (void *)obj, -1);
        } else {
            (*gObjectTriggerInterface)->runSequence(1, (void *)obj, -1);
            state->doorChoice = 1;
        }
    }
    if (((GameObject *)obj)->anim.parent != NULL) {
        int kind = *(int *)(*(int *)&((GameObject *)obj)->anim.parent + 0xf4);
        int *mvec = objModelGetVecFn_800395d8(obj, 0);
        if (mvec != 0 && kind < 9 && ((GameObject *)obj)->anim.currentMove != 5) {
            *(s16 *)((char *)mvec + 4) = *(s16 *)(*(int *)&((GameObject *)obj)->anim.parent + 4);
            ObjAnim_SetCurrentMove(obj, 5, lbl_803E591C, 0);
        } else if (mvec != 0 && kind >= 9 && ((GameObject *)obj)->anim.currentMove != 9) {
            *(s16 *)((char *)mvec + 4) = 0;
            ObjAnim_SetCurrentMove(obj, 9, lbl_803E591C, 0);
        }
    }
    if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E5918,
                                                                     timeDelta, NULL) != 0) {
        Sfx_PlayFromObject((int *)obj, SFXfend_rob_beep2);
    }
}
void SB_MiniFire_free(int* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->detachSource(obj);
}
extern int lbl_803DC098;
extern f32 lbl_803E592C;
extern f32 lbl_803E5948;
extern f32 lbl_803E594C;
extern f32 lbl_803E5950;

void SB_MiniFire_init(int obj)
{
    void *resource;

    ((GameObject *)obj)->countF4 = 180;
    ((GameObject *)obj)->anim.velocityX = -(lbl_803E594C * (f32)(s32)randomGetRange(20, 40)) + lbl_803E5948;
    ((GameObject *)obj)->anim.velocityY = lbl_803E592C;
    ((GameObject *)obj)->anim.velocityZ = lbl_803E5950;
    ((GameObject *)obj)->anim.rootMotionScale = ((GameObject *)obj)->anim.rootMotionScale * lbl_803E5948;

    resource = Resource_Acquire(117, 1);
    (*(void (**)(int, int, int, int, int, int))(*(int *)resource + 4))(
        obj, lbl_803DC098, 0, 0x10002, -1, 0);
    lbl_803DC098++;
    if (lbl_803DC098 > 3) {
        lbl_803DC098 = 1;
    }
    Resource_Release(resource);
    Sfx_PlayFromObject((int *)obj, SFXen_ripefruit11);
    Sfx_PlayFromObject((int *)obj, SFXbaddie_crater_call);
}
extern void fn_80053ED0(int);
extern void fn_80053EBC(int);
extern f32 lbl_803E5928;

void SB_MiniFire_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) {
        fn_80053ED0(8);
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E5928);
        fn_80053EBC(8);
    }
}
extern f64 lbl_803E5940;
extern f32 lbl_803E5930;
extern f32 lbl_803E5934;
extern f32 lbl_803E5938;
extern f32 lbl_803E593C;
void SB_MiniFire_update(int obj)
{
    f32 buf[6];
    f32 dx;
    f32 dy;
    f32 dz;
    int dt;
    ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.velocityX * timeDelta + ((GameObject *)obj)->anim.localPosX;
    ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.velocityZ * timeDelta + ((GameObject *)obj)->anim.localPosZ;
    buf[3] = lbl_803E592C;
    buf[4] = lbl_803E592C;
    buf[5] = lbl_803E592C;
    buf[2] = lbl_803E5928;
    if (((GameObject *)obj)->countF4 <= 0x3c) {
        buf[2] = (f32)((GameObject *)obj)->countF4 / lbl_803E5930;
        ((GameObject *)obj)->anim.alpha =
            (u8)(int)(lbl_803E5934 * ((f32)((GameObject *)obj)->countF4 / *(f32 *)&lbl_803E5930));
    }
    *(s16 *)((char *)buf + 4) = 0;
    *(s16 *)((char *)buf + 2) = 0;
    *(s16 *)((char *)buf + 0) = 0;
    (*gPartfxInterface)->spawnObject((void *)obj, 0xa0, buf, 1, -1, NULL);
    dy = ((GameObject *)obj)->anim.localPosY - ((GameObject *)obj)->anim.previousLocalPosY;
    dz = ((GameObject *)obj)->anim.localPosZ - ((GameObject *)obj)->anim.previousLocalPosZ;
    dx = ((GameObject *)obj)->anim.localPosX - ((GameObject *)obj)->anim.previousLocalPosX;
    buf[3] = dx / lbl_803E5938;
    buf[4] = dy / lbl_803E5938;
    buf[5] = dz / lbl_803E5938;
    (*gPartfxInterface)->spawnObject((void *)obj, 0xa0, buf, 1, -1, NULL);
    buf[3] = buf[3] * lbl_803E593C;
    buf[4] = buf[4] * lbl_803E593C;
    buf[5] = buf[5] * lbl_803E593C;
    (*gPartfxInterface)->spawnObject((void *)obj, 0xa0, buf, 1, -1, NULL);
    *(s16 *)obj = *(s16 *)obj + framesThisStep * 0x374;
    ((GameObject *)obj)->anim.rotY = ((GameObject *)obj)->anim.rotY + framesThisStep * 0x12c;
    ((GameObject *)obj)->countF4 = ((GameObject *)obj)->countF4 - framesThisStep;
    if (((GameObject *)obj)->countF4 < 0) {
        Obj_FreeObject(obj);
    }
}
void SB_SeqDoor_init(int* obj, int* def)
{
    ((GameObject *)obj)->animEventCallback = (void *)SB_SeqDoor_SeqFn;
    *(s16*)obj = (s16)((s32)((SBSeqDoorObjectDef *)def)->unk18 << 8);
    {
        s8 b = ((SBSeqDoorObjectDef *)def)->unk19;
        ((ObjAnimComponent *)obj)->bankIndex = (s8)(((u32)-b | (u32)b) >> 31);
    }
}
void SB_SeqDoor_update(int *obj)
{
    if (((GameObject *)obj)->anim.seqId == 371) {
        if (((GameObject *)obj)->countF4 == 0) {
            if ((u32)GameBit_Get(2635) != 0u) {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                ((GameObject *)obj)->countF4 = 1;
            }
        }
    }
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
}
extern f32 lbl_803E59C0;

void SB_ShipGunBroke_render(int* obj, int p2, int p3, int p4, int p5)
{
    int* p = *(int**)&((GameObject *)obj)->anim.placementData;
    if ((u32)GameBit_Get(((SBShipGunBrokePlacement *)p)->unk1E) != 0u) {
        ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E59C0);
    }
}
void SB_ShipGunBroke_update(int* obj)
{
    int* p = *(int**)&((GameObject *)obj)->anim.placementData;
    if ((u32)GameBit_Get(((SBShipGunBrokePlacement *)p)->unk1E) != 0u) {
        Sfx_PlayFromObject(obj, SFXen_nlite1_c);
    }
}

void ShipBattle_free(int* obj)
{
    int* state = ((GameObject *)obj)->extra;
    (*gObjectTriggerInterface)->freeState((u8 *)state);
    ((void(*)(int*, int, int, int, int))((void**)*gTitleMenuControlInterface)[2])(obj, 0xffff, 0, 0, 0);
    {
        int light = ((GameObject *)obj)->moveF8;
        if (light != 0) {
            ModelLightStruct_free((int*)light);
        }
    }
}
void ShipBattle_init(int obj, int def)
{
    ShipBattleState *state;
    int light;
    int chainIndex;

    state = ((GameObject *)obj)->extra;
    state->unk6A = ((ShipBattleObjectDef *)def)->unk1A;
    state->unk6E = -1;
    state->unk24 =
        lbl_803E595C / (lbl_803E595C + (f32)((ShipBattleObjectDef *)def)->unk24);
    state->unk28 = -1;

    chainIndex = ((GameObject *)obj)->countF4;
    if (chainIndex == 0) {
        if (((ShipBattleObjectDef *)def)->unk18 != 1) {
            (*gObjectTriggerInterface)->loadAnimData((u8 *)state, (u8 *)def);
            ((GameObject *)obj)->countF4 = ((ShipBattleObjectDef *)def)->unk18 + 1;
            goto light_setup;
        }
    }

    if (chainIndex != 0) {
        if (((ShipBattleObjectDef *)def)->unk18 != chainIndex - 1) {
            (*gObjectTriggerInterface)->freeState((u8 *)state);
            if (((ShipBattleObjectDef *)def)->unk18 != -1) {
                (*gObjectTriggerInterface)->loadAnimData((u8 *)state, (u8 *)def);
            }
            ((GameObject *)obj)->countF4 = ((ShipBattleObjectDef *)def)->unk18 + 1;
        }
    }

light_setup:
    if (((GameObject *)obj)->anim.seqId == 0x171) {
        light = objCreateLight((int *)obj, 1);
        if ((u32)light != 0) {
            modelLightStruct_setLightKind(light, 2);
            modelLightStruct_setDiffuseColor(light, 200, 60, 0, 0);
            modelLightStruct_setDistanceAttenuation(light, lbl_803E5970, lbl_803E5974);
        }
        ((GameObject *)obj)->moveF8 = light;
    }

    lbl_803DDC50 = lbl_803E5958;
    *(u8 *)((char *)&lbl_803DDC50 + 4) = 0;
}
void ShipBattle_render(int* obj)
{
    objRenderFn_8003b8f4(lbl_803E595C);
    if (((GameObject *)obj)->anim.seqId == 369) {
        objfx_spawnFlaggedTrailBurst(obj, lbl_803E5960, 4, 389, 5, NULL);
    }
}
void ShipBattle_update(int obj)
{
    int *objects;
    int objectCount;
    int triggerResult;
    int current;
    int linkedObject;
    int sameGroupCount;
    int groupId;

    if (((GameObject *)obj)->anim.placementData == NULL || *(s16 *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x18) == -1) {
        return;
    }

    triggerResult = (*gObjectTriggerInterface)->update((u8 *)obj, (f32)lbl_803DB411);
    if (triggerResult == 0 || ((GameObject *)obj)->classIdB4 != -2) {
        return;
    }

    groupId = *(s8 *)(*(int *)&((GameObject *)obj)->extra + 0x57);
    linkedObject = 0;
    objects = ObjList_GetObjects(&triggerResult, &objectCount);
    sameGroupCount = 0;
    triggerResult = 0;
    while (triggerResult < objectCount) {
        current = objects[triggerResult];
        if (*(s16 *)(current + 0xb4) == groupId) {
            linkedObject = current;
        }
        if (*(s16 *)(current + 0xb4) == -2 && *(s16 *)(current + 0x44) == 0x10 &&
            groupId == *(s8 *)(*(int *)(current + 0xb8) + 0x57)) {
            sameGroupCount++;
        }
        triggerResult++;
    }

    if (sameGroupCount <= 1 && linkedObject != 0 && *(s16 *)(linkedObject + 0xb4) != -1) {
        *(s16 *)(linkedObject + 0xb4) = -1;
        (*gObjectTriggerInterface)->endSequence(groupId);
    }
    ((GameObject *)obj)->classIdB4 = -1;
    Obj_FreeObject(obj);
}
void shop_buyItem(int obj, int price)
{
    int player;
    int state;
    int mapEventState;
    u8 *items;
    s16 boughtBit;

    player = (int)Obj_GetPlayerObject();
    state = *(int *)&((GameObject *)obj)->extra;
    mapEventState = (int)(*gMapEventInterface)->getState(*gMapEventInterface);
    playerAddMoney(player, -price);

    switch (((ShopBuyItemState *)state)->unk1) {
        case 0:
            playerAddHealth(player, 2);
            break;
        case 0x17:
            *(u8 *)(mapEventState + 0xa) = 10;
            break;
        case 1:
            playerAddHealth(player, 8);
            break;
        case 2:
            playerAddHealth(player, 4);
            break;
        case 3:
            playerAddHealth(player, 0x1c);
            break;
        case 4:
            gameBitIncrement(0x66c);
            break;
        case 5:
            gameBitIncrement(0x86a);
            break;
        case 6:
            gameBitIncrement(0xc1);
            break;
        case 7:
            gameBitIncrement(0x13d);
            gameBitIncrement(0x5d6);
            break;
        case 8:
            gameBitIncrement(0x3f5);
            break;
    }

    items = lbl_80327FD0;
    boughtBit = *(s16 *)(items + ((ShopBuyItemState *)state)->unk1 * 0xc + 8);
    if (boughtBit != -1) {
        GameBit_Set(boughtBit, 1);
    }
}
void shop_free(int* obj)
{
    skyFn_80088c94(7, 0);
    ObjGroup_RemoveObject(obj, 9);
    Music_Trigger(144, 0);
    GameBit_Set(3838, 0);
}

void shop_func0B(int* obj, int v, int p3)
{
    s8* state = ((GameObject *)obj)->extra;
    state[0] = (s8)v;
    if (v != 0) {
        (*gObjectTriggerInterface)->runSequence(p3, obj, -1);
    }
}
/* EN v1.0 0x801E60A4  size: 28b  shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash (s8)v in obj->_b8[4]. */
void shop_func15(int* obj, int v)
{
    s8* b = ((GameObject *)obj)->extra;
    b[2] = 0;
    b[3] = 0;
    b[4] = (s8)v;
}
/* EN v1.0 0x801E607C  size: 40b  Increment-and-store: obj->_b8[2] += p3,
 * obj->_b8[3] += p2. */
void shop_func16(int* obj, int p2, int p3)
{
    s8* b = ((GameObject *)obj)->extra;
    b[2] = (s8)(b[2] + p3);
    b[3] = (s8)(b[3] + p2);
}
/* EN v1.0 0x801E6050  size: 44b  Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */
void shop_func17(int* obj, int* out_b3, int* out_b2, int* out_b4)
{
    s8* b = ((GameObject *)obj)->extra;
    *out_b2 = b[2];
    *out_b3 = b[3];
    *out_b4 = b[4];
}
/* shop_getItem* helpers -- table lookup */
int shop_getItemPrice(int p, int idx)
{
    if (idx >= 0 && idx < 0x3c) {
        return lbl_80327FD0[idx * 0xc];
    }
    return 0;
}
s16 shop_getItemTextId(int p, int idx)
{
    if (idx >= 0 && idx < 0x3c) {
        return *(s16 *)&lbl_80327FD0[idx * 0xc + 0xa];
    }
    return 0;
}
u8 shop_getItemField4(int p, int idx)
{
    if (idx >= 0 && idx < 0x3c) {
        return lbl_80327FD0[idx * 0xc + 0x4];
    }
    return 0;
}
u8 shop_getItemMinPrice(int p, int idx)
{
    if (idx >= 0 && idx < 0x3c) {
        return lbl_80327FD0[idx * 0xc + 0x5];
    }
    return 0;
}
void shop_init(int obj, int objDef)
{
    int i;
    u8 *item;

    *(s8 *)(*(int *)&((GameObject *)obj)->extra + 1) = -1;
    ObjGroup_AddObject(obj, 9);
    i = 0;
    item = lbl_80327FD0;
    while (i < 0x3c) {
        item[5] = item[randomGetRange(0, 2) + 1];
        item += 0xc;
        i++;
    }
    Music_Trigger(0x90, 1);
    ((GameObject *)obj)->moveF8 = 0;
    GameBit_Set(0xefe, 1);
}
/* EN v1.0 0x801E6358  size: 104b  Returns 1 unless the item's
 * "available" GameBit gate (lbl_80327FD0[idx*12 + 6]) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */
int shop_isItemAvailable(int p, int idx)
{
    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    slot = *(s16 *)(lbl_80327FD0 + idx * 0xc + 0x6);
    if (slot == -1 || (u32)GameBit_Get(slot) != 0u) {
        result = 1;
    }
    return result;
}
/* EN v1.0 0x801E62F0  size: 104b  Returns 1 when shop item's "bought"
 * GameBit (slot at lbl_80327FD0[idx*12 + 8]) is set; else 0. */
int shop_isItemBought(int p, int idx)
{
    s16 slot;
    int result;
    Obj_GetPlayerObject();
    result = 0;
    slot = *(s16 *)(lbl_80327FD0 + idx * 0xc + 0x8);
    if (slot != -1 && (u32)GameBit_Get(slot) != 0u) {
        result = 1;
    }
    return result;
}
void shop_setStateField1(int* obj, int v)
{
    s8* state = ((GameObject *)obj)->extra;
    state[1] = (s8)v;
}
void shop_update(int obj)
{
    int player;

    player = (int)Obj_GetPlayerObject();
    if (fn_802966CC(player) != NULL && (u32)GameBit_Get(0x18b) == 0u) {
        fn_80295CF4(player, 0);
    }

    if (((GameObject *)obj)->countF4 == 0) {
        (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 0, 1);
        (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 5, 1);
        (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 6, 1);
        GameBit_Set(0x617, 1);
        skyFn_80088c94(7, 1);
        ((GameObject *)obj)->countF4 = 1;
    }

    if ((u32)GameBit_Get(0xd21) != 0u && ((GameObject *)obj)->moveF8 == 0) {
        envFxActFn_800887f8(0);
        getEnvfxAct(obj, obj, 0x1c8, 0);
        getEnvfxAct(obj, obj, 0x1cb, 0);
        ((GameObject *)obj)->moveF8 = 1;
        return;
    }

    if ((u32)GameBit_Get(0xd21) == 0u && ((GameObject *)obj)->moveF8 != 0) {
        ((GameObject *)obj)->moveF8 = 0;
    }
}
