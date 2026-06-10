#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll/scarab.h"
#include "main/dll/baddie_state.h"
#include "main/dll/rom_curve_interface.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/objhits_types.h"
#include "main/objseq.h"

typedef struct DllCBPlacement {
    u8 pad0[0x4 - 0x0];
    s8 unk4;
    s8 unk5;
    u8 unk6;
    u8 unk7;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x24 - 0x14];
    s16 unk24;
    u8 pad26[0x2C - 0x26];
    s16 unk2C;
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DllCBPlacement;


typedef struct DllCBState {
    f32 unk0;
    f32 unk4;
    u8 pad8[0x3DC - 0x8];
    void *unk3DC;
    s32 unk3E0;
    u8 pad3E4[0x3F6 - 0x3E4];
    s16 unk3F6;
    u8 pad3F8[0x3FE - 0x3F8];
    u16 unk3FE;
    u16 flags400;
    u8 pad402[0x405 - 0x402];
    s8 unk405;
    u8 pad406[0x408 - 0x406];
} DllCBState;


typedef struct GrimbleState {
    u8 pad0[0x38 - 0x0];
    s32 unk38;
    u8 pad3C[0x45 - 0x3C];
    s8 unk45;
    u8 pad46[0x48 - 0x46];
    f32 unk48;
    u8 pad4C[0x58 - 0x4C];
    s16 unk58;
    u8 pad5A[0x60 - 0x5A];
} GrimbleState;


extern undefined8 FUN_80003494();
extern undefined8 FUN_80006824();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069b8();
extern undefined4 FUN_800069bc();
extern int FUN_80006a10();
extern undefined4 FUN_80006a54();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017b00();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined8 ObjMsg_SendToObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_8015b47c();
extern undefined4 FUN_8015b7f0();
extern undefined4 FUN_8015badc();
extern undefined4 FUN_8015bb80();
extern undefined4 FUN_8015bbc8();
extern undefined4 FUN_8015bc20();
extern undefined4 FUN_8015bd9c();
extern undefined4 FUN_8015be40();
extern undefined4 FUN_8015c00c();
extern undefined4 FUN_8015c1b4();
extern undefined4 FUN_8015c3b4();
extern undefined4 FUN_8015c514();
extern undefined4 FUN_8015c654();
extern undefined4 FUN_8015c7a0();
extern undefined4 FUN_8015c8bc();
extern undefined4 FUN_8015ca54();
extern undefined4 FUN_8015cd2c();
extern undefined4 FUN_8015d00c();
extern undefined4 FUN_8015d19c();
extern undefined4 FUN_8015d324();
extern undefined4 FUN_8015d518();
extern undefined4 FUN_8015d6ec();
extern undefined4 FUN_8015da7c();
extern undefined4 FUN_8015de40();
extern undefined4 FUN_8015e038();
extern undefined4 FUN_8015e21c();
extern undefined8 FUN_80286838();
extern undefined4 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4 DAT_803209f0;
extern undefined4 DAT_80320a68;
extern undefined4 DAT_80320af8;
extern undefined4 DAT_80320b70;
extern undefined4 DAT_80320bd0;
extern undefined4 DAT_80320c58;
extern undefined4 DAT_80320cd0;
extern undefined4 DAT_803ad188;
extern undefined4 DAT_803ad18c;
extern undefined4 DAT_803ad190;
extern undefined4 DAT_803ad194;
extern undefined4 DAT_803ad198;
extern undefined4 DAT_803ad19c;
extern undefined4 DAT_803ad1a0;
extern undefined4 DAT_803ad1a4;
extern undefined4 DAT_803ad1a8;
extern undefined4 DAT_803ad1ac;
extern undefined4 DAT_803ad1b0;
extern undefined4 DAT_803ad1b4;
extern undefined4 DAT_803ad1b8;
extern undefined4 DAT_803ad1bc;
extern undefined4 DAT_803ad1c0;
extern undefined4 DAT_803ad1c4;
extern undefined4 DAT_803ad1c8;
extern undefined4 DAT_803ad1cc;
extern undefined4 DAT_803ad1d0;
extern undefined4 DAT_803ad1d4;
extern undefined4 DAT_803ad1d8;
extern undefined4 DAT_803ad1dc;
extern undefined4 DAT_803ad1e0;
extern undefined4 DAT_803ad1f8;
extern undefined4 DAT_803ad210;
extern undefined4 DAT_803ad230;
extern undefined4 DAT_803ad248;
extern undefined4 DAT_803dc070;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern EffectInterface **gPartfxInterface;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e39a0;
extern f64 DOUBLE_803e3a58;
extern f64 DOUBLE_803e3aa0;
extern f64 DOUBLE_803e3ac0;
extern f64 DOUBLE_803e3ae0;
extern f64 DOUBLE_803e3af8;
extern f64 DOUBLE_803e3b18;
extern f64 DOUBLE_803e3b38;
extern f64 DOUBLE_803e3b70;
extern f32 lbl_803DC074;
extern f32 lbl_803E39AC;
extern f32 lbl_803E39BC;
extern f32 lbl_803E39EC;
extern f32 lbl_803E3A28;
extern f32 lbl_803E3A4C;
extern f32 lbl_803E3A50;
extern f32 lbl_803E3A60;
extern f32 lbl_803E3A64;
extern f32 lbl_803E3A68;
extern f32 lbl_803E3A6C;
extern f32 lbl_803E3A70;
extern f32 lbl_803E3A74;
extern f32 lbl_803E3A78;
extern f32 lbl_803E3A7C;
extern f32 lbl_803E3A80;
extern f32 lbl_803E3A84;
extern f32 lbl_803E3A88;
extern f32 lbl_803E3A8C;
extern f32 lbl_803E3A90;
extern f32 lbl_803E3A94;
extern f32 lbl_803E3A98;
extern f32 lbl_803E3AAC;
extern f32 lbl_803E3AB0;
extern f32 lbl_803E3AB8;
extern f32 lbl_803E3ABC;
extern f32 lbl_803E3AC8;
extern f32 lbl_803E3ACC;
extern f32 lbl_803E3AD0;
extern f32 lbl_803E3AD4;
extern f32 lbl_803E3AD8;
extern f32 lbl_803E3AE8;
extern f32 lbl_803E3AEC;
extern f32 lbl_803E3AF0;
extern f32 lbl_803E3B00;
extern f32 lbl_803E3B04;
extern f32 lbl_803E3B08;
extern f32 lbl_803E3B0C;
extern f32 lbl_803E3B10;
extern f32 lbl_803E3B14;
extern f32 lbl_803E3B20;
extern f32 lbl_803E3B24;
extern f32 lbl_803E3B28;
extern f32 lbl_803E3B2C;
extern f32 lbl_803E3B30;
extern f32 lbl_803E3B34;
extern f32 lbl_803E3B40;
extern f32 lbl_803E3B48;
extern f32 lbl_803E3B4C;
extern f32 lbl_803E3B50;
extern f32 lbl_803E3B54;
extern f32 lbl_803E3B58;
extern f32 lbl_803E3B5C;
extern f32 lbl_803E3B60;
extern f32 lbl_803E3B64;
extern f32 lbl_803E3B68;
extern f32 lbl_803E3B6C;
extern f32 lbl_803E3B78;
extern f32 lbl_803E3B7C;
extern f32 lbl_803E3B80;
extern f32 lbl_803E3B84;
extern f32 lbl_803E3B88;
extern f32 lbl_803E3B8C;
extern f32 lbl_803E3B90;
extern f32 lbl_803E3B94;

/*
 * --INFO--
 *
 * Function: dll_CA_update
 * EN v1.0 Address: 0x8015D7B0
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x8015D86C
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dll_CA_update(int obj, int p2, int p3)
{
  extern void Sfx_PlayFromObject(int obj, int sfx);
  extern int fn_8015D3C0(int obj, int sub, int sub2);
  extern void mediumbasket_updateControlEffects(int obj, int sub);
  extern void mediumbasket_tryAcquireTarget(int obj, int sub, int sub2);
  extern void mediumbasket_updateTargetMotion(int obj, int sub, int sub2);
  extern int *gBaddieControlInterface;
  extern MapEventInterface **gMapEventInterface;
  extern ObjectTriggerInterface **gObjectTriggerInterface;
  extern f32 lbl_803E2D14;
  extern f32 lbl_803E2D90;
  extern f32 lbl_803E2DB8;
  GroundBaddieState *sub;
  int setup;

  sub = ((GameObject *)obj)->extra;
  setup = *(int *)&((GameObject *)obj)->anim.placementData;
  if (((GameObject *)obj)->unkF4 != 0) {
    if ((sub->baddie.unk270 != 3 || (sub->configFlags & 1) != 0) &&
        (*gMapEventInterface)->isTimedEventActive(((ObjPlacement *)setup)->mapId) != 0) {
      (*(void (**)(int, int, int, int, int, int, int, f32))(*(int *)gBaddieControlInterface +
                                                            0x58))(
          obj, setup, (int)sub, 14, 8, 0x102, 0x26, lbl_803E2DB8);
      sub->targetState = 0;
      Sfx_PlayFromObject(obj, SFXfoxcom_find);
      ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2D14, 0x10);
      *(s8 *)&sub->baddie.moveDone = 0;
      ((GameObject *)obj)->anim.alpha = 0xff;
      *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    }
  } else if (((GameObject *)obj)->unkF8 == 0) {
    ((GameObject *)obj)->anim.localPosX = ((ObjPlacement *)setup)->posX;
    ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)setup)->posY;
    ((GameObject *)obj)->anim.localPosZ = ((ObjPlacement *)setup)->posZ;
    (*gObjectTriggerInterface)->runSequence(*(s8 *)(setup + 0x2e), (void *)obj, -1);
    ((GameObject *)obj)->unkF8 = 1;
  } else {
    if ((*(int (**)(int, int, int))(*(int *)gBaddieControlInterface + 0x30))(obj, (int)sub, 0) == 0) {
      sub->targetState = 0;
    } else {
      fn_8015D3C0(obj, (int)sub, (int)sub);
      mediumbasket_updateControlEffects(obj, (int)sub);
      if (sub->targetState == 0) {
        mediumbasket_tryAcquireTarget(obj, (int)sub, (int)sub);
      } else {
        mediumbasket_updateTargetMotion(obj, (int)sub, (int)sub);
      }
      if ((sub->configFlags & 2) != 0) {
        ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)setup)->posY - lbl_803E2D90;
      }
    }
  }
}

/*
 * --INFO--
 *
 * Function: FUN_8015d99c
 * EN v1.0 Address: 0x8015D99C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8015DA64
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma scheduling off
#pragma peephole off
int fn_8015E3A0(int obj, int p2)
{
  extern void ObjHits_EnableObject(int);
  extern void ObjHits_SetHitVolumeSlot(int, int, int, int);
  extern void ObjHits_RegisterActiveHitVolumeObject(int);
  extern int *ObjList_GetObjects(int *, int *);
  extern f32 lbl_803E2DC8;
  extern f32 lbl_803E2DD8;
  GroundBaddieState *sub = ((GameObject *)obj)->extra;
  int count;
  int idx;

  if ((s32)(s8)*(u8 *)(p2 + 0x27a) != 0) {
    ObjHits_EnableObject(obj);
  }
  ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
  (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->objectPairPriority = 10;
  (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->objectPairHitVolume = 1;
  ObjHits_RegisterActiveHitVolumeObject(obj);

  if ((s32)(s8)*(u8 *)(p2 + 0x27a) != 0) {
    int *objs = ObjList_GetObjects(&idx, &count);
    while (idx < count) {
      int o = objs[idx];
      if ((void *)o != (void *)obj && ((GameObject *)o)->anim.seqId == 774) {
        (*(int (**)(int, int, int))(**(int **)&((GameObject *)o)->anim.dll + 0x24))(o, 129, 0);
      }
      idx++;
    }
  }

  *(f32 *)(p2 + 0x2a0) = lbl_803E2DD8;

  if ((s32)(s8)*(u8 *)(p2 + 0x27a) != 0) {
    ObjAnim_SetCurrentMove((int)obj, 10, lbl_803E2DC8, 0);
    *(u8 *)(p2 + 0x346) = 0;
  }
  *(u8 *)(p2 + 0x34d) = 1;

  if ((*(u32 *)(p2 + 0x314) & 0x1) != 0U) {
    int child = *(int *)&sub->control;
    *(u32 *)(p2 + 0x314) = *(u32 *)(p2 + 0x314) & ~0x1;
    *(u8 *)(child + 0x8) = (u8)(*(u8 *)(child + 0x8) | 0x1);
    Sfx_PlayFromObject(obj, SFXfoxcom_heel);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e0d0
 * EN v1.0 Address: 0x8015E0D0
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x8015E3CC
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
#pragma scheduling on
#pragma peephole on
FUN_8015e0d0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10)
{
  float fVar1;
  float *pfVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar3;
  
  fVar1 = lbl_803E3A60;
  if (*(char *)(param_10 + 0x27b) == '\0') {
    if (*(char *)(param_10 + 0x346) != '\0') {
      uVar3 = ObjMsg_SendToObjects(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,3,
                           param_9,0xe0000,param_9,in_r8,in_r9,in_r10);
      if (*(int *)&((GameObject *)param_9)->anim.placementData == 0) {
        FUN_80017ac8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
        return 0;
      }
      return 4;
    }
  }
  else {
    pfVar2 = *(float **)(*(int *)&((GameObject *)param_9)->extra + 0x40c);
    *pfVar2 = lbl_803E3A60;
    pfVar2[1] = fVar1;
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,6);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    ObjHits_DisableObject(param_9);
    *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode | 8;
  }
  return 0;
}

#pragma scheduling off
#pragma peephole off
int fn_8015E210(int *obj, GroundBaddieState *p)
{
  extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
  extern void *Obj_GetPlayerObject(void);
  extern f32 lbl_803E2DC8;
  extern f32 lbl_803E2DD4;
  int *objs;
  int count;
  int i;
  int *player_b8;
  int *player;
  int r;

  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2DC8, 0);
    *(s8 *)&p->baddie.moveDone = 0;
  }
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    objs = ObjList_GetObjects(&i, &count);
    for (; i < count; i++) {
      void *o = (void *)objs[i];
      if (o != (void *)obj && ((GameObject *)o)->anim.seqId == 774) {
        (*(void (**)(void *, int, int))(**(int **)&((GameObject *)o)->anim.dll + 0x24))(
            o, 129, 0);
      }
    }
    player_b8 = *(int **)((char *)Obj_GetPlayerObject() + 0xc8);
    player = (int *)Obj_GetPlayerObject();
    r = (**(int (**)(int *))(*(int *)(*(int *)&((GameObject *)player_b8)->anim.dll) + 0x44))(player_b8);
    if (r != 0) {
      if (((GameObject *)player)->anim.seqId != 0) {
        Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
      } else {
        Sfx_PlayFromObject(obj, SFXmv_ropecreak22);
      }
    } else {
      if (((GameObject *)player)->anim.seqId != 0) {
        Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
      } else {
        Sfx_PlayFromObject(obj, SFXfox_treadwater322);
      }
    }
    Sfx_PlayFromObject(obj, SFXfoxcom_stay);
  }
  *(s8 *)&p->baddie.unk34D = 3;
  p->baddie.moveSpeed = lbl_803E2DD4;
  p->baddie.animSpeedA = lbl_803E2DC8;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e260
 * EN v1.0 Address: 0x8015E260
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x8015E4F0
 * EN v1.1 Size: 132b
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
 * Function: FUN_8015e2e0
 * EN v1.0 Address: 0x8015E2E0
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8015E574
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015e2e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)&((GameObject *)param_9)->extra;
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = lbl_803E3A64;
  fVar1 = lbl_803E3A60;
  dVar4 = (double)lbl_803E3A60;
  *(float *)(param_10 + 0x280) = lbl_803E3A60;
  *(float *)(param_10 + 0x284) = fVar1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,0,param_12,
                 param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if ((*(byte *)(param_10 + 0x356) & 1) == 0) {
    iVar2 = FUN_80017a98();
    if (*(short *)(iVar2 + 0x46) == 0) {
      FUN_80006824(param_9,SFXfox_treadwater322);
    }
    else {
      FUN_80006824(param_9,SFXfoot_metal_run_2);
    }
    FUN_80006824(param_9,SFXdoor_unlocked);
    FUN_80006824(param_9,SFXfoxcom_find);
    *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 1;
  }
  if (((*(byte *)(param_10 + 0x356) & 2) == 0) && (lbl_803E3A68 < ((GameObject *)param_9)->anim.currentMoveProgress)) {
    FUN_80006824(param_9,SFXdoor_creak);
    *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 2;
    (**(code **)(*DAT_803dd738 + 0x4c))(param_9,(int)*(short *)(iVar3 + 0x3f0),0xffffffff,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e488
 * EN v1.0 Address: 0x8015E488
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x8015E6BC
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015e488(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int local_18;
  int local_14;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E3A60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    iVar1 = FUN_80017b00(&local_18,&local_14);
    for (; local_18 < local_14; local_18 = local_18 + 1) {
      uVar2 = *(uint *)(iVar1 + local_18 * 4);
      if ((uVar2 != param_9) && (*(short *)(uVar2 + 0x46) == 0x306)) {
        (**(code **)(**(int **)(uVar2 + 0x68) + 0x24))(uVar2,0x81,0);
      }
    }
    iVar1 = FUN_80017a98();
    iVar3 = *(int *)(iVar1 + 200);
    iVar1 = FUN_80017a98();
    iVar3 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x44))(iVar3);
    if (iVar3 == 0) {
      if (*(short *)(iVar1 + 0x46) == 0) {
        FUN_80006824(param_9,SFXfox_treadwater322);
      }
      else {
        FUN_80006824(param_9,SFXfoot_metal_run_2);
      }
    }
    else if (*(short *)(iVar1 + 0x46) == 0) {
      FUN_80006824(param_9,SFXmv_ropecreak22);
    }
    else {
      FUN_80006824(param_9,SFXfoot_metal_run_2);
    }
    FUN_80006824(param_9,SFXfoxcom_stay);
  }
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = lbl_803E3A6C;
  *(float *)(param_10 + 0x280) = lbl_803E3A60;
  return 0;
}

#pragma scheduling off
#pragma peephole off
int fn_8015DC04(int obj, GroundBaddieState *p)
{
  extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
  extern int randomGetRange(int min, int max);
  extern int *gBaddieControlInterface;
  extern int *gPlayerInterface;
  extern f64 lbl_803E2DC0;
  int count;
  int i;
  GroundBaddieState *sub;
  u8 *hit;
  int maxr;
  int four;
  int *objs;
  int r;
  int rnd;

  sub = ((GameObject *)obj)->extra;
  if (*(char *)&p->baddie.moveDone != '\0' || *(char *)&p->baddie.moveJustStartedB != '\0') {
    hit = *(u8 **)&sub->control;
    r = (*(int (**)(int, u8 *, f32, int))(*(int *)gBaddieControlInterface + 0x44))(
        obj, (u8 *)p, (f32)(u32)sub->aggroRange, 1);
    if (r != 0) {
      hit[9] &= ~2;
      return 5;
    }
    four = 0;
    maxr = 0;
    objs = ObjList_GetObjects(&i, &count);
    for (; i < count; i++) {
      void *o = (void *)objs[i];
      if (o != (void *)obj && ((GameObject *)o)->anim.seqId == 774) {
        int v = (*(int (**)(void *, int))(**(int **)&((GameObject *)o)->anim.dll + 0x20))(o, 0);
        if (v > maxr) {
          maxr = v;
        }
        if (v == 4) {
          four++;
        }
      }
    }
    rnd = randomGetRange(0, sub->aggression);
    if (maxr >= 5 || (hit[9] & 1) != 0) {
      if ((sub->configFlags & 2) != 0) {
        hit[9] |= 1;
      }
      (*(void (**)(int, u8 *, int))(*(int *)gPlayerInterface + 0x14))(obj, (u8 *)p, 4);
    } else if (rnd > 32) {
      if (four > 1) {
        (*(void (**)(int, u8 *, int))(*(int *)gPlayerInterface + 0x14))(obj, (u8 *)p, 2);
      } else {
        (*(void (**)(int, u8 *, int))(*(int *)gPlayerInterface + 0x14))(obj, (u8 *)p, 4);
      }
    } else if (rnd > 16) {
      (*(void (**)(int, u8 *, int))(*(int *)gPlayerInterface + 0x14))(obj, (u8 *)p, 2);
    } else {
      (*(void (**)(int, u8 *, int))(*(int *)gPlayerInterface + 0x14))(obj, (u8 *)p, 3);
    }
  }
  return 0;
}

#pragma dont_inline on
void fn_8015DAE8(void)
{
  extern void *gMediumBasketStateHandlersB[];
  extern void *gMediumBasketStateHandlersA[];
  extern int mediumbasket_updateOpenHitState();
  extern int mediumbasket_updateOpenState();
  extern int mediumbasket_updateHideResetState();
  extern int mediumbasket_updateImpactHitState();
  extern int mediumbasket_updateSpinState();
  extern int mediumbasket_stateHandlerA05();
  extern int mediumbasket_stateHandlerA06();
  extern int mediumbasket_updateHeightBlendState();
  extern int mediumbasket_updateControlMove5State();
  extern int mediumbasket_updateCommDownState();
  extern int mediumbasket_updateDropState();
  extern int mediumbasket_stateHandlerA0B();
  extern int mediumbasket_updateContactHitState();
  extern int mediumbasket_updateLandingState();
  extern int mediumbasket_checkTargetState();
  extern int mediumbasket_stateHandlerB01();
  extern int mediumbasket_stateHandlerB02();
  extern int mediumbasket_stateHandlerB03();
  extern int mediumbasket_stateHandlerB04();
  extern int mediumbasket_stateHandlerB05();
  extern int mediumbasket_stateHandlerB06();
  extern int mediumbasket_stateHandlerB07();

  gMediumBasketStateHandlersA[0] = (void *)mediumbasket_updateOpenHitState;
  gMediumBasketStateHandlersA[1] = (void *)mediumbasket_updateOpenState;
  gMediumBasketStateHandlersA[2] = (void *)mediumbasket_updateHideResetState;
  gMediumBasketStateHandlersA[3] = (void *)mediumbasket_updateImpactHitState;
  gMediumBasketStateHandlersA[4] = (void *)mediumbasket_updateSpinState;
  gMediumBasketStateHandlersA[5] = (void *)mediumbasket_stateHandlerA05;
  gMediumBasketStateHandlersA[6] = (void *)mediumbasket_stateHandlerA06;
  gMediumBasketStateHandlersA[7] = (void *)mediumbasket_updateHeightBlendState;
  gMediumBasketStateHandlersA[8] = (void *)mediumbasket_updateControlMove5State;
  gMediumBasketStateHandlersA[9] = (void *)mediumbasket_updateCommDownState;
  gMediumBasketStateHandlersA[10] = (void *)mediumbasket_updateDropState;
  gMediumBasketStateHandlersA[11] = (void *)mediumbasket_stateHandlerA0B;
  gMediumBasketStateHandlersA[12] = (void *)mediumbasket_updateContactHitState;
  gMediumBasketStateHandlersA[13] = (void *)mediumbasket_updateLandingState;
  gMediumBasketStateHandlersB[0] = (void *)mediumbasket_checkTargetState;
  gMediumBasketStateHandlersB[1] = (void *)mediumbasket_stateHandlerB01;
  gMediumBasketStateHandlersB[2] = (void *)mediumbasket_stateHandlerB02;
  gMediumBasketStateHandlersB[3] = (void *)mediumbasket_stateHandlerB03;
  gMediumBasketStateHandlersB[4] = (void *)mediumbasket_stateHandlerB04;
  gMediumBasketStateHandlersB[5] = (void *)mediumbasket_stateHandlerB05;
  gMediumBasketStateHandlersB[6] = (void *)mediumbasket_stateHandlerB06;
  gMediumBasketStateHandlersB[7] = (void *)mediumbasket_stateHandlerB07;
}
#pragma dont_inline reset

void dll_CA_init(int obj, u8 *p, int flags)
{
  extern int *gBaddieControlInterface;
  extern int *gPlayerInterface;
  extern f64 lbl_803E2D08;
  extern f32 lbl_803E2D14;
  extern f32 lbl_803E2D24;
  extern f32 lbl_803E2D54;
  extern f32 lbl_803E2DB8;
  GroundBaddieState *sub;
  u8 mode;

  sub = ((GameObject *)obj)->extra;
  mode = 6;
  if (flags != 0) {
    mode |= 1;
  }
  if ((*(u8 *)(p + 0x2b) & 0x20) == 0) {
    mode |= 8;
  }
  (*(void (**)(int, u8 *, int, int, int, int, u8, f32))(*(int *)gBaddieControlInterface + 0x58))(
      obj, p, (int)sub, 14, 8, 0x102, mode, lbl_803E2DB8);
  ((GameObject *)obj)->animEventCallback = NULL;
  if (lbl_803E2D24 * (f32)(u32)sub->aggroRange < lbl_803E2D54) {
    *(s16 *)&sub->aggroRange = 0x6e;
  }
  ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2D14, 0);
  *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
  (*(void (**)(int, int, int))(*(int *)gPlayerInterface + 0x14))(obj, (int)sub, 0);
  sub->baddie.unk270 = 0;
  *(s8 *)&sub->baddie.unk25F = 0;
}

int fn_8015E5DC(short *obj, GroundBaddieState *p)
{
  extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
  extern int randomGetRange(int min, int max);
  extern f32 lbl_803E2DC8;
  extern f32 lbl_803E2DDC;
  extern f32 lbl_803E2DE0;
  int count;
  int i;
  GroundBaddieState *sub;
  int *objs;

  sub = ((GameObject *)obj)->extra;
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    ObjHits_EnableObject(obj);
  }
  ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
  (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->objectPairPriority = 10;
  (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->objectPairHitVolume = 1;
  ObjHits_RegisterActiveHitVolumeObject(obj);
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    objs = ObjList_GetObjects(&i, &count);
    for (; i < count; i++) {
      void *o = (void *)objs[i];
      if (o != (void *)obj && ((GameObject *)o)->anim.seqId == 774) {
        (*(void (**)(void *, int, int))(**(int **)&((GameObject *)o)->anim.dll + 0x24))(
            o, 129, 0);
      }
    }
    if (randomGetRange(0, 1) != 0) {
      if (*(char *)&p->baddie.moveJustStartedA != '\0') {
        ObjAnim_SetCurrentMove((int)obj, 6, lbl_803E2DC8, 0);
        *(s8 *)&p->baddie.moveDone = 0;
      }
    } else {
      if (*(char *)&p->baddie.moveJustStartedA != '\0') {
        ObjAnim_SetCurrentMove((int)obj, 7, lbl_803E2DC8, 0);
        *(s8 *)&p->baddie.moveDone = 0;
      }
    }
    *(s8 *)&p->baddie.unk34D = 1;
    p->baddie.moveSpeed = lbl_803E2DDC + (f32)(u32)sub->aggression / lbl_803E2DE0;
  }
  p->baddie.animSpeedA = lbl_803E2DC8;
  return 0;
}

int fn_8015DF20(int obj, GroundBaddieState *p)
{
  extern int *gPlayerInterface;
  extern void Obj_FreeObject(int *obj);
  extern f32 lbl_803E2DC8;
  GroundBaddieState *sub = ((GameObject *)obj)->extra;
  f32 *v;
  f32 z;

  if (*(char *)&p->baddie.moveJustStartedB != '\0') {
    v = *(f32 **)&sub->control;
    z = lbl_803E2DC8;
    v[0] = z;
    v[1] = z;
    (*(void (**)(int, u8 *, int))(*(int *)gPlayerInterface + 0x14))(obj, (u8 *)p, 6);
    *(int *)&p->baddie.targetObj = 0;
    *(s8 *)&p->baddie.unk25F = 0;
    *(s8 *)&p->baddie.unk349 = 0;
    ObjHits_DisableObject(obj);
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
  } else if (*(char *)&p->baddie.moveDone != '\0') {
    ObjMsg_SendToObjects(0, 3, obj, 0xe0000, obj);
    if (((GameObject *)obj)->anim.placementData == NULL) {
      Obj_FreeObject((int *)obj);
      return 0;
    }
    return 4;
  }
  return 0;
}

int fn_8015E0C8(int obj, GroundBaddieState *p)
{
  extern int Obj_GetPlayerObject(void);
  extern void Sfx_PlayFromObject(int obj, int sfx);
  extern int *gBaddieControlInterface;
  extern f32 lbl_803E2DC8;
  extern f32 lbl_803E2DCC;
  extern f32 lbl_803E2DD0;
  GroundBaddieState *sub;
  f32 spd;

  sub = ((GameObject *)obj)->extra;
  *(s8 *)&p->baddie.unk34D = 3;
  p->baddie.moveSpeed = lbl_803E2DCC;
  spd = lbl_803E2DC8;
  p->baddie.animSpeedA = spd;
  p->baddie.animSpeedB = spd;
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 1, spd, 0);
    *(s8 *)&p->baddie.moveDone = 0;
  }
  if ((p->baddie.unk356 & 1) == 0) {
    if (*(s16 *)(Obj_GetPlayerObject() + 0x46) != 0) {
      Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
    } else {
      Sfx_PlayFromObject(obj, SFXfox_treadwater322);
    }
    Sfx_PlayFromObject(obj, SFXdoor_unlocked);
    Sfx_PlayFromObject(obj, SFXfoxcom_find);
    p->baddie.unk356 |= 1;
  }
  if ((p->baddie.unk356 & 2) == 0 && ((GameObject *)obj)->anim.currentMoveProgress > lbl_803E2DD0) {
    Sfx_PlayFromObject(obj, SFXdoor_creak);
    p->baddie.unk356 |= 2;
    (*(void (**)(int, int, int, int))(*(int *)gBaddieControlInterface + 0x4c))(
        obj, sub->unk3F0, -1, 0);
  }
  return 0;
}

int fn_8015E798(int obj, GroundBaddieState *p)
{
  extern void GameBit_Set(int bit, int val);
  extern f32 lbl_803E2DC8;
  extern f32 lbl_803E2DD8;
  extern f32 lbl_803E2DE4;
  GroundBaddieState *sub;
  u8 *hit;

  sub = ((GameObject *)obj)->extra;
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 14, lbl_803E2DC8, 0);
    *(s8 *)&p->baddie.moveDone = 0;
  }
  if (((GameObject *)obj)->anim.currentMoveProgress > lbl_803E2DE4) {
    hit = *(u8 **)&sub->control;
    hit[8] |= 2;
  }
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    ObjHits_DisableObject(obj);
    p->baddie.moveSpeed = lbl_803E2DD8;
    p->baddie.animSpeedA = lbl_803E2DC8;
  }
  if (*(char *)&p->baddie.moveDone != '\0') {
    GameBit_Set(sub->gameBitB, 0);
    ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2DC8, 0);
    *(int *)&p->baddie.targetObj = 0;
    *(s8 *)&p->baddie.unk25F = 0;
    *(s8 *)&p->baddie.unk349 = 0;
    sub->targetState = 0;
    if ((hit[9] & 2) == 0) {
      *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    }
  }
  return 0;
}

int fn_8015E8BC(int obj, GroundBaddieState *p)
{
  extern void GameBit_Set(int bit, int val);
  extern f32 lbl_803E2DC8;
  extern f32 lbl_803E2DE8;
  extern f32 lbl_803E2DEC;
  extern f32 lbl_803E2DF0;
  GroundBaddieState *sub;
  u8 *hit;
  int flags;

  sub = ((GameObject *)obj)->extra;
  hit = *(u8 **)&sub->control;
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 11, lbl_803E2DC8, 0);
    *(s8 *)&p->baddie.moveDone = 0;
  }
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    *(s8 *)&p->baddie.unk25F = 1;
    GameBit_Set(sub->gameBitB, 1);
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
    ((GameObject *)obj)->anim.alpha = 0xff;
    *(s8 *)&p->baddie.unk34D = 1;
    p->baddie.moveSpeed =
        lbl_803E2DE8 + (f32)(u32)sub->aggression / lbl_803E2DEC;
    ObjHits_EnableObject(obj);
  } else {
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->objectPairPriority = 10;
    (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
  }
  if (*(char *)&p->baddie.moveDone != '\0') {
    sub->targetState = 1;
  }
  flags = p->baddie.eventFlags;
  if ((flags & 0x200) != 0) {
    p->baddie.eventFlags = flags & ~0x200;
    hit[8] |= 4;
  }
  if (((GameObject *)obj)->anim.currentMoveProgress < lbl_803E2DF0) {
    hit[8] |= 2;
  }
  return 0;
}

void fn_8015EA48(int obj, GroundBaddieState *p)
{
  extern u8 Obj_IsLoadingLocked(void);
  extern int Obj_AllocObjectSetup(int size, int id);
  extern u8 *Obj_SetupObject(int setup, int a, int b, int c, int d);
  extern f64 lbl_803E2DC0;
  extern f32 lbl_803E2DF4;
  extern f32 lbl_803E2DF8;
  extern f32 lbl_803E2DFC;
  f32 dur;
  f32 t;
  int setup;
  u8 *o;

  if (Obj_IsLoadingLocked() == 0) {
    setup = Obj_AllocObjectSetup(36, 778);
    ((ObjPlacement *)setup)->posX = ((GameObject *)obj)->anim.localPosX;
    ((ObjPlacement *)setup)->posY = lbl_803E2DF4 + ((GameObject *)obj)->anim.localPosY;
    ((ObjPlacement *)setup)->posZ = ((GameObject *)obj)->anim.localPosZ;
    *(s8 *)(setup + 4) = 1;
    *(s8 *)(setup + 5) = 1;
    *(u8 *)(setup + 6) = 0xff;
    *(u8 *)(setup + 7) = 0xff;
    o = Obj_SetupObject(setup, 5, -1, -1, 0);
    if (o != NULL) {
      t = p->baddie.targetDistance / (f32)(u32)p->aggroRange;
      dur = lbl_803E2DF8 * t;
      ((GameObject *)o)->anim.velocityX =
          (*(f32 *)(*(int *)&p->baddie.targetObj + 0xc) - ((GameObject *)obj)->anim.localPosX) / dur;
      ((GameObject *)o)->anim.velocityY =
          ((lbl_803E2DFC * t + *(f32 *)(*(int *)&p->baddie.targetObj + 0x10)) - ((GameObject *)obj)->anim.localPosY) / dur;
      ((GameObject *)o)->anim.velocityZ =
          (*(f32 *)(*(int *)&p->baddie.targetObj + 0x14) - ((GameObject *)obj)->anim.localPosZ) / dur;
      *(int *)&((GameObject *)o)->unkC4 = obj;
    }
  }
}

/*
 * --INFO--
 *
 * Function: FUN_8015e678
 * EN v1.0 Address: 0x8015E678
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x8015E84C
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
#pragma scheduling on
#pragma peephole on
FUN_8015e678(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int local_18;
  int local_14;
  
  iVar4 = *(int *)&((GameObject *)param_9)->extra;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    ObjHits_EnableObject(param_9);
  }
  iVar3 = -1;
  ObjHits_SetHitVolumeSlot(param_9,10,1,-1);
  (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->objectPairPriority = 10;
  (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->objectPairHitVolume = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    iVar1 = FUN_80017b00(&local_18,&local_14);
    for (; local_18 < local_14; local_18 = local_18 + 1) {
      uVar2 = *(uint *)(iVar1 + local_18 * 4);
      if ((uVar2 != param_9) && (*(short *)(uVar2 + 0x46) == 0x306)) {
        iVar3 = **(int **)(uVar2 + 0x68);
        (**(code **)(iVar3 + 0x24))(uVar2,0x81,0);
      }
    }
  }
  *(float *)(param_10 + 0x2a0) = lbl_803E3A70;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E3A60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,10,0,iVar3,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    iVar4 = *(int *)(iVar4 + 0x40c);
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & ~1;
    *(byte *)(iVar4 + 8) = *(byte *)(iVar4 + 8) | 1;
    FUN_80006824(param_9,SFXfoxcom_heel);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e88c
 * EN v1.0 Address: 0x8015E88C
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x8015E9CC
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015e88c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    ObjHits_EnableObject(param_9);
  }
  uVar1 = 0xffffffff;
  ObjHits_SetHitVolumeSlot(param_9,10,1,-1);
  (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->objectPairPriority = 10;
  (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->objectPairHitVolume = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  *(float *)(param_10 + 0x2a0) = lbl_803E3A70;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E3A60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,5,0,uVar1,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e9f4
 * EN v1.0 Address: 0x8015E9F4
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x8015EA88
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015e9f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int local_28;
  int local_24 [5];
  
  iVar5 = *(int *)&((GameObject *)param_9)->extra;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    ObjHits_EnableObject(param_9);
  }
  iVar4 = -1;
  ObjHits_SetHitVolumeSlot(param_9,10,1,-1);
  (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->objectPairPriority = 10;
  (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->objectPairHitVolume = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    iVar1 = FUN_80017b00(&local_28,local_24);
    for (; local_28 < local_24[0]; local_28 = local_28 + 1) {
      iVar2 = *(int *)(iVar1 + local_28 * 4);
      if ((iVar2 != param_9) && (*(short *)(iVar2 + 0x46) == 0x306)) {
        iVar4 = **(int **)(iVar2 + 0x68);
        (**(code **)(iVar4 + 0x24))(iVar2,0x81,0);
      }
    }
    uVar3 = randomGetRange(0,1);
    if (uVar3 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_800305f8((double)lbl_803E3A60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,7,0,iVar4,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_800305f8((double)lbl_803E3A60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,6,0,iVar4,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         lbl_803E3A74 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x406)) - DOUBLE_803e3a58) /
         lbl_803E3A78;
  }
  *(float *)(param_10 + 0x280) = lbl_803E3A60;
  return 0;
}

#pragma scheduling off
#pragma peephole off
void fn_8015EB6C(int obj, int p2, int p3)
{
  extern int *gBaddieControlInterface;
  extern void *Obj_GetPlayerObject(void);
  extern f32 sqrtf(f32);
  extern f32 timeDelta;
  extern f32 lbl_803E2DEC;
  extern f32 lbl_803E2E00;
  int sub = *(int *)(p2 + 0x40c);
  char *r;

  r = (char *)(**(int (**)(int, int, f32, int))((char *)(*gBaddieControlInterface) + 0x48))(
      obj, p3, (f32)(u32)*(u16 *)(p2 + 0x3fe), 0x8000);

  if (r != NULL && (*(u8 *)(p2 + 0x404) & 0x4) == 0) {
    int v = -1;
    (**(void (**)(int, int, int, int, int, int, int, int, int))((char *)(*gBaddieControlInterface) + 0x28))(
        obj, p3, p2 + 0x35c, (s32)*(s16 *)(p2 + 0x3f4), 0, 0, 0, 8, v);
    *(int *)(p3 + 0x2d0) = (int)r;
    *(u8 *)(p3 + 0x349) = 0;
    *(s16 *)(p2 + 0x402) = 1;
  } else {
    void *player = Obj_GetPlayerObject();
    f32 dist;
    struct {
      f32 x, y, z;
    } d;
    f32 *dp = &d.x;
    if (player != NULL) {
      d.x = *(f32 *)((int)player + 0x18) - ((GameObject *)obj)->anim.worldPosX;
      d.y = *(f32 *)((int)player + 0x1c) - ((GameObject *)obj)->anim.worldPosY;
      d.z = *(f32 *)((int)player + 0x20) - ((GameObject *)obj)->anim.worldPosZ;
      dist = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
    } else {
      dist = lbl_803E2DEC;
    }
    if (*(f32 *)(sub + 0) > *(f32 *)(sub + 4)) {
      if (dist < lbl_803E2E00) {
        Sfx_PlayFromObject(obj, SFXfoxcom_gogetit);
        *(f32 *)(sub + 4) += (f32)(s32)randomGetRange(50, 250);
      }
    }
    *(f32 *)(sub + 0) += timeDelta;
  }
}

/*
 * --INFO--
 *
 * Function: FUN_8015ec98
 * EN v1.0 Address: 0x8015EC98
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x8015EC44
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
#pragma scheduling on
#pragma peephole on
FUN_8015ec98(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int unaff_r29;
  int iVar1;
  
  iVar1 = *(int *)&((GameObject *)param_9)->extra;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E3A60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xe,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (lbl_803E3A7C < ((GameObject *)param_9)->anim.currentMoveProgress) {
    unaff_r29 = *(int *)(iVar1 + 0x40c);
    *(byte *)(unaff_r29 + 8) = *(byte *)(unaff_r29 + 8) | 2;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    ObjHits_DisableObject(param_9);
    *(float *)(param_10 + 0x2a0) = lbl_803E3A70;
    *(float *)(param_10 + 0x280) = lbl_803E3A60;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    FUN_80017698((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_800305f8((double)lbl_803E3A60,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    *(undefined2 *)(iVar1 + 0x402) = 0;
    if ((*(byte *)(unaff_r29 + 9) & 2) == 0) {
      *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode | 8;
    }
  }
  return 0;
}

#pragma scheduling off
#pragma peephole off
void fn_8015ED1C(int p1, int p2, int p3)
{
  extern int *gBaddieControlInterface;
  extern void *Obj_GetPlayerObject(void);
  extern f32 sqrtf(f32);
  extern u8 lbl_8031FEA8[];
  extern u8 lbl_8031FF20[];
  extern u8 lbl_803AC580[];
  void *player;
  char *t;
  int r;
  struct {
    f32 x, y, z;
  } d;
  f32 *dp = &d.x;

  player = Obj_GetPlayerObject();
  t = *(char **)(p3 + 0x2d0);
  if (t != NULL) {
    d.x = *(f32 *)(t + 0x18) - ((GameObject *)p1)->anim.worldPosX;
    d.y = *(f32 *)(t + 0x1c) - ((GameObject *)p1)->anim.worldPosY;
    d.z = *(f32 *)(t + 0x20) - ((GameObject *)p1)->anim.worldPosZ;
    *(f32 *)(p3 + 0x2c0) = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
  }

  if ((*(u8 *)(p2 + 0x404) & 0x20) == 0) {
    (**(void (**)(int, int, int, int, int, int, int))((char *)(*gBaddieControlInterface) + 0x3c))(
        p1, p3, p2 + 0x400, 2, 3, (s32)*(s16 *)(p2 + 0x3fa), (s32)*(s16 *)(p2 + 0x3fc));
  }

  (**(void (**)(int, int, int, int, int, int, int, int))((char *)(*gBaddieControlInterface) + 0x54))(
      p1, p3, p2 + 0x35c, (s32)*(s16 *)(p2 + 0x3f4), 0, 0, 0, 8);

  r = (int)(**(int (**)(int, int, int, int, u8 *, u8 *, int, u8 *))((char *)(*gBaddieControlInterface) + 0x50))(
      p1, p3, p2 + 0x35c, (s32)*(s16 *)(p2 + 0x3f4), lbl_8031FEA8, lbl_8031FF20, 1, lbl_803AC580);

  if (r != 0) {
    void *pc8 = ((GameObject *)player)->unkC8;
    (*(void (**)(void *))(**(int **)((char *)pc8 + 0x68) + 0x50))(pc8);
  }
}

/*
 * --INFO--
 *
 * Function: dll_CE_func0B
 * EN v1.0 Address: 0x8015EE98
 * EN v1.0 Size: 464b
 * EN v1.1 Address: 0x8015ED68
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_CE_func0B(int obj, int v)
{
  extern void Sfx_PlayFromObject(int obj, int sfx);
  extern int *gPlayerInterface;
  GroundBaddieState *sub = ((GameObject *)obj)->extra;
  GroundBaddieState *sub2 = (GroundBaddieState *)(int)sub;

  switch ((u8)v) {
  case 0x80:
    *(u8 *)(*(int *)&sub->control + 9) |= 2;
    Sfx_PlayFromObject(obj, SFXfoxcom_flame);
    (*(void (**)(int, int, int))(*(int *)gPlayerInterface + 0x14))(obj, (int)sub2, 1);
    sub2->baddie.unk270 = 4;
    *(s8 *)&sub2->baddie.moveJustStartedB = 1;
    break;
  case 0x81:
    sub->configFlags &= ~4;
    break;
  }
}

void dll_CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
  extern void objRenderFn_8003b8f4(f32);
  extern void fn_8003B5E0(int, int, int, int);
  extern f32 lbl_803E2DC8;
  extern f32 lbl_803E2E10;
  GroundBaddieState *sub = ((GameObject *)p1)->extra;
  f32 t;

  if (visible != 0 && ((GameObject *)p1)->unkF4 == 0 && sub->targetState != 0) {
    t = sub->unk3E8;
    if (t != lbl_803E2DC8) {
      fn_8003B5E0(200, 0, 0, (int)t);
    }
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5,
                                                                   lbl_803E2E10);
  }
}

void dll_CE_init(int obj, u8 *p, int flags)
{
  extern int randomGetRange(int min, int max);
  extern int *gBaddieControlInterface;
  extern int *gPlayerInterface;
  extern f64 lbl_803E2E08;
  extern f32 lbl_803E2DC8;
  extern f32 lbl_803E2E14;
  GroundBaddieState *sub;
  u8 mode;
  f32 *v;

  sub = ((GameObject *)obj)->extra;
  mode = 6;
  if (flags != 0) {
    mode |= 1;
  }
  if ((*(u8 *)(p + 0x2b) & 0x20) == 0) {
    mode |= 8;
  }
  (*(void (**)(int, u8 *, int, int, int, int, u8, f32))(*(int *)gBaddieControlInterface + 0x58))(
      obj, p, (int)sub, 7, 6, 0x102, mode, lbl_803E2E14);
  ((GameObject *)obj)->animEventCallback = NULL;
  v = *(f32 **)&sub->control;
  *v = (f32)(int)randomGetRange(10, 300);
  ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2DC8, 0);
  *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
  (*(void (**)(int, int, int))(*(int *)gPlayerInterface + 0x14))(obj, (int)sub, 0);
  sub->baddie.unk270 = 0;
  *(s8 *)&sub->baddie.unk25F = 0;
  ObjHits_DisableObject(obj);
}

void dll_CE_update(int obj, int p2, int p3)
{
  extern void Sfx_PlayFromObject(int obj, int sfx);
  extern void fn_8015ED1C(int p1, int p2, int p3);
  extern void fn_8015EB6C(int obj, int p2, int p3);
  extern void fn_8015EA48(int obj, u8 *p);
  extern int *gBaddieControlInterface;
  extern MapEventInterface **gMapEventInterface;
  extern ObjectTriggerInterface **gObjectTriggerInterface;
  extern int *gSHthorntailAnimationInterface;
  extern int *gPlayerInterface;
  extern void *lbl_803AC5B0[];
  extern void *lbl_803AC598[];
  extern f32 timeDelta;
  extern f32 lbl_803E2DC8;
  extern f32 lbl_803E2E14;
  extern f32 lbl_803E2E18;
  GroundBaddieState *sub;
  int setup;
  u8 *hit;
  int n;
  int buf[4];

  sub = ((GameObject *)obj)->extra;
  setup = *(int *)&((GameObject *)obj)->anim.placementData;
  if (((GameObject *)obj)->unkF4 != 0) {
    if ((sub->baddie.unk270 != 3 || (sub->configFlags & 1) != 0) &&
        (*gMapEventInterface)->isTimedEventActive(((ObjPlacement *)setup)->mapId) != 0) {
      (*(void (**)(int, int, int, int, int, int, int, f32))(*(int *)gBaddieControlInterface +
                                                            0x58))(
          obj, setup, (int)sub, 7, 6, 0x102, 0x26, lbl_803E2E14);
      sub->targetState = 0;
      Sfx_PlayFromObject(obj, SFXfoxcom_find);
      ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2DC8, 0x10);
      *(s8 *)&sub->baddie.moveDone = 0;
      ((GameObject *)obj)->anim.alpha = 0xff;
      *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    }
  } else if (((GameObject *)obj)->unkF8 == 0) {
    ((GameObject *)obj)->anim.localPosX = ((ObjPlacement *)setup)->posX;
    ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)setup)->posY;
    ((GameObject *)obj)->anim.localPosZ = ((ObjPlacement *)setup)->posZ;
    (*gObjectTriggerInterface)->runSequence(*(s8 *)(setup + 0x2e), (void *)obj, -1);
    ((GameObject *)obj)->unkF8 = 1;
  } else {
    if ((*(int (**)(int, int, int))(*(int *)gBaddieControlInterface + 0x30))(obj, (int)sub, 0) == 0) {
      sub->targetState = 0;
    } else if ((sub->configFlags & 0x10) != 0 &&
               (*(int (**)(int *))(*(int *)gSHthorntailAnimationInterface + 0x24))(buf) == 0) {
      sub->targetState = 0;
    } else {
      fn_8015ED1C(obj, (int)sub, (int)sub);
      if (sub->targetState == 0) {
        fn_8015EB6C(obj, (int)sub, (int)sub);
      } else {
        hit = *(u8 **)&sub->control;
        if ((hit[8] & 1) != 0) {
          fn_8015EA48(obj, (u8 *)sub);
        }
        if ((hit[8] & 2) != 0) {
          (*gPartfxInterface)->spawnObject((void *)obj, 0x345, NULL, 1, -1, NULL);
        }
        if ((hit[8] & 4) != 0) {
          n = 0;
          do {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x343, NULL, 1, -1, NULL);
            n++;
          } while (n < 10);
        }
        hit[8] = 0;
        (*(void (**)(int, int, f32, int))(*(int *)gBaddieControlInterface + 0x2c))(obj, (int)sub, lbl_803E2DC8, -1);
        (*(void (**)(int, int, f32, int))(*(int *)gPlayerInterface + 0x30))(obj, (int)sub, timeDelta,
                                                                            4);
        sub->savedObjC0 = *(int *)&((GameObject *)obj)->unkC0;
        *(int *)&((GameObject *)obj)->unkC0 = 0;
        (*(void (**)(int, int, f32, f32, void *, void *))(*(int *)gPlayerInterface + 8))(obj, (int)sub, timeDelta, timeDelta, lbl_803AC5B0, lbl_803AC598);
        *(int *)&((GameObject *)obj)->unkC0 = sub->savedObjC0;
      }
      ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)setup)->posY - lbl_803E2E18;
    }
  }
}

/*
 * --INFO--
 *
 * Function: FUN_8015f068
 * EN v1.0 Address: 0x8015F068
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x8015EEF4
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_8015FBEC(int obj)
{
  extern void Camera_EnableViewYOffset(void);
  extern void CameraShake_SetAllMagnitudes(f32);
  extern f32 lbl_803E2E50;
  s16 mode = ((GameObject *)obj)->anim.seqId;
  int i;

  if (mode == 715) {
    for (i = 0; i < 25; i++) {
      (*gPartfxInterface)->spawnObject((void *)obj, 834, NULL, 1, -1, NULL);
    }
  } else if (mode == 100 || mode == 778) {
    for (i = 0; i < 25; i++) {
      (*gPartfxInterface)->spawnObject((void *)obj, 836, NULL, 1, -1, NULL);
    }
  }

  Sfx_PlayFromObject(obj, SFXkr_impact3);
  Camera_EnableViewYOffset();
  CameraShake_SetAllMagnitudes(lbl_803E2E50);
}
#pragma dont_inline reset

static inline u8 scarab_isObjectInList(void *o)
{
  extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
  int i;
  int count;
  int *objs = ObjList_GetObjects(&i, &count);
  while (i < count) {
    if (o == (void *)objs[i++]) {
      return 1;
    }
  }
  return 0;
}

void fn_8015FCCC(int obj)
{
  extern void Camera_EnableViewYOffset(void);
  extern void CameraShake_SetAllMagnitudes(f32);
  extern f32 lbl_803E2E50;
  s16 type;
  int n;

  Camera_EnableViewYOffset();
  CameraShake_SetAllMagnitudes(lbl_803E2E50);
  Sfx_PlayFromObject(obj, SFXkr_impact3);
  type = ((GameObject *)obj)->anim.seqId;
  if (type == 0x2cb) {
    if (((GameObject *)obj)->unkC4 != NULL) {
      if (scarab_isObjectInList(((GameObject *)obj)->unkC4)) {
        (*(void (**)(void *, int))(**(int **)(*(int *)&((GameObject *)obj)->unkC4 + 0x68) + 0x20))(
            ((GameObject *)obj)->unkC4, 0x80);
      }
    }
    for (n = 0; n < 25; n++) {
      (*gPartfxInterface)->spawnObject((void *)obj, 832, NULL, 1, -1, NULL);
    }
  } else if (type == 100) {
    if (((GameObject *)obj)->unkC4 != NULL) {
      if (scarab_isObjectInList(((GameObject *)obj)->unkC4)) {
        (*(void (**)(void *, int))(**(int **)(*(int *)&((GameObject *)obj)->unkC4 + 0x68) + 0x24))(
            ((GameObject *)obj)->unkC4, 0x80);
      }
    }
    for (n = 0; n < 25; n++) {
      (*gPartfxInterface)->spawnObject((void *)obj, 835, NULL, 1, -1, NULL);
    }
  } else if (type == 0x30a) {
    if (((GameObject *)obj)->unkC4 != NULL) {
      if (scarab_isObjectInList(((GameObject *)obj)->unkC4)) {
        (*(void (**)(void *, int, int))(**(int **)(*(int *)&((GameObject *)obj)->unkC4 + 0x68) + 0x24))(
            ((GameObject *)obj)->unkC4, 0x80, 0);
      }
    }
    for (n = 0; n < 25; n++) {
      (*gPartfxInterface)->spawnObject((void *)obj, 835, NULL, 1, -1, NULL);
    }
  }
}

/*
 * --INFO--
 *
 * Function: FUN_8015fb0c
 * EN v1.0 Address: 0x8015FB0C
 * EN v1.0 Size: 1212b
 * EN v1.1 Address: 0x8015FBEC
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


extern int objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int getTrickyObject(void);
extern int Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int *obj);
extern f32 timeDelta;
extern f32 lbl_803E2E54;
extern f32 lbl_803E2E58;

/*
 * --INFO--
 *
 * Function: iceball_update
 * EN v1.0 Address: 0x8015FFC8
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x8015FF9C
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void iceball_update(undefined2 *param_1,int param_2)
{
  int p;

  p = (int)param_1;
  *(int *)(p + 0xf4) = (s32)((f32)(s32)*(int *)(p + 0xf4) - timeDelta);
  if (*(int *)(p + 0xf4) < 0) {
    Obj_FreeObject((int *)p);
    return;
  }
  if (((GameObject *)p)->anim.alpha == 0) {
    return;
  }
  *(float *)(p + 0x28) = *(float *)(p + 0x28) - lbl_803E2E54 * timeDelta;
  *(float *)(p + 0x28) = *(float *)(p + 0x28) * lbl_803E2E58;
  *(s16 *)(p + 0) += 910;
  *(s16 *)(p + 4) += 910;
  *(s16 *)(p + 2) += 910;
  objMove(p, *(float *)(p + 0x24) * timeDelta, *(float *)(p + 0x28) * timeDelta,
          *(float *)(p + 0x2c) * timeDelta);
  ObjHits_SetHitVolumeSlot(p, 10, 1, 0);
  ObjHitbox_SetSphereRadius(p, 5);
  ObjHits_EnableObject(p);
  if ((*(ObjHitsPriorityState **)(p + 0x54))->lastHitObject != 0 &&
      ((*(ObjHitsPriorityState **)(p + 0x54))->lastHitObject == Obj_GetPlayerObject() ||
       (*(ObjHitsPriorityState **)(p + 0x54))->lastHitObject == getTrickyObject())) {
    fn_8015FCCC(p);
    ((GameObject *)p)->anim.alpha = 0;
    *(int *)(p + 0xf4) = 120;
    (*(ObjHitsPriorityState **)(p + 0x54))->flags &= ~1;
  }
  else if ((*(ObjHitsPriorityState **)(p + 0x54))->contactFlags != 0) {
    fn_8015FBEC(p);
    ((GameObject *)p)->anim.alpha = 0;
    *(int *)(p + 0xf4) = 120;
    (*(ObjHitsPriorityState **)(p + 0x54))->flags &= ~1;
  }
}

int fn_801601C4(int obj, GroundBaddieState *p)
{
  extern int *gPlayerInterface;
  extern void *memcpy(void *dst, const void *src, int n);
  extern void voxmaps_updateRoutePath(char *a, char *b);
  extern f32 lbl_803E2E68;
  extern f32 lbl_803E2E6C;
  extern f32 lbl_803E2E70;
  extern f32 lbl_803E2E74;
  extern f32 lbl_803E2E78;
  GroundBaddieState *sub;
  char *wp;
  f32 z;

  sub = ((GameObject *)obj)->extra;
  if (*(void **)&p->baddie.targetObj != NULL) {
    (*(void (**)(int, u8 *, int))(*(int *)gPlayerInterface + 0x14))(obj, (u8 *)p, 1);
    wp = (char *)sub->route35C;
    z = lbl_803E2E68;
    p->baddie.unk290 = z;
    p->baddie.unk28C = z;
    memcpy(wp, (void *)&((GameObject *)obj)->anim.localPosX, 12);
    memcpy((void *)(sub->route35C + 0xc), (void *)(*(int *)&p->baddie.targetObj + 0xc), 12);
    voxmaps_updateRoutePath(wp, (char *)(sub->route35C + 0x28));
    if (p->baddie.targetDistance < lbl_803E2E6C && sub->unk405 == 2) {
      return 5;
    }
    if (*(u8 *)(wp + 0x25) == 0) {
      (*(void (**)(int, u8 *, f32, f32, f32, f32, f32))(*(int *)gPlayerInterface + 0x1c))(
          obj, (u8 *)p, *(f32 *)(wp + 0x18), *(f32 *)(wp + 0x20), lbl_803E2E68, *(f32 *)&lbl_803E2E68,
          lbl_803E2E70);
    } else {
      (*(void (**)(int, u8 *, f32, f32, f32, f32, f32))(*(int *)gPlayerInterface + 0x1c))(
          obj, (u8 *)p, *(f32 *)(wp + 0x18), *(f32 *)(wp + 0x20), lbl_803E2E74, lbl_803E2E78,
          lbl_803E2E70);
    }
  } else {
    (*(void (**)(int, u8 *, int))(*(int *)gPlayerInterface + 0x14))(obj, (u8 *)p, 0);
    *(s8 *)&p->baddie.moveDone = 0;
  }
  return 0;
}

int fn_8016043C(int obj, GroundBaddieState *p)
{
  extern int *gPlayerInterface;
  extern int Obj_GetPlayerObject(void);
  extern void ObjMsg_SendToObject(int target, int msg, int from, int a);
  extern void Obj_FreeObject(int *obj);

  if (*(char *)&p->baddie.moveJustStartedB != '\0') {
    (*(void (**)(int, u8 *, int))(*(int *)gPlayerInterface + 0x14))(obj, (u8 *)p, 3);
    *(int *)&p->baddie.targetObj = 0;
    *(s8 *)&p->baddie.unk25F = 0;
    *(s8 *)&p->baddie.unk349 = 0;
    (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~1;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
  } else {
    ObjMsg_SendToObject(Obj_GetPlayerObject(), 0xe0000, obj, 0);
    if (((GameObject *)obj)->anim.placementData == NULL) {
      Obj_FreeObject((int *)obj);
      return 0;
    }
    return 4;
  }
  return 0;
}

#pragma dont_inline on
void fn_801606F0(int obj, void *p2, int sub, GroundBaddieState *p)
{
  extern int *gBaddieControlInterface;
  extern ObjectTriggerInterface **gObjectTriggerInterface;
  extern int *gPlayerInterface;
  extern void *lbl_803AC5D0[];
  extern void *lbl_803AC5E8[];
  extern f32 timeDelta;
  extern f64 lbl_803E2EA0;
  extern f32 lbl_803E2E9C;
  int setup;

  setup = *(int *)&((GameObject *)obj)->anim.placementData;
  *(s8 *)&p->baddie.moveDone = 1;
  if ((*(int (**)(int, u8 *, f32, int))(*(int *)gBaddieControlInterface + 0x44))(
          obj, (u8 *)p, (f32)(u32)*(u16 *)(sub + 0x3fe), 1) != 0) {
    *(int *)&p->baddie.targetObj = *(int *)(sub + 0x3e0);
    *(s8 *)&p->baddie.unk349 = 0;
    if (*(char *)(setup + 0x2e) != -1) {
      if (p2 != NULL) {
        (*gObjectTriggerInterface)->yield((ObjSeqState *)p2, *(s16 *)(setup + 0x24));
      }
      *(s8 *)(sub + 0x405) = 1;
    } else {
      *(int *)&p->baddie.targetObj = 0;
    }
  }
  (*(void (**)(int, u8 *, f32, int))(*(int *)gBaddieControlInterface + 0x2c))(obj, (u8 *)p,
                                                                              lbl_803E2E9C, 1);
  *(int *)(sub + 0x3e0) = *(int *)&((GameObject *)obj)->unkC0;
  *(int *)&((GameObject *)obj)->unkC0 = 0;
  (*(void (**)(int, u8 *, f32, f32, void *, void *))(*(int *)gPlayerInterface + 8))(
      obj, (u8 *)p, timeDelta, timeDelta, lbl_803AC5E8, lbl_803AC5D0);
  *(int *)&((GameObject *)obj)->unkC0 = *(int *)(sub + 0x3e0);
}
#pragma dont_inline reset

#pragma dont_inline on
void fn_8016083C(int *obj, GroundBaddieState *sub, GroundBaddieState *p)
{
  extern void characterDoEyeAnims(int *obj, u8 *a);
  extern f32 sqrtf(f32);
  extern int Obj_GetPlayerObject(void);
  extern int *gBaddieControlInterface;
  extern u8 lbl_80320008[];
  extern u8 lbl_80320080[];
  char *o;
  int t;
  struct {
    f32 x, y, z;
  } d;
  f32 *dp = &d.x;

  if (((GameObject *)obj)->unkC8 != NULL) {
    *(int *)(*(int *)&((GameObject *)obj)->unkC8 + 0x30) = *(int *)&((GameObject *)obj)->anim.parent;
  }
  o = *(char **)&p->baddie.targetObj;
  if (o != NULL) {
    d.x = ((GameObject *)o)->anim.worldPosX - ((GameObject *)obj)->anim.worldPosX;
    d.y = ((GameObject *)o)->anim.worldPosY - ((GameObject *)obj)->anim.worldPosY;
    d.z = ((GameObject *)o)->anim.worldPosZ - ((GameObject *)obj)->anim.worldPosZ;
    p->baddie.targetDistance = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
  }
  characterDoEyeAnims(obj, sub->route35C + 0x50);
  if ((sub->configFlags & 1) == 0) {
    (*(void (**)(int *, u8 *, u8 *, int, int, int, int))(*(int *)gBaddieControlInterface + 0x3c))(
        obj, (u8 *)p, (u8 *)&sub->flags400, 2, 3, sub->unk3FC, sub->unk3FA);
  }
  (*(void (**)(int *, u8 *, u8 *, int, u8 *, int, int, int))(*(int *)gBaddieControlInterface +
                                                             0x54))(
      obj, (u8 *)p, sub->route35C, sub->gameBitB, &sub->unk405, 0, 0, 0);
  t = (*(int (**)(int *, u8 *, u8 *, int, u8 *, u8 *, int, int))(*(int *)gBaddieControlInterface +
                                                                 0x50))(
      obj, (u8 *)p, sub->route35C, sub->gameBitB, lbl_80320008, lbl_80320080, 1, 0);
  if (t >= 4) {
    *(s8 *)&sub->unk405 = 2;
    *(int *)&p->baddie.targetObj = Obj_GetPlayerObject();
  }
}
#pragma dont_inline reset

int dll_CB_seqFn(short *obj, int p2, u8 *e)
{
  extern u32 GameBit_Get(int bit);
  extern int Curve_AdvanceAlongPath(int *p, f32 t);
  extern int getAngle(f32 a, f32 b);
  extern int *gBaddieControlInterface;
  extern ObjectTriggerInterface **gObjectTriggerInterface;
  extern int *gPlayerInterface;
  extern void *lbl_803AC5D0[];
  extern void *lbl_803AC5E8[];
  extern f32 lbl_803E2E8C;
  extern f32 lbl_803E2E98;
  extern f32 lbl_803E2E9C;
  int setup;
  int *path;
  int sub;

  setup = *(int *)&((GameObject *)obj)->anim.placementData;
  sub = *(int *)&((GameObject *)obj)->extra;
  if (((GameObject *)obj)->unkF4 != 0) {
    return 0;
  }
  if (((GameObject *)obj)->unkB4 != -1) {
    if ((*(int (**)(short *, int, int))(*(int *)gBaddieControlInterface + 0x30))(obj, sub, 1) ==
        0) {
      return 1;
    }
    fn_8016083C((int *)obj, (GroundBaddieState *)sub, (GroundBaddieState *)sub);
    if (((DllCBState *)sub)->unk3F6 != -1 && GameBit_Get(((DllCBState *)sub)->unk3F6) != 0) {
      (*gObjectTriggerInterface)->yield((ObjSeqState *)e, ((DllCBPlacement *)setup)->unk2C);
      ((DllCBState *)sub)->unk3F6 = -1;
    }
    switch (*(u8 *)&((DllCBState *)sub)->unk405) {
    case 2:
      *(s16 *)(e + 0x6e) = 0;
      fn_801606F0((int)obj, e, sub, (GroundBaddieState *)sub);
      if (*(u8 *)&((DllCBState *)sub)->unk405 == 1) {
        ((GroundBaddieState *)sub)->baddie.unk270 = 5;
        (*(void (**)(short *, int, f32, f32, void *, void *))(*(int *)gPlayerInterface + 8))(
            obj, sub, lbl_803E2E8C, *(f32 *)&lbl_803E2E8C, lbl_803AC5E8, lbl_803AC5D0);
        *(s8 *)(e + 0x56) = 0;
      }
      break;
    case 1:
      if ((*(int (**)(short *, u8 *, int, void *, void *, int))(*(int *)gBaddieControlInterface +
                                                                0x34))(
              obj, e, sub, lbl_803AC5E8, lbl_803AC5D0, 0) != 0) {
        (*(void (**)(short *, int, f32, int))(*(int *)gBaddieControlInterface + 0x2c))(obj, sub, lbl_803E2E9C, 1);
      }
      break;
    case 0:
    default:
      *(s16 *)(e + 0x6e) = -1;
      *(s16 *)(e + 0x6e) &= ~0x40;
      path = *(int **)&((DllCBState *)sub)->unk3DC;
      if ((((DllCBState *)sub)->flags400 & 8) != 0) {
        if ((Curve_AdvanceAlongPath(path, ((GroundBaddieState *)sub)->baddie.animSpeedA) != 0 || path[4] != 0) &&
            (*gRomCurveInterface)->goNextPoint(path) != 0) {
          ((DllCBState *)sub)->flags400 &= ~8;
        }
        ((GroundBaddieState *)sub)->baddie.animSpeedA = lbl_803E2E98;
        ((GameObject *)obj)->anim.rotX = getAngle(*(f32 *)((char *)path + 0x74), *(f32 *)((char *)path + 0x7c)) + 0x8000;
        ((GameObject *)obj)->anim.rotY = getAngle(*(f32 *)((char *)path + 0x7c), *(f32 *)((char *)path + 0x78)) + 0x4000;
        ((GameObject *)obj)->anim.rotZ = getAngle(*(f32 *)((char *)path + 0x78), *(f32 *)((char *)path + 0x74)) + 0x4000;
        ((GameObject *)obj)->anim.localPosX = *(f32 *)((char *)path + 0x68);
        ((GameObject *)obj)->anim.localPosY = *(f32 *)((char *)path + 0x6c);
        ((GameObject *)obj)->anim.localPosZ = *(f32 *)((char *)path + 0x70);
      }
      break;
    }
  }
  if (((GameObject *)obj)->unkB4 == -1) {
    ((DllCBState *)sub)->flags400 |= 2;
    return 0;
  }
  return *(u8 *)&((DllCBState *)sub)->unk405 != 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801600a8
 * EN v1.0 Address: 0x801600A8
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x80160098
 * EN v1.1 Size: 224b
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
 * Function: FUN_8016043c
 * EN v1.0 Address: 0x8016043C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80160440
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016043c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_80160798
 * EN v1.0 Address: 0x80160798
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x80160670
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80160798(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)
{
  float fVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)&((GameObject *)param_9)->extra;
  if (*(int *)(param_10 + 0x2d0) == 0) {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,0);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,1);
    fVar1 = lbl_803E3B00;
    *(float *)(param_10 + 0x290) = lbl_803E3B00;
    *(float *)(param_10 + 0x28c) = fVar1;
    FUN_80003494(iVar2 + 0x35c,param_9 + 0xc,0xc);
    uVar3 = FUN_80003494(iVar2 + 0x368,*(int *)(param_10 + 0x2d0) + 0xc,0xc);
    FUN_80006a54(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if ((*(float *)(param_10 + 0x2c0) < lbl_803E3B04) && (*(char *)(iVar2 + 0x405) == '\x02')) {
      return 5;
    }
    if (*(char *)(iVar2 + 0x381) == '\0') {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar2 + 0x374),(double)*(float *)(iVar2 + 0x37c),
                 (double)lbl_803E3B00,(double)lbl_803E3B00,(double)lbl_803E3B08,param_9,
                 param_10);
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar2 + 0x374),(double)*(float *)(iVar2 + 0x37c),
                 (double)lbl_803E3B0C,(double)lbl_803E3B10,(double)lbl_803E3B08,param_9,
                 param_10);
    }
  }
  return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_80160aa4
 * EN v1.0 Address: 0x80160AA4
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x801608E8
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80160aa4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  undefined4 uVar2;
  
  if (*(char *)(param_10 + 0x27b) == '\0') {
    iVar1 = FUN_80017a98();
    ObjMsg_SendToObject(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0xe0000,
                 param_9,0,param_13,param_14,param_15,param_16);
    if (*(int *)&((GameObject *)param_9)->anim.placementData == 0) {
      FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      uVar2 = 0;
    }
    else {
      uVar2 = 4;
    }
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,3);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->flags &= ~1;
    *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode | 8;
    uVar2 = 0;
  }
  return uVar2;
}


/*
 * --INFO--
 *
 * Function: FUN_80160cd0
 * EN v1.0 Address: 0x80160CD0
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80160A80
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80160cd0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E3B00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x25f) = 1;
  *(undefined2 *)(param_9 + 4) = *(undefined2 *)(param_10 + 0x19e);
  *(undefined2 *)(param_9 + 2) = *(undefined2 *)(param_10 + 0x19c);
  (**(code **)(*DAT_803dd738 + 0x10))
            ((double)lbl_803E3B24,(double)lbl_803E3B28,param_9,param_10,uVar1);
  *(float *)(param_10 + 0x2a0) = lbl_803E3B2C * *(float *)(param_10 + 0x280);
  return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_80161130
 * EN v1.0 Address: 0x80161130
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80161180
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80161130(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined4 uVar1;
  undefined8 uVar2;
  
  uVar1 = *(undefined4 *)&((GameObject *)param_9)->extra;
  uVar2 = ObjGroup_RemoveObject(param_9,3);
  if (*(int *)&((GameObject *)param_9)->unkC8 != 0) {
    FUN_80017ac8(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)&((GameObject *)param_9)->unkC8);
    *(undefined4 *)&((GameObject *)param_9)->unkC8 = 0;
  }
  (**(code **)(*DAT_803dd738 + 0x40))(param_9,uVar1,1);
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_801615d4
 * EN v1.0 Address: 0x801615D4
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x80161638
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801615d4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10)
{
  undefined4 uVar1;
  
  if (*(char *)(param_10 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,8);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    param_1 = ObjHits_DisableObject(param_9);
    *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode | 8;
  }
  if (((GameObject *)param_9)->anim.alpha == 0) {
    if (*(int *)&((GameObject *)param_9)->anim.placementData == 0) {
      FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      uVar1 = 0;
    }
    else {
      uVar1 = 6;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}


/*
 * --INFO--
 *
 * Function: FUN_80161c08
 * EN v1.0 Address: 0x80161C08
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80161B58
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80161c08(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)&((GameObject *)param_9)->extra;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E3B50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = lbl_803E3B80;
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    FUN_80006824(param_9,SFXdoor_creak);
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    (**(code **)(*DAT_803dd738 + 0x4c))(param_9,(int)*(short *)(iVar1 + 0x3f0),0xffffffff,1);
  }
  return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_80161ea0
 * EN v1.0 Address: 0x80161EA0
 * EN v1.0 Size: 888b
 * EN v1.1 Address: 0x80161D2C
 * EN v1.1 Size: 632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80161ea0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  double dVar5;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34 [2];
  uint uStack_2c;
  
  iVar4 = *(int *)(*(int *)&((GameObject *)param_9)->extra + 0x40c);
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)param_9)->anim.hitReactState)->hitVolumePriority = 9;
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)param_9)->anim.hitReactState)->hitVolumeId = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  uVar1 = randomGetRange(0,100);
  if ((int)uVar1 < 0x32) {
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_800305f8((double)lbl_803E3B50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
  }
  else if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E3B50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,4,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = lbl_803E3B88;
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
  uStack_2c = *(char *)(iVar4 + 0x45) * -2 + 1U ^ 0x80000000;
  local_34[1] = 176.0;
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x28))
            ((double)(*(float *)(param_10 + 0x280) *
                     (f32)(s32)uStack_2c),
             *(int *)(iVar4 + 0x38),iVar4 + 0x48);
  if (lbl_803E3B8C <= *(float *)(iVar4 + 0x48)) {
    if (lbl_803E3B90 < *(float *)(iVar4 + 0x48)) {
      *(float *)(iVar4 + 0x48) = lbl_803E3B90;
    }
  }
  else {
    *(float *)(iVar4 + 0x48) = lbl_803E3B8C;
  }
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar4 + 0x48) - lbl_803E3B94),*(int *)(iVar4 + 0x38),&local_48,
             &local_44,&local_40);
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x24))
            ((double)(lbl_803E3B94 + *(float *)(iVar4 + 0x48)),*(int *)(iVar4 + 0x38),&local_3c,
             &local_38,local_34);
  local_48 = local_48 - local_3c;
  local_44 = local_44 - local_38;
  local_40 = local_40 - local_34[0];
  dVar5 = FUN_80293900((double)(local_48 * local_48 + local_40 * local_40));
  local_48 = (float)dVar5;
  iVar2 = FUN_80017730();
  ((GameObject *)param_9)->anim.rotY = (short)iVar2 * ((short)((int)*(char *)(iVar4 + 0x45) << 1) + -1);
  if (*(char *)(param_10 + 0x346) == '\0') {
    uVar3 = 0;
  }
  else {
    uVar3 = 5;
  }
  return uVar3;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_CA_release_nop(void) {}
void dll_CE_hitDetect_nop(void) {}
void dll_CE_release_nop(void) {}
void chukchuk_free(void) {}
void chukchuk_hitDetect(void) {}
void chukchuk_release(void) {}
void chukchuk_initialise(void) {}

extern uint GameBit_Get(int eventId);

/*
 * Per-object extra state for the ChukChuk ice-spitter
 * (chukchuk_getExtraSize == 0x18).
 */
typedef struct ChukChukState {
    f32 glowPhase; /* texture glow ramp index; 10 primes an attack, resets to rand(16,245) */
    f32 steamTimer; /* counts down after destruction, scales the steam particle */
    s16 unk08; /* from params+0x22 */
    s16 gameBit; /* set on destruction; already-set disables on load */
    u16 triggerDistance; /* params[0x29] << 3 */
    u16 arcHalfAngle; /* (s8)params[0x28] * 182 -- facing wedge for the spit attack */
    u16 prevDistance; /* player planar distance last frame */
    u8 flags; /* 1 primed, 2 dead/disabled, 4 forced attack */
    u8 hitsLeft;
    u8 attackChance; /* percent, vs rand(0,99) */
    u8 aimHeightY; /* added to player Y when aiming the iceball */
    u8 pad16[2];
} ChukChukState;

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

#pragma scheduling off
#pragma peephole off
void chukchuk_init(u8* obj, u8* params) {
    ChukChukState* sub = ((GameObject *)obj)->extra;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x8);
    sub->gameBit = *(s16*)(params + 0x18);
    if (sub->gameBit != -1 && GameBit_Get(sub->gameBit) != 0) {
        ObjHits_DisableObject(obj);
        ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        sub->flags = (u8)(sub->flags | 0x2);
    } else {
        sub->triggerDistance = (u16)(params[0x29] << 3);
        sub->unk08 = *(s16*)(params + 0x22);
        sub->hitsLeft = params[0x32];
        sub->arcHalfAngle = (u16)((s8)params[0x28] * 0xb6);
        sub->attackChance = params[0x2f];
        sub->aimHeightY = params[0x27];
        *(s16*)obj = (s16)((s8)params[0x2a] << 8);
    }
}
#pragma scheduling on
#pragma peephole on
void iceball_hitDetect(void) {}
void iceball_release(void) {}
void iceball_initialise(void) {}
void dll_CB_func0B_nop(void) {}
void dll_CB_release_nop(void) {}

extern f32 lbl_803E2EA8;

#pragma scheduling off
#pragma peephole off
void dll_CB_init(int *obj, u8 *params, int extra) {
    extern int *gBaddieControlInterface;
    extern int *gPlayerInterface;
    GroundBaddieState *sub;
    u8 flags;

    sub = ((GameObject *)obj)->extra;
    flags = 0x16;
    if (extra != 0) flags |= 1;
    if ((params[0x2b] & 1) == 0) flags |= 8;
    ((GameObject *)obj)->anim.rotY = (s16)((s8)params[0x28] << 8);
    ((GameObject *)obj)->anim.rotZ = (s16)((s8)params[0x27] << 8);
    ((void(*)(int*, u8*, u8*, int, int, int, u8, f32))((void**)*(int*)gBaddieControlInterface)[22])(obj, params, (u8 *)sub, 4, 6, 0x82, flags, lbl_803E2EA8);
    ((GameObject *)obj)->animEventCallback = (void *)dll_CB_seqFn;
    ((void(*)(int*, u8*, int))((void**)*(int*)gPlayerInterface)[5])(obj, (u8 *)sub, 0);
    sub->baddie.unk270 = 0;
    if (sub->aggroRange < 0x32) {
        sub->aggroRange = 0x32;
    }
}


extern int Curve_AdvanceAlongPath(int *p, f32 t);
extern int getAngle(f32 a, f32 b);
extern f32 lbl_803E2E98;

void dll_CB_update(int *obj) {
    extern int *gBaddieControlInterface;
    int *path;
    GroundBaddieState *sub;
    u8 *def;

    sub = ((GameObject *)obj)->extra;
    def = *(u8**)&((GameObject *)obj)->anim.placementData;
    if (((GameObject *)obj)->unkF4 != 0) return;
    if (((GameObject *)obj)->unkF8 == 0) {
        ((GameObject *)obj)->anim.localPosX = ((DllCBPlacement *)def)->unk8;
        ((GameObject *)obj)->anim.localPosY = ((DllCBPlacement *)def)->unkC;
        ((GameObject *)obj)->anim.localPosZ = ((DllCBPlacement *)def)->unk10;
        ((GameObject *)obj)->unkF8 = 1;
        return;
    }
    if ((sub->flags400 & 2) != 0) {
        ((void(*)(int*, u8*, u8*, s16, u8*, int, int, int, int))((int**)*(int**)gBaddieControlInterface)[10])(obj, (u8 *)sub, sub->route35C, sub->gameBitB, &sub->unk405, 0, 0, 0, 1);
        sub->flags400 = (u16)(sub->flags400 & ~2);
    }
    if (((int(*)(int*, u8*, int))((int**)*(int**)gBaddieControlInterface)[12])(obj, (u8 *)sub, 1) == 0) return;
    fn_8016083C(obj, sub, sub);
    path = *(int **)&sub->path;
    if ((sub->flags400 & 8) == 0) return;
    if (Curve_AdvanceAlongPath(path, sub->baddie.animSpeedA) != 0 || path[4] != 0) {
        if ((*gRomCurveInterface)->goNextPoint(path) != 0) {
            sub->flags400 = (u16)(sub->flags400 & ~8);
        }
    }
    sub->baddie.animSpeedA = lbl_803E2E98;
    *(s16*)obj = (s16)(getAngle(*(f32*)((char*)path + 0x74), *(f32*)((char*)path + 0x7c)) + 0x8000);
    ((GameObject *)obj)->anim.rotY = (s16)(getAngle(*(f32*)((char*)path + 0x7c), *(f32*)((char*)path + 0x78)) + 0x4000);
    ((GameObject *)obj)->anim.rotZ = (s16)(getAngle(*(f32*)((char*)path + 0x78), *(f32*)((char*)path + 0x74)) + 0x4000);
    ((GameObject *)obj)->anim.localPosX = *(f32*)((char*)path + 0x68);
    ((GameObject *)obj)->anim.localPosY = *(f32*)((char*)path + 0x6c);
    ((GameObject *)obj)->anim.localPosZ = *(f32*)((char*)path + 0x70);
}

/* 8b "li r3, N; blr" returners. */
int dll_CE_getExtraSize_ret_1052(void) { return 0x41c; }
int dll_CE_getObjectTypeId(void) { return 0x49; }
int chukchuk_getExtraSize(void) { return 0x18; }
int chukchuk_getObjectTypeId(void) { return 0x0; }
int iceball_getExtraSize(void) { return 0x2; }
int iceball_getObjectTypeId(void) { return 0x0; }
int fn_8016052C(void) { return 0x6; }
int dll_CB_getExtraSize_ret_1040(void) { return 0x410; }
int dll_CB_getObjectTypeId(void) { return 0x14b; }

/* Pattern wrappers. */
s16 dll_CE_setScale(int *obj) { return *(s16*)((char*)((int**)obj)[0xb8/4] + 0x274); }
s16 dll_CB_setScale(int *obj) { return *(s16*)((char*)((int**)obj)[0xb8/4] + 0x274); }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E2E30;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E2E50;
void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E2E30); }
void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E2E50); }

/* plain forwarder. */
extern void Camera_DisableViewYOffset(void);
void dll_CA_initialise(void) { fn_8015DAE8(); }
void iceball_free(void) { Camera_DisableViewYOffset(); }


void fn_8015F5B0(short *obj)
{
  extern u8 Obj_IsLoadingLocked(void);
  extern int Obj_AllocObjectSetup(int size, int id);
  extern u8 *Obj_SetupObject(int setup, int a, int b, int c, int d);
  extern int Obj_GetPlayerObject(void);
  extern f64 lbl_803E2E28;
  extern f32 lbl_803E2E20;
  extern f32 lbl_803E2E24;
  ChukChukState *sub;
  int setup;
  u8 *o;
  int pl;
  f32 sc;

  sub = ((GameObject *)obj)->extra;
  if (Obj_IsLoadingLocked() != 0) {
    setup = Obj_AllocObjectSetup(36, 1307);
    ((ObjPlacement *)setup)->posX = ((GameObject *)obj)->anim.localPosX;
    ((ObjPlacement *)setup)->posY = lbl_803E2E20 + ((GameObject *)obj)->anim.localPosY;
    ((ObjPlacement *)setup)->posZ = ((GameObject *)obj)->anim.localPosZ;
    *(s8 *)(setup + 4) = 1;
    *(s8 *)(setup + 5) = 4;
    *(u8 *)(setup + 7) = 0xff;
    o = Obj_SetupObject(setup, 5, -1, -1, 0);
    if (o != NULL) {
      pl = Obj_GetPlayerObject();
      ((GameObject *)o)->anim.velocityX = (*(f32 *)(pl + 0xc) - ((GameObject *)obj)->anim.localPosX) / (sc = lbl_803E2E24);
      ((GameObject *)o)->anim.velocityY =
          ((*(f32 *)(pl + 0x10) + (f32)(u32)sub->aimHeightY) - ((GameObject *)obj)->anim.localPosY) /
          sc;
      ((GameObject *)o)->anim.velocityZ = (*(f32 *)(pl + 0x14) - ((GameObject *)obj)->anim.localPosZ) / sc;
    }
  }
}

void chukchuk_update(short *obj)
{
  extern void objParticleFn_80099d84(f32, short *, int, f32, int);
  extern int *objFindTexture(short *obj, int a, int b);
  extern int Obj_GetPlayerObject(void);
  extern int getAngle(f32 deltaX, f32 deltaZ);
  extern f32 sqrtf(f32);
  extern void GameBit_Set(int bit, int val);
  extern void fn_8015F5B0(short *obj);
  extern u8 lbl_8031FF80[];
  extern f32 timeDelta;
  extern f64 lbl_803E2E48;
  extern f32 lbl_803E2E30;
  extern f32 lbl_803E2E34;
  extern f32 lbl_803E2E38;
  extern f32 lbl_803E2E3C;
  extern f32 lbl_803E2E40;
  ChukChukState *v;
  u16 di;
  int pl;
  int *tex;
  int ang;
  int r;
  f32 ph;
  f32 lim;
  f32 nv;
  f32 dx;
  f32 dz;
  struct {
    int c;
    int b;
    int a;
    f32 d[3];
  } stk;

  v = ((GameObject *)obj)->extra;
  if (v->steamTimer != lbl_803E2E34) {
    v->steamTimer -= timeDelta;
    objParticleFn_80099d84(lbl_803E2E30, obj, 1, v->steamTimer / lbl_803E2E38, 0);
    if (v->steamTimer <= *(f32 *)&lbl_803E2E34) {
      v->steamTimer = lbl_803E2E34;
    }
  }
  if ((v->flags & 2) == 0) {
    tex = objFindTexture(obj, 0, 0);
    if (v->glowPhase < lbl_803E2E3C) {
      if ((int)v->glowPhase == 10) {
        v->flags |= 1;
      }
      *tex = lbl_8031FF80[(int)v->glowPhase] << 8;
      lim = lbl_803E2E3C;
      nv = v->glowPhase + lbl_803E2E30;
      v->glowPhase = nv;
      if (lim == nv) {
        v->glowPhase = (f32)(int)randomGetRange(16, 245);
      }
    } else {
      if (lbl_803E2E40 - v->glowPhase >= timeDelta) {
        v->glowPhase = v->glowPhase + timeDelta;
      } else {
        v->glowPhase = lbl_803E2E34;
      }
      *tex = 0;
    }
    pl = Obj_GetPlayerObject();
    dx = *(f32 *)(pl + 0xc) - ((GameObject *)obj)->anim.localPosX;
    dz = *(f32 *)(pl + 0x14) - ((GameObject *)obj)->anim.localPosZ;
    di = sqrtf(dx * dx + dz * dz);
    if (di < v->triggerDistance) {
      if (v->prevDistance >= v->triggerDistance) {
        v->flags = 5;
        v->glowPhase = lbl_803E2E34;
      }
      if ((v->flags & 5) != 0) {
        stk.d[0] = *(f32 *)(pl + 0x18) - ((GameObject *)obj)->anim.worldPosX;
        stk.d[1] = *(f32 *)(pl + 0x1c) - ((GameObject *)obj)->anim.worldPosY;
        stk.d[2] = *(f32 *)(pl + 0x20) - ((GameObject *)obj)->anim.worldPosZ;
        ang = getAngle(stk.d[0], stk.d[2]) & 0xffff;
        ang -= *obj & 0xffff;
        if (ang > 0x8000) {
          ang -= 0xffff;
        }
        if (ang < -0x8000) {
          ang += 0xffff;
        }
        if (((u32)ang & 0xffff) < v->arcHalfAngle ||
            ((u32)ang & 0xffff) > ((0xffff - v->arcHalfAngle) & 0xffff)) {
          r = randomGetRange(0, 99);
          if (r < v->attackChance || (v->flags & 4) != 0) {
            Sfx_PlayFromObject(obj, SFXkr_impact1);
            fn_8015F5B0(obj);
          } else {
            Sfx_PlayFromObject(obj, SFXkr_impact2);
          }
        } else {
          Sfx_PlayFromObject(obj, SFXkr_impact2);
        }
      }
    } else if ((v->flags & 1) != 0) {
      Sfx_PlayFromObject(obj, SFXkr_impact2);
    }
    v->prevDistance = di;
    if (ObjHits_GetPriorityHit(obj, &stk.a, &stk.b, &stk.c) == 14) {
      v->hitsLeft -= 1;
      if (v->hitsLeft < 1) {
        ObjHits_DisableObject(obj);
        ((GameObject *)obj)->anim.flags |= 0x4000;
        v->flags |= 2;
        Sfx_PlayFromObject(obj, SFXkr_impact3);
        GameBit_Set(v->gameBit, 1);
        v->steamTimer = lbl_803E2E38;
        Sfx_PlayFromObject(obj, SFXfoot_ice_run_4);
      }
    }
    v->flags &= ~5;
  }
}

/* chukchuk_setScale (52B). If low-byte of arg2 (u8) == 0x80, call Sfx_PlayFromObject(obj, SFXkr_jump1). */
#pragma scheduling on
#pragma peephole on
void chukchuk_setScale(int obj, int v) {
    switch ((u8)v) {
    case 0x80:
        Sfx_PlayFromObject(obj, SFXkr_jump1);
        break;
    }
}

/* iceball_init (60B). Sets ->f4 = 0xb4, calls ObjHits_DisableObject(obj), then stb 0xff at 0x36. */
#pragma scheduling off
#pragma peephole off
void iceball_init(void *obj) {
    char *p = (char*)obj;
    *(int*)(p + 0xf4) = 0xb4;
    ObjHits_DisableObject((int)p);
    ((GameObject *)p)->anim.alpha = 0xff;
}

/* fn_8016050C (32B). Returns 3 if (s8)obj[0x354] < 1 else 6. */
#pragma scheduling on
int fn_8016050C(int p1, u8 *obj) {
    if ((s8)obj[0x354] < 1) return 3;
    return 6;
}
/* grimble_stateHandlerB03 (32B). Returns 5 if (s8)obj[0x354] < 1 else 1. */
int grimble_stateHandlerB03(int p1, u8 *obj) {
    if ((s8)obj[0x354] < 1) return 5;
    return 1;
}

/* fn_8015E00C (56B). Two-tier select: <1 -> 3, else if obj[0x346]!=0 -> 6 else 0. */
int fn_8015E00C(int p1, u8 *obj) {
    if ((s8)obj[0x354] < 1) return 3;
    if ((s8)obj[0x346] != 0) return 6;
    return 0;
}

/* grimble_stateHandlerB05 (92B). If obj2->27b != 0, clear obj->b8->405, call GameBit_Set twice. */
extern void GameBit_Set(int eventId, int value);
#pragma scheduling off
int grimble_stateHandlerB05(int* obj, u8* obj2) {
    GroundBaddieState* x = ((GameObject *)obj)->extra;
    if ((s8)obj2[0x27b] != 0) {
        x->unk405 = 0;
        GameBit_Set(x->gameBitB, 0);
        GameBit_Set(x->gameBitA, 1);
    }
    return 0;
}

/* fn_801603E8 (84B). If obj2->27b != 0, vtable call through gBaddieControlInterface with (obj, x->unk3F0, -1, 0). */
extern undefined4* gBaddieControlInterface;
int fn_801603E8(int* obj, u8* obj2) {
    GroundBaddieState* x = ((GameObject *)obj)->extra;
    if ((s8)obj2[0x27b] != 0) {
        (*(code*)((char*)(*gBaddieControlInterface) + 0x4c))(obj, x->unk3F0, -1, 0);
    }
    return 0;
}

/* dll_CB_hitDetect (60B). Vtable dispatch through gPlayerInterface with extra args (obj->b8, lbl_803AC5E8). */
extern u8 lbl_803AC5E8[];
extern undefined4* gPlayerInterface;
#pragma peephole on
void dll_CB_hitDetect(int* obj) {
    void* a = ((GameObject *)obj)->extra;
    (*(code*)((char*)(*gPlayerInterface) + 0xc))(obj, a, lbl_803AC5E8);
}

/* dll_CB_render (64B). Render variant: if visible && !obj->f4 then objRenderFn(lbl_803E2E8C). */
extern f32 lbl_803E2E8C;
#pragma scheduling on
#pragma peephole off
void dll_CB_render(int* obj, int p2, int p3, int p4, int p5, s8 visible) {
    s32 v = visible;
    if (v != 0) {
        switch (((GameObject *)obj)->unkF4) {
        case 0:
            objRenderFn_8003b8f4(lbl_803E2E8C);
            break;
        }
    }
}

/* fn_801605A8 (44B). Writes float+state fields into obj and copies two halfwords to out. */
extern f32 lbl_803E2E68;
#pragma scheduling off
#pragma peephole on
int fn_801605A8(short *out, u8 *obj) {
    f32 f = lbl_803E2E68;
    *(f32*)(obj + 0x280) = f;
    *(f32*)(obj + 0x284) = f;
    *(s8 *)(obj + 0x25f) = 1;
    out[2] = *(s16*)(obj + 0x19e);
    out[1] = *(s16*)(obj + 0x19c);
    return 0;
}

/* fn_80160690 (96B). Like fn_801605A8 but with extra stfs at 0x2a0 and a vtable call. */
int fn_80160690(short* out, u8* obj) {
    f32 f = lbl_803E2E68;
    *(f32*)(obj + 0x280) = f;
    *(f32*)(obj + 0x284) = f;
    *(f32*)(obj + 0x2a0) = f;
    *(s8*)(obj + 0x25f) = 1;
    out[2] = *(s16*)(obj + 0x19e);
    out[1] = *(s16*)(obj + 0x19c);
    (*(code*)((char*)(*gPlayerInterface) + 0x30))(out, obj, 5);
    return 0;
}

extern f32 lbl_803E2DC8;
extern u8 framesThisStep;

/* Drift-recovery: add new fns with v1.0 names to capture asm symbols. */

#pragma peephole off
int fn_8015DE50(int* obj, GroundBaddieState *state)
{
    GroundBaddieState* sub = ((GameObject *)obj)->extra;
    if ((s8)state->baddie.moveJustStartedB != 0) {
        f32 fz;
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 1);
        {
            f32* p = *(f32 **)&sub->control;
            fz = lbl_803E2DC8;
            p[0] = fz;
            p[1] = fz;
        }
    }
    return 0;
}

int fn_8015DEB4(int* obj, GroundBaddieState *state)
{
    GroundBaddieState* sub;
    if ((s8)state->baddie.moveJustStartedB != 0) {
        sub = ((GameObject *)obj)->extra;
        sub->unk405 = 0;
        if (sub->gameBitB != -1) {
            GameBit_Set(sub->gameBitB, 0);
        }
        if (sub->gameBitA != -1) {
            GameBit_Set(sub->gameBitA, 1);
        }
    }
    return 0;
}

int fn_8015E044(int* obj, GroundBaddieState *state)
{
    if (*(int **)&state->baddie.targetObj != NULL) {
        if ((s8)state->baddie.moveJustStartedB != 0) {
            f32 fz = lbl_803E2DC8;
            state->baddie.animSpeedB = fz;
            state->baddie.animSpeedA = fz;
            ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 0);
        }
        if ((s8)state->baddie.moveDone != 0) {
            return 6;
        }
    }
    return 0;
}

extern f32 lbl_803E2DD8;
extern f32 lbl_803E2E7C;
extern f64 lbl_803E2E80;
extern f32 lbl_803E2E88;
extern f32 lbl_803E2EB8;
extern f32 lbl_803E2EE8;

int grimble_stateHandlerA08(int* obj, GroundBaddieState *state)
{
    GroundBaddieState* sub = ((GameObject *)obj)->extra;
    if ((s8)state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2EB8, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.moveSpeed = lbl_803E2EE8;
    if ((*(int *)&state->baddie.eventFlags & 0x200) != 0) {
        Sfx_PlayFromObject(obj, SFXdoor_creak);
        *(int *)&state->baddie.eventFlags &= ~0x200;
        ((void(*)(int*, int, int, int))((void**)*gBaddieControlInterface)[19])(obj, sub->unk3F0, -1, 1);
    }
    return 0;
}

int fn_8016032C(int* obj, GroundBaddieState *state)
{
    if ((s8)state->baddie.moveJustStartedB != 0) {
        f32 fz;
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 0);
        fz = lbl_803E2E7C;
        ((GameObject *)obj)->anim.velocityY = fz;
        state->baddie.animSpeedA = fz;
        state->baddie.unk294 = fz;
    }
    if (((GameObject *)obj)->anim.velocityY < lbl_803E2E80) {
        f32 fz = lbl_803E2E68;
        ((GameObject *)obj)->anim.velocityY = fz;
        state->baddie.animSpeedA = fz;
        state->baddie.unk294 = fz;
        return 6;
    }
    {
        f32 d = lbl_803E2E88;
        ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY / d;
        state->baddie.animSpeedA = state->baddie.animSpeedA / d;
        state->baddie.unk294 = state->baddie.unk294 / d;
    }
    return 0;
}

int fn_8015E520(int* obj, GroundBaddieState *state)
{
    if ((s8)state->baddie.moveJustStartedA != 0) {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->objectPairPriority = 10;
    (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    state->baddie.moveSpeed = lbl_803E2DD8;
    if ((s8)state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E2DC8, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.unk34D = 1;
    return 0;
}

int grimble_stateHandlerB04(int* obj, GroundBaddieState *state)
{
    if ((s8)state->baddie.moveJustStartedB != 0) {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 8);
        *(int *)&state->baddie.targetObj = 0;
        state->baddie.unk25F = 0;
        state->baddie.unk349 = 0;
        ObjHits_DisableObject((int)obj);
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    }
    if (((GameObject *)obj)->anim.alpha == 0) {
        if (*(void**)&((GameObject *)obj)->anim.placementData == NULL) {
            Obj_FreeObject(obj);
            return 0;
        }
        return 6;
    }
    return 0;
}

extern void* lbl_803AC5D0[];
extern int fn_801605D4(int* obj, GroundBaddieState* def);
int fn_80160534(int* obj);

extern void* lbl_803AC5B0[];
extern void* lbl_803AC598[];

void dll_CE_initialise(void)
{
    lbl_803AC5B0[0] = (void*)fn_8015E8BC;
    lbl_803AC5B0[1] = (void*)fn_8015E798;
    lbl_803AC5B0[2] = (void*)fn_8015E5DC;
    lbl_803AC5B0[3] = (void*)fn_8015E520;
    lbl_803AC5B0[4] = (void*)fn_8015E3A0;
    lbl_803AC5B0[5] = (void*)fn_8015E210;
    lbl_803AC5B0[6] = (void*)fn_8015E0C8;
    lbl_803AC598[0] = (void*)fn_8015E044;
    lbl_803AC598[1] = (void*)fn_8015E00C;
    lbl_803AC598[2] = (void*)fn_8015DF20;
    lbl_803AC598[3] = (void*)fn_8015DEB4;
    lbl_803AC598[4] = (void*)fn_8015DE50;
    lbl_803AC598[5] = (void*)fn_8015DC04;
}

extern f32 lbl_803E2E90;
extern f32 lbl_803E2E94;

int fn_801605D4(int* obj, GroundBaddieState *def)
{
    GroundBaddieState* state = ((GameObject *)obj)->extra;
    if ((s8)def->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2E68, 0);
        *(s8 *)&def->baddie.moveDone = 0;
    }
    *(s8 *)&def->baddie.unk25F = 1;
    ((GameObject *)obj)->anim.rotZ = def->baddie.unk19E;
    ((GameObject *)obj)->anim.rotY = def->baddie.unk19C;
    ((void(*)(int*, u8*, int*, f32, f32))((void**)*gBaddieControlInterface)[4])(obj, (u8 *)def, (int *)state, lbl_803E2E8C, lbl_803E2E90);
    def->baddie.moveSpeed = lbl_803E2E94 * def->baddie.animSpeedA;
    return 0;
}

void dll_CB_initialise(void)
{
    ((void**)lbl_803AC5E8)[0] = (void*)fn_80160690;
    ((void**)lbl_803AC5E8)[1] = (void*)fn_801605D4;
    ((void**)lbl_803AC5E8)[2] = (void*)fn_801605A8;
    ((void**)lbl_803AC5E8)[3] = (void*)fn_80160534;
    lbl_803AC5D0[0] = (void*)fn_8016052C;
    lbl_803AC5D0[1] = (void*)fn_8016050C;
    lbl_803AC5D0[2] = (void*)fn_8016043C;
    lbl_803AC5D0[3] = (void*)fn_801603E8;
    lbl_803AC5D0[4] = (void*)fn_8016032C;
    lbl_803AC5D0[5] = (void*)fn_801601C4;
}

#pragma peephole on
int fn_80160534(int* obj)
{
    GroundBaddieState* sub = ((GameObject *)obj)->extra;
    u8 step;
    if (((GameObject *)obj)->anim.alpha >= (step = framesThisStep)) {
        ((GameObject *)obj)->anim.alpha = ((GameObject *)obj)->anim.alpha - step;
    } else {
        ((GameObject *)obj)->anim.alpha = 0;
    }
    if (((GameObject *)obj)->anim.alpha == 0) {
        GameBit_Set(sub->gameBitB, 0);
        GameBit_Set(sub->gameBitA, 1);
    }
    return 0;
}

#pragma peephole off
int grimble_stateHandlerB01(int* obj, GroundBaddieState *state)
{
    if ((s8)state->baddie.moveJustStartedB != 0) {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 9);
    }
    if ((s8)state->baddie.moveDone != 0) {
        return 1;
    }
    return 0;
}

int grimble_stateHandlerB00(int obj, GroundBaddieState *p)
{
  extern f32 timeDelta;
  extern f64 lbl_803E2ED8;
  extern f32 lbl_803E2ED0;
  extern f32 lbl_803E2ED4;
  u16 a;
  u16 b;
  u16 c;

  if (*(void **)&p->baddie.targetObj != NULL && p->baddie.controlMode != 2) {
    if ((f32)p->baddie.unk32E > lbl_803E2ED0 * timeDelta) {
      (*(void (**)(int, int, int, u16 *, u16 *, u16 *))((char *)*gBaddieControlInterface + 0x14))(
          obj, *(int *)&p->baddie.targetObj, 16, &a, &b, &c);
      if (a < 4 || a > 11) {
        return 3;
      }
      (*(void (**)(int, u8 *, int))((char *)*gPlayerInterface + 0x14))(obj, (u8 *)p, 2);
      p->baddie.moveSpeed = lbl_803E2ED4;
      *(s8 *)&p->baddie.moveDone = 0;
    }
  }
  return 0;
}

int grimble_stateHandlerA09(int obj, GroundBaddieState *p)
{
  extern f32 lbl_803E2EB8;
  extern f32 lbl_803E2EE0;
  extern f32 lbl_803E2EE4;
  GroundBaddieState *sub;
  f32 spd;

  sub = ((GameObject *)obj)->extra;
  *(s8 *)&p->baddie.unk34D = 0;
  p->baddie.moveSpeed = lbl_803E2EE0;
  spd = lbl_803E2EB8;
  p->baddie.animSpeedA = spd;
  p->baddie.animSpeedB = spd;
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    Sfx_PlayFromObject(obj, SFXsc_death02);
    if (*(char *)&p->baddie.moveJustStartedA != '\0') {
      ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E2EB8, 0);
      *(s8 *)&p->baddie.moveDone = 0;
    }
    p->baddie.moveSpeed = lbl_803E2EE4;
    *(s8 *)&p->baddie.moveDone = 0;
    ((GameObject *)obj)->anim.alpha = 0xff;
    sub->flags400 |= 0x100;
  }
  if (*(char *)&p->baddie.moveDone != '\0') {
    return 1;
  }
  return 0;
}

int grimble_stateHandlerA06(short *obj, GroundBaddieState *p, f32 spd)
{
  extern f32 sqrtf(f32);
  extern int getAngle(f32 a, f32 b);
  extern int randomGetRange(int min, int max);
  extern f32 lbl_803E2EB8;
  extern f32 lbl_803E2EF0;
  extern f32 lbl_803E2EF4;
  extern f32 lbl_803E2EF8;
  extern f32 lbl_803E2EFC;
  extern f64 lbl_803E2ED8;
  int hit;
  f64 d;
  f32 r;
  struct {
    f32 x, y, z;
  } b;
  struct {
    f32 x, y, z;
  } a;

  hit = *(int *)(*(int *)&((GameObject *)obj)->extra + 0x40c);
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)obj)->anim.hitReactState)->hitVolumePriority = 9;
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)obj)->anim.hitReactState)->hitVolumeId = 1;
  ObjHits_RegisterActiveHitVolumeObject(obj);
  if (randomGetRange(0, 100) < 50) {
    if (*(char *)&p->baddie.moveJustStartedA != '\0') {
      ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E2EB8, 0);
      *(s8 *)&p->baddie.moveDone = 0;
    }
  } else if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 4, lbl_803E2EB8, 0);
    *(s8 *)&p->baddie.moveDone = 0;
  }
  p->baddie.moveSpeed = lbl_803E2EF0;
  (*(void (**)(short *, u8 *, f32, int))((char *)*gPlayerInterface + 0x20))(obj, (u8 *)p, spd, 1);
  (*(void (**)(void *, void *, f32))(**(int **)(((GrimbleState *)hit)->unk38 + 0x68) + 0x28))(
      *(void **)&((GrimbleState *)hit)->unk38, (void *)(hit + 0x48),
      p->baddie.animSpeedA * (f32)(1 - (((GrimbleState *)hit)->unk45 << 1)));
  if (((GrimbleState *)hit)->unk48 < lbl_803E2EF4) {
    ((GrimbleState *)hit)->unk48 = lbl_803E2EF4;
  } else if (((GrimbleState *)hit)->unk48 > lbl_803E2EF8) {
    ((GrimbleState *)hit)->unk48 = lbl_803E2EF8;
  }
  (*(void (**)(void *, f32, f32 *, f32 *, f32 *))(**(int **)(((GrimbleState *)hit)->unk38 + 0x68) +
                                                  0x24))(
      *(void **)&((GrimbleState *)hit)->unk38, ((GrimbleState *)hit)->unk48 - lbl_803E2EFC, &a.x, &a.y, &a.z);
  (*(void (**)(void *, f32, f32 *, f32 *, f32 *))(**(int **)(((GrimbleState *)hit)->unk38 + 0x68) +
                                                  0x24))(
      *(void **)&((GrimbleState *)hit)->unk38, lbl_803E2EFC + ((GrimbleState *)hit)->unk48, &b.x, &b.y, &b.z);
  a.x = a.x - b.x;
  a.y = a.y - b.y;
  a.z = a.z - b.z;
  r = sqrtf(a.x * a.x + a.z * a.z);
  d = r;
  a.x = r;
  {
    int ang = (s16)getAngle(a.y, (f32)d);
    ((GameObject *)obj)->anim.rotY = ang * ((((GrimbleState *)hit)->unk45 << 1) - 1);
  }
  if (*(char *)&p->baddie.moveDone != '\0') {
    return 5;
  }
  return 0;
}

int grimble_stateHandlerA07(short *obj, GroundBaddieState *p)
{
  extern f32 lbl_803E2EB8;
  extern f32 lbl_803E2EEC;
  int hit;
  s16 yaw;
  int diff;
  f32 spd;

  hit = *(int *)(*(int *)&((GameObject *)obj)->extra + 0x40c);
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 7, lbl_803E2EB8, 0);
    *(s8 *)&p->baddie.moveDone = 0;
  }
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    Sfx_PlayFromObject(obj, SFXsc_attack04);
  }
  p->baddie.moveSpeed = lbl_803E2EEC;
  yaw = ((GrimbleState *)hit)->unk58;
  diff = *obj - (yaw & 0xffff);
  if (diff > 0x8000) {
    diff -= 0xffff;
  }
  if (diff < -0x8000) {
    diff += 0xffff;
  }
  *obj = yaw;
  if (diff > 0x3ffc || diff < -0x3ffc) {
    *obj += 0x8000;
  }
  spd = lbl_803E2EB8;
  p->baddie.animSpeedA = spd;
  p->baddie.animSpeedB = spd;
  if (*(char *)&p->baddie.moveDone != '\0') {
    return 1;
  }
  return 0;
}

int grimble_stateHandlerA05(short *obj, GroundBaddieState *p)
{
  extern f32 sqrtf(f32);
  extern int getAngle(f32 a, f32 b);
  extern f32 lbl_803E2EB8;
  extern f32 lbl_803E2EF0;
  extern f32 lbl_803E2EFC;
  int hit;
  f64 d;
  f32 r;
  struct {
    f32 x, y, z;
  } b;
  struct {
    f32 x, y, z;
  } a;

  hit = *(int *)(*(int *)&((GameObject *)obj)->extra + 0x40c);
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 6, lbl_803E2EB8, 0);
    *(s8 *)&p->baddie.moveDone = 0;
  }
  p->baddie.moveSpeed = lbl_803E2EF0;
  (*(void (**)(void *, f32, f32 *, f32 *, f32 *))(**(int **)(((GrimbleState *)hit)->unk38 + 0x68) +
                                                  0x24))(
      *(void **)&((GrimbleState *)hit)->unk38, ((GrimbleState *)hit)->unk48 - lbl_803E2EFC, &a.x, &a.y, &a.z);
  (*(void (**)(void *, f32, f32 *, f32 *, f32 *))(**(int **)(((GrimbleState *)hit)->unk38 + 0x68) +
                                                  0x24))(
      *(void **)&((GrimbleState *)hit)->unk38, lbl_803E2EFC + ((GrimbleState *)hit)->unk48, &b.x, &b.y, &b.z);
  a.x = a.x - b.x;
  a.y = a.y - b.y;
  a.z = a.z - b.z;
  r = sqrtf(a.x * a.x + a.z * a.z);
  d = r;
  a.x = r;
  {
    int ang = (s16)getAngle(a.y, (f32)d);
    ((GameObject *)obj)->anim.rotY = ang * ((((GrimbleState *)hit)->unk45 << 1) - 1);
  }
  return 0;
}

int grimble_stateHandlerA04(short *obj, GroundBaddieState *p)
{
  extern f32 sqrtf(f32);
  extern int getAngle(f32 a, f32 b);
  extern f32 lbl_803E2EB8;
  extern f32 lbl_803E2EF0;
  extern f32 lbl_803E2EFC;
  int hit;
  f64 d;
  f32 r;
  struct {
    f32 x, y, z;
  } b;
  struct {
    f32 x, y, z;
  } a;

  hit = *(int *)(*(int *)&((GameObject *)obj)->extra + 0x40c);
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E2EB8, 0);
    *(s8 *)&p->baddie.moveDone = 0;
  }
  p->baddie.moveSpeed = lbl_803E2EF0;
  (*(void (**)(void *, f32, f32 *, f32 *, f32 *))(**(int **)(((GrimbleState *)hit)->unk38 + 0x68) +
                                                  0x24))(
      *(void **)&((GrimbleState *)hit)->unk38, ((GrimbleState *)hit)->unk48 - lbl_803E2EFC, &a.x, &a.y, &a.z);
  (*(void (**)(void *, f32, f32 *, f32 *, f32 *))(**(int **)(((GrimbleState *)hit)->unk38 + 0x68) +
                                                  0x24))(
      *(void **)&((GrimbleState *)hit)->unk38, lbl_803E2EFC + ((GrimbleState *)hit)->unk48, &b.x, &b.y, &b.z);
  a.x = a.x - b.x;
  a.y = a.y - b.y;
  a.z = a.z - b.z;
  r = sqrtf(a.x * a.x + a.z * a.z);
  d = r;
  a.x = r;
  {
    int ang = (s16)getAngle(a.y, (f32)d);
    ((GameObject *)obj)->anim.rotY = ang * ((((GrimbleState *)hit)->unk45 << 1) - 1);
  }
  if (*(char *)&p->baddie.moveDone != '\0') {
    return 6;
  }
  return 0;
}

int grimble_stateHandlerA03(short *obj, GroundBaddieState *p)
{
  extern f32 sqrtf(f32);
  extern int getAngle(f32 a, f32 b);
  extern f32 lbl_803E2EB8;
  extern f32 lbl_803E2EE4;
  extern f32 lbl_803E2EFC;
  int hit;
  f64 d;
  f32 r;
  struct {
    f32 x, y, z;
  } b;
  struct {
    f32 x, y, z;
  } a;

  hit = *(int *)(*(int *)&((GameObject *)obj)->extra + 0x40c);
  if (*(char *)&p->baddie.moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E2EB8, 0);
    *(s8 *)&p->baddie.moveDone = 0;
  }
  p->baddie.moveSpeed = lbl_803E2EE4;
  (*(void (**)(void *, f32, f32 *, f32 *, f32 *))(**(int **)(((GrimbleState *)hit)->unk38 + 0x68) +
                                                  0x24))(
      *(void **)&((GrimbleState *)hit)->unk38, ((GrimbleState *)hit)->unk48 - lbl_803E2EFC, &a.x, &a.y, &a.z);
  (*(void (**)(void *, f32, f32 *, f32 *, f32 *))(**(int **)(((GrimbleState *)hit)->unk38 + 0x68) +
                                                  0x24))(
      *(void **)&((GrimbleState *)hit)->unk38, lbl_803E2EFC + ((GrimbleState *)hit)->unk48, &b.x, &b.y, &b.z);
  a.x = a.x - b.x;
  a.y = a.y - b.y;
  a.z = a.z - b.z;
  r = sqrtf(a.x * a.x + a.z * a.z);
  d = r;
  a.x = r;
  {
    int ang = (s16)getAngle(a.y, (f32)d);
    ((GameObject *)obj)->anim.rotY = ang * ((((GrimbleState *)hit)->unk45 << 1) - 1);
  }
  if (*(char *)&p->baddie.moveDone != '\0') {
    return 1;
  }
  return 0;
}

void dll_CB_free(int* obj)
{
    GroundBaddieState* state = ((GameObject *)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    {
        int* sub = ((GameObject *)obj)->unkC8;
        if (sub != NULL) {
            Obj_FreeObject(sub);
            ((GameObject *)obj)->unkC8 = NULL;
        }
    }
    ((void(*)(int*, int*, int))((void**)*gBaddieControlInterface)[16])(obj, (int *)state, 1);
}

void dll_CE_free(int* obj)
{
    GroundBaddieState* state = ((GameObject *)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    {
        int* sub = ((GameObject *)obj)->unkC8;
        if (sub != NULL) {
            Obj_FreeObject(sub);
            ((GameObject *)obj)->unkC8 = NULL;
        }
    }
    ((void(*)(int*, int*, int))((void**)*gBaddieControlInterface)[16])(obj, (int *)state, 32);
}


ObjectDescriptor11WithPadding gChukChukObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)chukchuk_initialise,
        (ObjectDescriptorCallback)chukchuk_release,
        0,
        (ObjectDescriptorCallback)chukchuk_init,
        (ObjectDescriptorCallback)chukchuk_update,
        (ObjectDescriptorCallback)chukchuk_hitDetect,
        (ObjectDescriptorCallback)chukchuk_render,
        (ObjectDescriptorCallback)chukchuk_free,
        (ObjectDescriptorCallback)chukchuk_getObjectTypeId,
        chukchuk_getExtraSize,
        (ObjectDescriptorCallback)chukchuk_setScale,
    },
    0,
};

ObjectDescriptor gIceBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)iceball_initialise,
    (ObjectDescriptorCallback)iceball_release,
    0,
    (ObjectDescriptorCallback)iceball_init,
    (ObjectDescriptorCallback)iceball_update,
    (ObjectDescriptorCallback)iceball_hitDetect,
    (ObjectDescriptorCallback)iceball_render,
    (ObjectDescriptorCallback)iceball_free,
    (ObjectDescriptorCallback)iceball_getObjectTypeId,
    iceball_getExtraSize,
};

extern f32 sqrtf(f32);
extern f32 lbl_803E2EB0;
extern f32 lbl_803E2EB4;
extern f32 lbl_803E2EBC;
extern f32 lbl_803E2EC0;
extern f32 lbl_803E2EC4;
extern f32 lbl_803E2EC8;
extern f32 lbl_803E2ECC;

/* scarab_updateProximityGate: scarab AI proximity gate. If no current target, dispatches
 * vtable[5](obj, state, 0) and returns 1. Else (unless state mode 6 means
 * already engaged) reads the angle from the obj to the target; when within
 * a +/-90? wedge the planar distance term is the constant lbl_803E2EB0,
 * otherwise it's sqrtf(dx*dx + dz*dz) - lbl_803E2EB4. The signed magnitude
 * drives three threshold checks against lbl_803E2EBC/EC0/EC4 that issue
 * vtable[5] calls with mode 6 (close), 1 (medium-out), or 1 (close-in)
 * depending on the current mode at (*(u8 *)&state->baddie.controlMode) and the latch byte at
 * state->baddie.moveDone. When mode == 1, picks one of two scalars (lbl_803E2EC8 or
 * lbl_803E2ECC) for (*(u8 *)&state->baddie.moveSpeed). Returns 0. */
int scarab_updateProximityGate(int* obj, GroundBaddieState *state) {
    int* target;
    f32 dx;
    f32 dz;
    f32 magAbs;
    u32 rel;

    target = *(int **)&state->baddie.targetObj;
    if (target == NULL) {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 0);
        return 1;
    }
    if (state->baddie.controlMode != 6) {
    dx = ((GameObject *)obj)->anim.localPosX - *(f32*)((char*)target + 0xc);
    dz = ((GameObject *)obj)->anim.localPosZ - *(f32*)((char*)target + 0x14);
    rel = (getAngle(dx, dz) - *(s16*)obj) & 0xffff;
    if (rel > 0x4000 && rel < 0xc000) {
        dx = lbl_803E2EB0;
    } else {
        dx = sqrtf(dx * dx + dz * dz) - lbl_803E2EB4;
    }
    magAbs = dx < lbl_803E2EB8 ? -dx : dx;
    if (magAbs < lbl_803E2EBC) {
        if (state->baddie.controlMode == 1 ||
            (state->baddie.controlMode == 5 && (s8)state->baddie.moveDone != 0)) {
            ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 6);
            goto post;
        }
    }
    if (state->baddie.controlMode == 1) goto post;
    if (dx > lbl_803E2EC0) {
        if (state->baddie.controlMode != 4 &&
            (state->baddie.controlMode != 5 || (s8)state->baddie.moveDone != 0)) {
            ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 1);
        }
    }
    if (dx < lbl_803E2EC4) {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 1);
    }
post:
    if (state->baddie.controlMode == 1) {
        state->baddie.moveSpeed = (dx > lbl_803E2EB8) ? lbl_803E2EC8 : lbl_803E2ECC;
    }
    }
    return 0;
}
