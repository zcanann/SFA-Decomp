#include "ghidra_import.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"
#include "main/objanim.h"
#include "main/objhits_types.h"
#include "main/objseq.h"
#include "main/dll/CF/CFBaby.h"

typedef struct InfopointPlacement {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
} InfopointPlacement;


typedef struct Dll109State {
    u8 pad0[0xA - 0x0];
    u8 unkA;
    u8 padB[0x10 - 0xB];
} Dll109State;


typedef struct InfopointObjectDef {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    u8 pad1A[0x1B - 0x1A];
    u8 unk1B;
    s16 unk1C;
    u8 unk1E;
    u8 unk1F;
} InfopointObjectDef;


typedef struct FallLaddersObjectDef {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} FallLaddersObjectDef;


typedef struct FlammablevineObjectDef {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} FlammablevineObjectDef;


typedef struct FlammablevinePlacement {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} FlammablevinePlacement;


typedef struct LandedArwingPlacement {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} LandedArwingPlacement;


typedef struct LandedArwingUpdateHitReactionPlacement {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} LandedArwingUpdateHitReactionPlacement;


typedef struct LandedArwingUpdateDamageTexturePlacement {
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} LandedArwingUpdateDamageTexturePlacement;


typedef struct ColdwatercontrolState {
    u8 pad0[0x8 - 0x0];
    u8 unk8;
    u8 unk9;
    u8 padA[0x10 - 0xA];
} ColdwatercontrolState;


typedef struct InfopointState {
    u8 pad0[0x8 - 0x0];
    u8 unk8;
    u8 unk9;
    u8 padA[0x20 - 0xA];
} InfopointState;


typedef struct FlammablevineState {
    u8 pad0[0x8 - 0x0];
    u8 unk8;
    u8 unk9;
    u8 padA[0x14 - 0xA];
} FlammablevineState;


extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006ba8();
extern void* FUN_80017470();
extern undefined4 FUN_80017680();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId,int value);
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_800178b8();
extern undefined4 FUN_80017a48();
extern int FUN_80017a5c();
extern undefined4 FUN_80017a78();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ad0();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305c4();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined8 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjHits_PollPriorityHitEffectWithCooldown();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_800427c8();
extern undefined4 FUN_80042800();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern undefined4 FUN_80044404();
extern undefined4 FUN_8005398c();
extern undefined4 FUN_80053c98();
extern int FUN_800575b4();
extern undefined4 FUN_800810f0();
extern undefined4 FUN_80081108();
extern undefined4 FUN_80081110();
extern undefined4 FUN_8011d9b4();
extern char FUN_8012e0e0();
extern int FUN_8012efc4();
extern undefined4 FUN_8013651c();
extern undefined4 FUN_8020a758();
extern undefined4 FUN_8020a75c();
extern undefined4 FUN_80247edc();
extern double SeekTwiceBeforeRead();
extern int FUN_80286834();
extern int FUN_80286840();
extern undefined4 FUN_80286880();
extern undefined4 FUN_8028688c();
extern uint FUN_80294c04();
extern int FUN_80294dbc();
extern void *Obj_GetPlayerObject(void);

extern undefined4 DAT_803225e0;
extern undefined4 DAT_803225f0;
extern undefined4 DAT_80322678;
extern undefined4 DAT_8032267c;
extern undefined4 DAT_8032267d;
extern undefined4 DAT_8032267e;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern EffectInterface **gPartfxInterface;
extern MapEventInterface **gMapEventInterface;
extern undefined4* DAT_803dd740;
extern f64 DOUBLE_803e47d0;
extern f64 DOUBLE_803e47f8;
extern f64 DOUBLE_803e4818;
extern f64 DOUBLE_803e4828;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4738;
extern f32 FLOAT_803e4750;
extern f32 FLOAT_803e4770;
extern f32 FLOAT_803e4774;
extern f32 FLOAT_803e4778;
extern f32 FLOAT_803e4780;
extern f32 FLOAT_803e4784;
extern f32 FLOAT_803e4790;
extern f32 FLOAT_803e4794;
extern f32 FLOAT_803e4798;
extern f32 FLOAT_803e479c;
extern f32 FLOAT_803e47a0;
extern f32 FLOAT_803e47a4;
extern f32 FLOAT_803e47a8;
extern f32 FLOAT_803e47ac;
extern f32 FLOAT_803e47b0;
extern f32 FLOAT_803e47b8;
extern f32 FLOAT_803e47bc;
extern f32 FLOAT_803e47c0;
extern f32 FLOAT_803e47c4;
extern f32 FLOAT_803e47c8;
extern f32 FLOAT_803e47cc;
extern f32 FLOAT_803e47dc;
extern f32 FLOAT_803e47e0;
extern f32 FLOAT_803e47e8;
extern f32 FLOAT_803e47ec;
extern f32 FLOAT_803e47f0;
extern f32 FLOAT_803e47f4;
extern f32 FLOAT_803e4800;
extern f32 FLOAT_803e4804;
extern f32 FLOAT_803e4810;
extern f32 FLOAT_803e4814;
extern f32 FLOAT_803e4820;
extern f32 FLOAT_803e4830;
extern f32 FLOAT_803e4834;
extern f32 FLOAT_803e4838;
extern f32 FLOAT_803e4840;
extern f32 FLOAT_803e4844;
extern f32 FLOAT_803e4848;

/*
 * --INFO--
 *
 * Function: FireFlyLantern_init
 * EN v1.0 Address: 0x80187524
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x80187608
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void FireFlyLantern_init(int obj, int def)
{
  void *player;
  u8 *childSlot;
  u8 *state;
  int i;
  u32 childCount;

  state = ((GameObject *)obj)->extra;
  ((GameObject *)obj)->animEventCallback = (void *)FireFlyLantern_SeqFn;
  player = Obj_GetPlayerObject();
  if (((GameObject *)player)->anim.seqId != 0) {
    *(s16 *)(state + 0x20) = 0x13d;
  }
  else {
    *(s16 *)(state + 0x20) = 0x5d6;
  }

  *(u8 *)(state + 0x1c) = 0;
  *(u8 *)(state + 0x1d) = GameBit_Get(*(s16 *)(state + 0x20));

  if (*(s8 *)(def + 0x19) == 1) {
    if (*(u8 *)(state + 0x1d) != 0) {
      *(u8 *)(state + 0x1c) = 1;
      *(int *)state = FireFlyLantern_spawnFireFly((int *)obj);
    }
    ((GameObject *)obj)->anim.flags = ((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
  }
  else {
    childCount = *(u8 *)(state + 0x1d);
    if (childCount >= 6) {
      childCount = 6;
    }
    *(u8 *)(state + 0x1c) = (u8)childCount;

    i = 0;
    childSlot = state;
    while (i < *(u8 *)(state + 0x1c)) {
      *(int *)childSlot = FireFlyLantern_spawnFireFly((int *)obj);
      childSlot += 4;
      i++;
    }
  }
}

/*
 * --INFO--
 *
 * Function: FUN_80187664
 * EN v1.0 Address: 0x80187664
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x80187720
 * EN v1.1 Size: 196b
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
 * Function: infopoint_hitDetect
 * EN v1.0 Address: 0x8018843C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801884A0
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void infopoint_hitDetect(void)
{
}


/*
 * --INFO--
 *
 * Function: FUN_80189054
 * EN v1.0 Address: 0x80189054
 * EN v1.0 Size: 2620b
 * EN v1.1 Address: 0x80189218
 * EN v1.1 Size: 1552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80189054(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,int param_12,undefined4 param_13,undefined4 param_14,undefined4 param_15,
            undefined4 param_16)
{
  undefined4 uVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 extraout_f1_03;
  undefined8 uVar8;
  
  iVar6 = *(int *)&((GameObject *)param_9)->anim.placementData;
  iVar5 = *(int *)&((GameObject *)param_9)->extra;
  iVar7 = 0;
  iVar4 = param_11;
  do {
    if ((int)(uint)*(byte *)(param_11 + 0x8b) <= iVar7) {
      return 0;
    }
    switch(*(undefined *)(param_11 + iVar7 + 0x81)) {
    case 2:
    case 0x65:
      iVar4 = *(int *)(iVar6 + 0x14);
      if (iVar4 == 0x49f5a) {
        FUN_80041ff8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x26);
        iVar4 = 1;
        FUN_80042b9c(0,0,1);
        uVar1 = FUN_80044404(0x26);
        FUN_80042bec(uVar1,0);
        uVar1 = FUN_80044404(0xb);
        FUN_80042bec(uVar1,1);
      }
      else if (iVar4 < 0x49f5a) {
        if (iVar4 == 0x451b9) {
          cVar2 = (*gMapEventInterface)->getMode(0xd);
          param_1 = extraout_f1;
          if (cVar2 == '\x02') {
            FUN_80041ff8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
            iVar4 = 1;
            FUN_80042b9c(0,0,1);
            uVar1 = FUN_80044404(0xb);
            FUN_80042bec(uVar1,0);
          }
          else {
            FUN_80041ff8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
            iVar4 = 1;
            FUN_80042b9c(0,0,1);
            uVar1 = FUN_80044404(0x29);
            FUN_80042bec(uVar1,0);
          }
        }
        else {
          if ((0x451b8 < iVar4) || (iVar4 != 0x43775)) goto LAB_801893dc;
          FUN_80041ff8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
          iVar4 = 1;
          FUN_80042b9c(0,0,1);
          uVar1 = FUN_80044404(0x29);
          FUN_80042bec(uVar1,0);
        }
      }
      else if (iVar4 == 0x4cd65) {
        FUN_80041ff8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x41);
        iVar4 = 1;
        FUN_80042b9c(0,0,1);
        uVar1 = FUN_80044404(0x41);
        FUN_80042bec(uVar1,0);
        uVar1 = FUN_80044404(0xb);
        FUN_80042bec(uVar1,1);
      }
      else {
LAB_801893dc:
        FUN_80041ff8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
        iVar4 = 1;
        FUN_80042b9c(0,0,1);
        uVar1 = FUN_80044404(0x29);
        FUN_80042bec(uVar1,0);
      }
      break;
    case 3:
    case 100:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x49f5a) {
        iVar4 = 0;
        param_12 = (int)*gMapEventInterface;
        param_1 = (**(code **)(param_12 + 0x50))(0xb,4);
      }
      else if (iVar3 < 0x49f5a) {
        if (iVar3 == 0x451b9) {
          cVar2 = (*gMapEventInterface)->getMode(0xd);
          param_1 = extraout_f1_00;
          if (cVar2 == '\x02') {
            uVar8 = extraout_f1_00;
            FUN_80042b9c(0,0,1);
            FUN_80044404(0xd);
            FUN_80043030(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            (*gMapEventInterface)->setAnimEvent(0xd,10,0);
            (*gMapEventInterface)->setAnimEvent(0xd,0xb,0);
            iVar4 = 0;
            param_12 = (int)*gMapEventInterface;
            param_1 = (**(code **)(param_12 + 0x50))(0xd,0xe);
          }
        }
        else if ((iVar3 < 0x451b9) && (iVar3 == 0x43775)) {
          iVar4 = 1;
          FUN_80042b9c(0,0,1);
          FUN_80044404(7);
          param_1 = FUN_80043030(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
      }
      else if (iVar3 == 0x4cd65) {
        iVar4 = 1;
        FUN_80042b9c(0,0,1);
        FUN_80044404(0xb);
        param_1 = FUN_80043030(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      break;
    case 5:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x451b9) {
        cVar2 = (*gMapEventInterface)->getMode(0xd);
        param_1 = extraout_f1_01;
        if (cVar2 == '\x02') {
          param_1 = FUN_80042800();
        }
      }
      else if (iVar3 < 0x451b9) {
        if (iVar3 == 0x43775) {
LAB_801895a4:
          param_1 = FUN_80042800();
        }
      }
      else if (iVar3 == 0x49f5a) goto LAB_801895a4;
      break;
    case 6:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x451b9) {
        cVar2 = (*gMapEventInterface)->getMode(0xd);
        param_1 = extraout_f1_02;
        if (cVar2 == '\x02') {
          param_1 = FUN_800427c8();
        }
      }
      else if (iVar3 < 0x451b9) {
        if (iVar3 == 0x43775) {
LAB_80189614:
          param_1 = FUN_800427c8();
        }
      }
      else if (iVar3 == 0x49f5a) goto LAB_80189614;
      break;
    case 7:
    case 0x66:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x49f5a) {
        param_1 = FUN_80053c98(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,
                               '\0',iVar4,param_12,param_13,param_14,param_15,param_16);
      }
      else if (iVar3 < 0x49f5a) {
        if ((iVar3 == 0x451b9) &&
           (cVar2 = (*gMapEventInterface)->getMode(0xd), param_1 = extraout_f1_03,
           cVar2 == '\x02')) {
          iVar4 = (int)*gMapEventInterface;
          uVar8 = (**(code **)(iVar4 + 0x44))(0xb,5);
          param_1 = FUN_80053c98(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x4e,
                                 '\0',iVar4,param_12,param_13,param_14,param_15,param_16);
        }
      }
      else if (iVar3 == 0x4cd65) {
        FUN_80053c98(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x7f,'\0',iVar4
                     ,param_12,param_13,param_14,param_15,param_16);
        iVar4 = (int)*gMapEventInterface;
        param_1 = (**(code **)(iVar4 + 0x44))(0x41,2);
      }
      break;
    case 10:
      *(undefined *)(iVar5 + 0x1a) = 1;
      break;
    case 0xb:
      *(undefined *)(iVar5 + 0x1a) = 0;
      break;
    case 0xc:
      *(float *)(iVar5 + 4) = FLOAT_803e4830;
      break;
    case 0xd:
      *(float *)(iVar5 + 4) = FLOAT_803e4840;
      break;
    case 0xe:
      *(float *)(iVar5 + 4) = FLOAT_803e4844;
      break;
    case 0xf:
      *(float *)(iVar5 + 4) = FLOAT_803e4848;
      break;
    case 0x10:
      *(float *)(iVar5 + 8) = FLOAT_803e4830;
      break;
    case 0x11:
      *(float *)(iVar5 + 8) = FLOAT_803e4840;
      break;
    case 0x12:
      *(float *)(iVar5 + 8) = FLOAT_803e4844;
      break;
    case 0x13:
      *(float *)(iVar5 + 8) = FLOAT_803e4848;
      break;
    case 0x14:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4830;
      break;
    case 0x15:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4840;
      break;
    case 0x16:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4844;
      break;
    case 0x17:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4848;
      break;
    case 0x18:
      iVar3 = *(int *)(iVar5 + 0x10);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xbfff;
      }
      break;
    case 0x19:
      iVar3 = *(int *)(iVar5 + 0x10);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
      }
    }
    iVar7 = iVar7 + 1;
  } while( true );
}



/* Trivial 4b 0-arg blr leaves. */
void flammablevine_release(void) {}
void flammablevine_initialise(void) {}
void dll_109_hitDetect_nop(void) {}
void dll_109_release_nop(void) {}
void dll_109_initialise_nop(void) {}
void Fall_Ladders_render(void) {}
void Fall_Ladders_hitDetect(void) {}
void Fall_Ladders_release(void) {}
void Fall_Ladders_initialise(void) {}
void infopoint_free(void) {}
void infopoint_release(void) {}
void infopoint_initialise(void) {}
void decoration11a_free(void) {}
void decoration11a_update(void) {}

/* 8b "li r3, N; blr" returners. */
int flammablevine_getExtraSize(void) { return 0x14; }
int flammablevine_getObjectTypeId(void) { return 0x0; }
int dll_109_getExtraSize_ret_16(void) { return 0x10; }
int dll_109_getObjectTypeId(void) { return 0x0; }
int Fall_Ladders_SeqFn(void) { return 0x0; }
int Fall_Ladders_getExtraSize(void) { return 0xc; }
int Fall_Ladders_getObjectTypeId(void) { return 0x0; }
int coldwatercontrol_getExtraSize(void) { return 0x8; }
int infopoint_getExtraSize(void) { return 0x20; }
int infopoint_getObjectTypeId(void) { return 0x0; }
int decoration11a_getExtraSize(void) { return 0x1c; }
int landed_arwing_getExtraSize(void) { return 0x1c; }

typedef struct FallLaddersState {
    f32 restYOffset;
    s16 lowerGameBit;
    s16 upperGameBit;
    u8 motionState;
    u8 playStartSound;
    s16 delay;
} FallLaddersState;

typedef struct CarryableBreakRespawnState {
    u8 pad0[0xa];
    u8 state;
    u8 padB;
    f32 timer;
} CarryableBreakRespawnState;

extern int *lbl_803DCAC0;
extern f32 timeDelta;
extern f32 lbl_803E3B44;
extern f32 lbl_803E3B48;
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int setup, int arg1, int arg2, int arg3, int arg4);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int ViewFrustum_IsSphereVisible(f32 *pos, f32 radius);

/* Carryable impact state machine that spawns break particles, hides, then respawns. */
#pragma scheduling off
#pragma peephole off
void carryable_break_respawn_update(int obj) {
    CarryableBreakRespawnState *state;
    int def;
    int setup;
    u32 hitVolume;

    state = ((GameObject *)obj)->extra;
    def = *(int *)&((GameObject *)obj)->anim.placementData;
    switch (state->state) {
        case 0:
            (*(void (*)(int, CarryableBreakRespawnState *))(*(int *)(*lbl_803DCAC0 + 8)))(obj, state);
            if (ObjHits_GetPriorityHit(obj, 0, 0, &hitVolume) != 0) {
                (*(void (*)(int, CarryableBreakRespawnState *))(*(int *)(*lbl_803DCAC0 + 0x30)))(obj, state);
                Sfx_PlayFromObject(obj, SFXen_rfall5_c);
                ObjHitbox_SetSphereRadius(obj, 0x28);
                ObjHits_SetHitVolumeSlot(obj, 5, 4, 0);
                if (Obj_IsLoadingLocked() != 0) {
                    setup = Obj_AllocObjectSetup(0x24, 0x253);
                    ((ObjPlacement *)setup)->posX = ((GameObject *)obj)->anim.localPosX;
                    ((ObjPlacement *)setup)->posY = ((GameObject *)obj)->anim.localPosY;
                    ((ObjPlacement *)setup)->posZ = ((GameObject *)obj)->anim.localPosZ;
                    Obj_SetupObject(setup, 5, ((GameObject *)obj)->anim.mapEventSlot, -1, *(int *)&((GameObject *)obj)->anim.parent);
                }
                (*gPartfxInterface)->spawnObject((void *)obj, 0x355, NULL, 0, -1, NULL);
                (*gPartfxInterface)->spawnObject((void *)obj, 0x352, NULL, 0, -1, NULL);
                state->state = 1;
            }
            break;
        case 1:
            ObjHits_ClearHitVolumes();
            ObjHits_DisableObject(obj);
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
            state->state = 2;
            state->timer = lbl_803E3B44;
            ((GameObject *)obj)->anim.localPosX = ((ObjPlacement *)def)->posX;
            ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)def)->posY;
            ((GameObject *)obj)->anim.localPosZ = ((ObjPlacement *)def)->posZ;
            break;
        case 2:
            state->timer += timeDelta;
            if (state->timer > lbl_803E3B48) {
                if (ViewFrustum_IsSphereVisible(&((GameObject *)obj)->anim.localPosX,
                                                ((GameObject *)obj)->anim.hitboxScale * ((GameObject *)obj)->anim.rootMotionScale) == 0) {
                    ObjHits_EnableObject(obj);
                    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
                    state->state = 0;
                }
            }
            break;
    }
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3AF8;
extern f32 lbl_803E3AFC;
extern f32 lbl_803E3B00;
extern f32 lbl_803E3B04;
extern f32 lbl_803E3B08;
extern f32 lbl_803E3B0C;
extern f32 lbl_803E3B10;
extern f32 lbl_803E3B14;
extern f32 lbl_803E3B18;
extern f32 lbl_803E3B1C;
extern f32 lbl_803E3B20;
extern f32 lbl_803E3B24;
extern f32 lbl_803E3B28;
extern f32 lbl_803E3B2C;
extern f32 lbl_803E3B30;
extern f32 lbl_803E3B34;
extern void objRenderFn_8003b8f4(f32);
extern void Obj_RemoveFromUpdateList(int obj);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern void fn_80098B18(int obj, f32 scale, int type, int a, int b, int c);
extern int cMenuGetSelectedItem(void);
extern void *getTrickyObject(void);
extern f32 lbl_803E3B70;
extern f32 lbl_803E3B78;
void flammablevine_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3AF8); }
void infopoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3B70); }
void decoration11a_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3B78); }

/* ObjGroup_RemoveObject(x, N) wrappers. */
void flammablevine_free(int x) { ObjGroup_RemoveObject(x, 0x31); }

void flammablevine_hitDetect(int obj)
{
    u8 *state;
    u8 *def;
    int hitObj;

    state = ((GameObject *)obj)->extra;
    def = *(u8 **)&((GameObject *)obj)->anim.placementData;
    if ((state[0] & 3) == 0) {
        if (ObjHits_GetPriorityHit(obj, 0, 0, &hitObj) == 0x1a) {
            if (((FlammablevinePlacement *)def)->unk1E != -1) {
                GameBit_Set(((FlammablevinePlacement *)def)->unk1E, 1);
                Sfx_PlayFromObject(0, 0x409);
            }
            *(f32 *)(state + 4) = lbl_803E3AFC;
            state[0] = state[0] | 1;
        }
    }
}

void flammablevine_init(int obj, int def)
{
    u8 *state;
    f32 scale;

    state = ((GameObject *)obj)->extra;
    ObjGroup_AddObject(obj, 0x31);
    *(s16 *)obj = (s16)((s8)*(u8 *)(def + 0x18) << 8);

    ((GameObject *)obj)->anim.rootMotionScale = lbl_803E3B20 * ((f32)((FlammablevineObjectDef *)def)->unk1A / lbl_803E3B24);
    if (((GameObject *)obj)->anim.rootMotionScale <= *(f32 *)&lbl_803E3B28) {
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E3B28;
    }

    scale = ((GameObject *)obj)->anim.rootMotionScale;
    ObjHitbox_SetCapsuleBounds(
        obj,
        (s16)(lbl_803E3B2C * scale),
        0,
        (s16)(lbl_803E3B30 * scale));
    *(f32 *)(state + 0x10) = lbl_803E3B34;
    ObjAnim_SetMoveProgress(lbl_803E3B00, (ObjAnimComponent *)obj);

    if (((FlammablevineObjectDef *)def)->unk1E != -1 && GameBit_Get(((FlammablevineObjectDef *)def)->unk1E) != 0) {
        Obj_RemoveFromUpdateList(obj);
        ObjHits_DisableObject(obj);
        ((GameObject *)obj)->anim.alpha = 0;
        state[0] = state[0] | 2;
    }

    state[1] = *(u8 *)(def + 0x19);
    if (state[1] == 1) {
        ObjHits_MarkObjectPositionDirty(obj);
    }
}

void flammablevine_update(int obj)
{
    u8 *state;
    u8 *def;
    void *tricky;
    u8 canUse;
    f32 burnTimer;
    f32 zero;
    int pulseStyle;
    u32 fadeAlpha;

    state = ((GameObject *)obj)->extra;
    def = *(u8 **)&((GameObject *)obj)->anim.placementData;
    tricky = getTrickyObject();

    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8;
    if (((FlammablevinePlacement *)def)->unk20 == -1) {
        goto can_use_vine;
    }
    if (GameBit_Get(((FlammablevinePlacement *)def)->unk20) == 0) {
        goto cant_use_vine;
    }
    if (tricky == NULL) {
        goto cant_use_vine;
    }
    if (GameBit_Get(0x245) == 0) {
        goto cant_use_vine;
    }
can_use_vine:
    canUse = 1;
    goto checked_vine_use;
cant_use_vine:
    canUse = 0;
checked_vine_use:

    if ((state[0] & 3) == 0) {
        if (state[1] == 0) {
            ObjHits_SetHitVolumeSlot(obj, 9, 1, 0);
        }
        ObjHits_EnableObject(obj);

        if (((GameObject *)obj)->anim.seqId == 0x102) {
            if (cMenuGetSelectedItem() == -1) {
                *(u8 *)(*(int *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x40) + 0x11) = 0;
            }
            else {
                *(u8 *)(*(int *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x40) + 0x11) = 0x10;
            }
        }

        if (tricky != NULL && canUse != 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~8;
            if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0) {
                ((void (*)(void *, int, int, int))(*(int *)(*(int *)(*(int *)((u8 *)tricky + 0x68)) + 0x28)))(
                    tricky, obj, 1, 4);
            }
        }
    }

    burnTimer = *(f32 *)(state + 4);
    zero = lbl_803E3B00;
    if (burnTimer > zero) {
        *(f32 *)(state + 4) = burnTimer - timeDelta;
        if (*(f32 *)(state + 4) <= zero) {
            ((GameObject *)obj)->anim.alpha = 0;
            *(f32 *)(state + 4) = zero;
            state[0] = state[0] & ~1;
            state[0] = state[0] | 2;
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
        }
    }

    if ((state[0] & 1) != 0) {
        if (*(f32 *)(state + 4) < lbl_803E3B04) {
            *(f32 *)(state + 0x10) = lbl_803E3AF8;
        }
        else {
            *(f32 *)(state + 0x10) = lbl_803E3AF8 - ((*(f32 *)(state + 4) - lbl_803E3B04) / lbl_803E3B04);
        }

        if (*(f32 *)(state + 4) < lbl_803E3B08 && *(f32 *)(state + 4) > lbl_803E3B04) {
            ObjAnim_SetMoveProgress(
                lbl_803E3AF8 - ((*(f32 *)(state + 4) - lbl_803E3B04) / lbl_803E3B0C),
                (ObjAnimComponent *)obj);
        }

        if (*(f32 *)(state + 4) < lbl_803E3B10) {
            if (*(f32 *)(state + 4) < lbl_803E3B04) {
                ((GameObject *)obj)->anim.alpha = 0;
            }
            else {
                fadeAlpha = (u8)(lbl_803E3B14 * ((*(f32 *)(state + 4) - lbl_803E3B04) / lbl_803E3B18));
                ((GameObject *)obj)->anim.alpha = fadeAlpha;
            }
        }

        *(f32 *)(state + 0xc) = *(f32 *)(state + 0xc) - timeDelta;
        if (*(f32 *)(state + 0xc) <= lbl_803E3B00) {
            pulseStyle = 3;
            *(f32 *)(state + 0xc) = *(f32 *)(state + 0xc) + lbl_803E3AF8;
        }
        else {
            pulseStyle = 0;
        }
        fn_80098B18(obj, lbl_803E3B1C * (*(f32 *)(state + 0x10) * ((GameObject *)obj)->anim.rootMotionScale), 3, 0, pulseStyle, 0);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXmv_liftloop);
    }
}

/* Fall_Ladders_free: expgfx interface freeObject callback. */
#pragma scheduling on
#pragma peephole on
void Fall_Ladders_free(int obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

/* coldwatercontrol_init: set float field + OR flag bits. */
extern f32 lbl_803E3B68;
extern f32 lbl_803E3B6C;
extern int fn_80295C40(int obj);
#pragma scheduling off
#pragma peephole off
void coldwatercontrol_update(int obj) {
    u8 *state;

    state = ((GameObject *)obj)->extra;
    if (GameBit_Get(0x1bf) != 0 && GameBit_Get(0x1bd) == 0) {
        (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
        GameBit_Set(0x1bd, 1);
        return;
    }

    if (*(void **)(state + 4) != NULL) {
        if (fn_80295C40(*(int *)(state + 4)) != 0) {
            if (lbl_803E3B68 == *(f32 *)state) {
                ObjHits_RecordObjectHit(*(int *)(state + 4), obj, 0x1c, 0, 1);
            }

            *(f32 *)state = *(f32 *)state + timeDelta;
            if (*(f32 *)state > lbl_803E3B6C) {
                ObjHits_RecordObjectHit(*(int *)(state + 4), obj, 0x1c, 1, 1);
                *(f32 *)state = *(f32 *)state - lbl_803E3B6C;
            }
        }
        else {
            *(f32 *)state = lbl_803E3B68;
        }
    }
    else {
        *(int *)(state + 4) = (int)Obj_GetPlayerObject();
    }
}

#pragma scheduling on
void coldwatercontrol_init(int obj) {
    int *p = ((int**)obj)[0xb8/4];
    *(f32*)p = lbl_803E3B68;
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x6000);
}

/* landed_arwing_free: free child object + detach link. */
extern void Obj_FreeObject(int obj);
#pragma scheduling off
void landed_arwing_free(int obj) {
    int o = obj;
    int *p = ((int**)o)[0xb8/4];
    if (*(void**)&p[0x10/4] != NULL) {
        Obj_FreeObject(p[0x10/4]);
        ObjLink_DetachChild(o, p[0x10/4]);
    }
}

/* landed_arwing_render: visible-guarded render with extra call. */
extern f32 lbl_803E3BA4;
extern void landed_arwing_renderPathEffects(int obj);
void landed_arwing_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    s32 v = visible;
    if (v != 0) {
        objRenderFn_8003b8f4(lbl_803E3BA4);
        landed_arwing_renderPathEffects(obj);
    }
}

typedef struct LandedArwingFxPoint {
    f32 scale;
    u8 pathPoint;
    u8 arg5;
    u8 arg6;
    u8 pad;
} LandedArwingFxPoint;

typedef struct LandedArwingFxScratch {
    u8 effectPos[12];
    f32 x;
    f32 y;
    f32 z;
} LandedArwingFxScratch;

typedef struct CFLandedArwingState {
    f32 unk0;
    f32 path7Fx;
    f32 path8Fx;
    f32 path6Fx;
    int childObject;
    s16 unk14;
    u8 sequenceState;
    u8 unk17;
    u8 unk18;
    u8 unk19;
    u8 enablePathFx;
    u8 unk1B;
    u8 hitStarted;
    u8 hitFlags;
    u8 unk1E;
    u8 spawnCount;
    u8 hitCooldown[4];
} CFLandedArwingState;

typedef struct LandedArwingHitFlagBits {
    u8 damaged:1;
    u8 impactHandled:1;
    u8 gameBit24Set:1;
    u8 reactionDone:1;
    u8 rest:4;
} LandedArwingHitFlagBits;

extern LandedArwingFxPoint lbl_80321A28[];
extern f32 lbl_803E3B98;
extern f32 lbl_803E3B9C;
extern void objfx_spawnMaskedHitEffect(int obj, int arg4, int arg5, int arg6, void *pos, f32 scale);
extern void objfx_spawnLightPulse(int obj, int arg4, int arg5, int arg6, void *pos, f32 scale, f32 value);

void landed_arwing_renderPathEffects(int obj) {
    CFLandedArwingState *state;
    u8 i;
    LandedArwingFxPoint *entry;
    LandedArwingFxScratch scratch;
    f32 *xPtr;
    f32 *yPtr;
    f32 *zPtr;

    state = ((GameObject *)obj)->extra;
    if (state->enablePathFx != 0) {
        i = 0;
        zPtr = &scratch.z;
        yPtr = &scratch.y;
        xPtr = &scratch.x;
        while (i < 5) {
            entry = &lbl_80321A28[i];
            ObjPath_GetPointWorldPosition(obj, entry->pathPoint, xPtr, yPtr, zPtr, 0);
            *xPtr -= ((GameObject *)obj)->anim.localPosX;
            *yPtr -= ((GameObject *)obj)->anim.localPosY;
            *zPtr -= ((GameObject *)obj)->anim.localPosZ;
            objfx_spawnMaskedHitEffect(obj, 4, entry->arg5, entry->arg6, scratch.effectPos,
                        ((GameObject *)obj)->anim.rootMotionScale * entry->scale);
            i++;
        }
    }

    if (state->path6Fx != lbl_803E3B98) {
        ObjPath_GetPointWorldPosition(obj, 6, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= ((GameObject *)obj)->anim.localPosX;
        scratch.y -= ((GameObject *)obj)->anim.localPosY;
        scratch.z -= ((GameObject *)obj)->anim.localPosZ;
        objfx_spawnLightPulse(obj, 4, 0, 0, scratch.effectPos, lbl_803E3B9C, state->path6Fx);
    }

    if (state->path8Fx != lbl_803E3B98) {
        ObjPath_GetPointWorldPosition(obj, 8, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= ((GameObject *)obj)->anim.localPosX;
        scratch.y -= ((GameObject *)obj)->anim.localPosY;
        scratch.z -= ((GameObject *)obj)->anim.localPosZ;
        objfx_spawnLightPulse(obj, 4, 0, 0, scratch.effectPos, lbl_803E3B9C, state->path8Fx);
    }

    if (state->path7Fx != lbl_803E3B98) {
        ObjPath_GetPointWorldPosition(obj, 7, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= ((GameObject *)obj)->anim.localPosX;
        scratch.y -= ((GameObject *)obj)->anim.localPosY;
        scratch.z -= ((GameObject *)obj)->anim.localPosZ;
        objfx_spawnLightPulse(obj, 4, 0, 0, scratch.effectPos, lbl_803E3B9C, state->path7Fx);
    }
}

extern void loadMapAndParent(int mapId);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int dirIdx, int locked);
extern void mapUnload(int dirIdx, int flags);
extern void setLoadedFileFlags_blocks1(void);
extern void clearLoadedFileFlags_blocks1(void);
extern void warpToMap(int mapId, int arg);
extern void unlockLevel(int a, int b, int c);
extern f32 lbl_803E3BA8;
extern f32 lbl_803E3BAC;
extern f32 lbl_803E3BB0;

#define MAP_EVENT_STATUS(mapId) (*gMapEventInterface)->getMode((mapId))
#define MAP_EVENT_SET(mapId, value) (*gMapEventInterface)->setMode((mapId), (value))
#define MAP_EVENT_OP(mapId, arg, value) (*gMapEventInterface)->setAnimEvent((mapId), (arg), (value))

int Landed_Arwing_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate) {
    int i;
    int def;
    CFLandedArwingState *state;
    int mapId;
    int child;

    def = *(int *)&((GameObject *)obj)->anim.placementData;
    state = ((GameObject *)obj)->extra;
    for (i = 0; i < animUpdate->eventCount; i++) {
        switch (animUpdate->eventIds[i]) {
            case 2:
            case 0x65:
                mapId = *(int *)(def + 0x14);
                if (mapId == 0x49f5a) {
                    loadMapAndParent(0x26);
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(0x26), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                } else if (mapId < 0x49f5a) {
                    if (mapId == 0x451b9) {
                        if (MAP_EVENT_STATUS(0xd) == 2) {
                            loadMapAndParent(0xb);
                            unlockLevel(0, 0, 1);
                            lockLevel(mapGetDirIdx(0xb), 0);
                        } else {
                            loadMapAndParent(0x29);
                            unlockLevel(0, 0, 1);
                            lockLevel(mapGetDirIdx(0x29), 0);
                        }
                    } else if (mapId == 0x43775) {
                        loadMapAndParent(0x29);
                        unlockLevel(0, 0, 1);
                        lockLevel(mapGetDirIdx(0x29), 0);
                    } else {
                        loadMapAndParent(0x29);
                        unlockLevel(0, 0, 1);
                        lockLevel(mapGetDirIdx(0x29), 0);
                    }
                } else if (mapId == 0x4cd65) {
                    loadMapAndParent(0x41);
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(0x41), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                } else {
                    loadMapAndParent(0x29);
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(0x29), 0);
                }
                break;
            case 3:
            case 0x64:
                mapId = ((LandedArwingPlacement *)def)->unk14;
                if (mapId == 0x49f5a) {
                    MAP_EVENT_OP(0xb, 4, 0);
                } else if (mapId < 0x49f5a) {
                    if (mapId == 0x451b9) {
                        if (MAP_EVENT_STATUS(0xd) == 2) {
                            unlockLevel(0, 0, 1);
                            mapUnload(mapGetDirIdx(0xd), 0x3f3f);
                            MAP_EVENT_OP(0xd, 0xa, 0);
                            MAP_EVENT_OP(0xd, 0xb, 0);
                            MAP_EVENT_OP(0xd, 0xe, 0);
                        }
                    } else if (mapId == 0x43775) {
                        unlockLevel(0, 0, 1);
                        mapUnload(mapGetDirIdx(7), 0x3f3c);
                    }
                } else if (mapId == 0x4cd65) {
                    unlockLevel(0, 0, 1);
                    mapUnload(mapGetDirIdx(0xb), 0x3f00);
                }
                break;
            case 5:
                mapId = ((LandedArwingPlacement *)def)->unk14;
                if (mapId == 0x451b9) {
                    if (MAP_EVENT_STATUS(0xd) == 2) {
                        setLoadedFileFlags_blocks1();
                    }
                } else if (mapId < 0x451b9) {
                    if (mapId == 0x43775) {
                        setLoadedFileFlags_blocks1();
                    }
                } else if (mapId == 0x49f5a) {
                    setLoadedFileFlags_blocks1();
                }
                break;
            case 6:
                mapId = ((LandedArwingPlacement *)def)->unk14;
                if (mapId == 0x451b9) {
                    if (MAP_EVENT_STATUS(0xd) == 2) {
                        clearLoadedFileFlags_blocks1();
                    }
                } else if (mapId < 0x451b9) {
                    if (mapId == 0x43775) {
                        clearLoadedFileFlags_blocks1();
                    }
                } else if (mapId == 0x49f5a) {
                    clearLoadedFileFlags_blocks1();
                }
                break;
            case 7:
            case 0x66:
                mapId = ((LandedArwingPlacement *)def)->unk14;
                if (mapId == 0x49f5a) {
                    warpToMap(0x32, 0);
                } else if (mapId < 0x49f5a) {
                    if (mapId == 0x451b9) {
                        if (MAP_EVENT_STATUS(0xd) == 2) {
                            MAP_EVENT_SET(0xb, 5);
                            warpToMap(0x4e, 0);
                        }
                    }
                } else if (mapId == 0x4cd65) {
                    warpToMap(0x7f, 0);
                    MAP_EVENT_SET(0x41, 2);
                }
                break;
            case 0xa:
                state->enablePathFx = 1;
                break;
            case 0xb:
                state->enablePathFx = 0;
                break;
            case 0xc:
                state->path7Fx = lbl_803E3B98;
                break;
            case 0xd:
                state->path7Fx = lbl_803E3BA8;
                break;
            case 0xe:
                state->path7Fx = lbl_803E3BAC;
                break;
            case 0xf:
                state->path7Fx = lbl_803E3BB0;
                break;
            case 0x10:
                state->path8Fx = lbl_803E3B98;
                break;
            case 0x11:
                state->path8Fx = lbl_803E3BA8;
                break;
            case 0x12:
                state->path8Fx = lbl_803E3BAC;
                break;
            case 0x13:
                state->path8Fx = lbl_803E3BB0;
                break;
            case 0x14:
                state->path6Fx = lbl_803E3B98;
                break;
            case 0x15:
                state->path6Fx = lbl_803E3BA8;
                break;
            case 0x16:
                state->path6Fx = lbl_803E3BAC;
                break;
            case 0x17:
                state->path6Fx = lbl_803E3BB0;
                break;
            case 0x18:
                child = state->childObject;
                if (child != 0) {
                    *(u16 *)(child + 6) &= 0xbfff;
                }
                break;
            case 0x19:
                child = state->childObject;
                if (child != 0) {
                    *(u16 *)(child + 6) |= 0x4000;
                }
                break;
        }
    }
    return 0;
}

extern void fn_8022F270(int obj, int arg);
extern void fn_8022F27C(int obj);
extern int fn_802972A8(int obj);
extern u8 fn_8012DDA4(void);
extern void cutSceneFn_8011dd30(void);
extern f32 lbl_803E3BA0;

void landed_arwing_update(int obj) {
    CFLandedArwingState *state;
    int player;
    int child;
    int nearest;
    int def;

    state = ((GameObject *)obj)->extra;
    player = (int)Obj_GetPlayerObject();
    if ((u32)state->childObject == 0) {
        if (Obj_IsLoadingLocked() != 0) {
            child = Obj_SetupObject(Obj_AllocObjectSetup(0x24, 0x606), 4, -1, -1, 0);
            state->childObject = child;
            if ((u32)state->childObject != 0) {
                ObjLink_AttachChild(obj, state->childObject, 0);
                fn_8022F270(state->childObject, 0xaf);
                *(s16 *)(state->childObject + 6) |= 0x4000;
            }
        }
    }

    if ((u32)state->childObject != 0) {
        fn_8022F27C(state->childObject);
    }

    if ((u32)player != 0 && (u32)fn_802972A8(player) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x10;
    }

    switch (state->sequenceState) {
        case 0:
            if (ObjTrigger_IsSet(obj) != 0) {
                def = *(int *)&((GameObject *)obj)->anim.placementData;
                nearest = ObjGroup_FindNearestObject(0xf, obj, NULL);
                if (((GameObject *)obj)->anim.mapEventSlot == 0xd && GameBit_Get(0xc92) != 0) {
                    *(f32 *)(nearest + 0x10) += lbl_803E3BA0;
                    (*gObjectTriggerInterface)->runSequence(2, (void *)nearest, -1);
                } else {
                    (*gObjectTriggerInterface)->runSequence(1, (void *)nearest, -1);
                }
                GameBit_Set(*(s16 *)(def + 0x1c), 0);
            }
            break;
        case 1:
            if (ObjTrigger_IsSet(obj) != 0) {
                state->sequenceState = 2;
                cutSceneFn_8011dd30();
            }
            ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f, state);
            break;
        case 2:
            if (fn_8012DDA4() != 0) {
                def = *(int *)&((GameObject *)obj)->anim.placementData;
                nearest = ObjGroup_FindNearestObject(0xf, obj, NULL);
                if (((GameObject *)obj)->anim.mapEventSlot == 0xd && GameBit_Get(0xc92) != 0) {
                    *(f32 *)(nearest + 0x10) += lbl_803E3BA0;
                    (*gObjectTriggerInterface)->runSequence(2, (void *)nearest, -1);
                } else {
                    (*gObjectTriggerInterface)->runSequence(1, (void *)nearest, -1);
                }
                GameBit_Set(*(s16 *)(def + 0x1c), 0);
            } else {
                state->sequenceState = 1;
            }
            break;
    }
}

/* infopoint_update: if low bit on 0xaf, disable button + vtable[0x48]. */
extern void buttonDisable(int p1, int mask);
void infopoint_update(int obj) {
    if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0) {
        buttonDisable(0, 0x100);
        (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
    }
}

/* landed_arwing_init: flag bits, counter, conditional unlock, set callback. */
void landed_arwing_init(int obj, int param) {
    int *p = ((int**)obj)[0xb8/4];
    ((GameObject *)obj)->objectFlags = ((GameObject *)obj)->objectFlags | 0x2000;
    *(s8*)((char*)p + 0x16) = 1;
    if (GameBit_Get(*(s16*)((char*)param + 0x1c)) == 0) {
        unlockLevel(0, 0, 1);
    }
    ((GameObject *)obj)->animEventCallback = (void *)Landed_Arwing_SeqFn;
}

extern f32 lbl_803E3BB8;
extern f32 lbl_803E3BBC;
extern f32 lbl_803E3BC0;
extern f32 lbl_803E3BC4;
extern int *objFindTexture(int obj, int textureIndex, int materialIndex);

/* landed arwing hit/animation step: handles impact reactions and spawned debris. */
void landed_arwing_updateHitReaction(int obj, CFLandedArwingState *state) {
    int def;
    int i;
    int setup;
    int other;
    CFLandedArwingState *otherState;
    f32 range;
    f32 yOffset;
    u8 animScratch[0x34];

    def = *(int *)&((GameObject *)obj)->anim.placementData;
    if (((state->hitFlags >> 7) & 1) != 0) {
        if (((state->hitFlags >> 6) & 1) != 0 && state->hitStarted == 0) {
            return;
        }
        if (state->hitStarted != 0) {
            ((GameObject *)obj)->anim.rotY = 0;
            ((GameObject *)obj)->anim.rotZ = 0;
            if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E3BBC && ((state->hitFlags >> 4) & 1) == 0) {
                if (((LandedArwingUpdateHitReactionPlacement *)def)->unk24 > 0) {
                    GameBit_Set(((LandedArwingUpdateHitReactionPlacement *)def)->unk24, 1);
                }

                switch (*(u8 *)(def + 0x1e)) {
                    case 0:
                        if (Obj_IsLoadingLocked() != 0) {
                            yOffset = lbl_803E3BB8;
                            for (i = 0; i < *(u8 *)(def + 0x1f); i++) {
                                setup = Obj_AllocObjectSetup(0x24, 0x259);
                                ((ObjPlacement *)setup)->posX = ((GameObject *)obj)->anim.localPosX;
                                ((ObjPlacement *)setup)->posY = ((GameObject *)obj)->anim.localPosY + yOffset;
                                ((ObjPlacement *)setup)->posZ = ((GameObject *)obj)->anim.localPosZ;
                                *(u8 *)(setup + 4) = 1;
                                Obj_SetupObject(setup, 5, ((GameObject *)obj)->anim.mapEventSlot, -1,
                                                *(int *)&((GameObject *)obj)->anim.parent);
                            }
                        }
                        break;
                    case 1:
                        range = lbl_803E3BC0;
                        other = ObjGroup_FindNearestObject(0x41, obj, &range);
                        if (other != 0) {
                            otherState = ((GameObject *)other)->extra;
                            if (*(s16 *)(*(int *)&((GameObject *)other)->anim.placementData + 0x22) > 0) {
                                GameBit_Set(*(s16 *)(*(int *)&((GameObject *)other)->anim.placementData + 0x22), 1);
                            }
                            otherState->hitFlags = otherState->hitFlags & 0x7f | 0x80;
                        }
                        break;
                }
                state->hitStarted = 0;
                state->hitFlags = state->hitFlags & 0xef | 0x10;
            }
            state->hitFlags = state->hitFlags & 0xbf | 0x40;
            state->path8Fx = lbl_803E3BC4;
        } else {
            if (*(u8 *)(def + 0x1e) == 2) {
                ((GameObject *)obj)->anim.rotY = (s16)randomGetRange(-200, 200);
                ((GameObject *)obj)->anim.rotZ = (s16)randomGetRange(-200, 200);
            }
            ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f,
                                                      state->hitCooldown);
        }
        ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, state->path8Fx, timeDelta,
                                   (ObjAnimEventList *)animScratch);
    }
}

/* landed arwing material flags: mirrors game bits into the damaged texture state. */
void landed_arwing_updateDamageTexture(int obj, CFLandedArwingState *state) {
    int def;
    int *texture;
    u32 bit;
    LandedArwingHitFlagBits *flags;

    def = *(int *)&((GameObject *)obj)->anim.placementData;
    flags = (LandedArwingHitFlagBits *)&state->hitFlags;
    if (((LandedArwingUpdateDamageTexturePlacement *)def)->unk24 != -1) {
        bit = GameBit_Get(((LandedArwingUpdateDamageTexturePlacement *)def)->unk24);
        flags->gameBit24Set = bit;
        bit = flags->gameBit24Set;
        if (bit != 0 && *(u8 *)(def + 0x1c) == 5) {
            flags->impactHandled = 1;
        } else if (bit == 0) {
            flags->impactHandled = 0;
        }
    }

    if (flags->damaged == 0) {
        if (((LandedArwingUpdateDamageTexturePlacement *)def)->unk22 != -1 && GameBit_Get(((LandedArwingUpdateDamageTexturePlacement *)def)->unk22) != 0) {
            flags->damaged = 1;
        }
    } else {
        if (((LandedArwingUpdateDamageTexturePlacement *)def)->unk22 != -1 && GameBit_Get(((LandedArwingUpdateDamageTexturePlacement *)def)->unk22) == 0) {
            flags->damaged = 0;
        }
    }

    texture = objFindTexture(obj, 0, 0);
    if (texture != NULL) {
        if (flags->damaged != 0) {
            if (flags->gameBit24Set != 0) {
                *texture = 0x200;
            } else {
                *texture = 0x100;
            }
        } else {
            *texture = 0;
        }
    }
}

#define gCarryableInterface lbl_803DCAC0
void dll_109_init(int obj, u8 *p) {
    *(s16 *)obj = (s16)((s32)p[0x1a] << 8);
    ((GameObject *)obj)->objectFlags |= 0x2000;
    (*(void (*)(int, int *, int))(*(int *)(*gCarryableInterface + 0x4)))(obj, ((GameObject *)obj)->extra, 0x21);
    (*(void (*)(int *, int))(*(int *)(*gCarryableInterface + 0x2c)))(((GameObject *)obj)->extra, 1);
}

#pragma dont_inline on
#pragma peephole on
void decoration11a_expandBoundsWithVertex(f32 *vertex, f32 *maxOut, f32 *minOut) {
    f32 v;
    v = vertex[0]; if (v > maxOut[0]) maxOut[0] = v; else if (v < minOut[0]) minOut[0] = v;
    v = vertex[1]; if (v > maxOut[1]) maxOut[1] = v; else if (v < minOut[1]) minOut[1] = v;
    v = vertex[2]; if (v > maxOut[2]) maxOut[2] = v; else if (v < minOut[2]) minOut[2] = v;
}
#pragma dont_inline reset

int InfoPoint_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate) {
    s16 *inner = ((GameObject *)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++) {
        switch (animUpdate->eventIds[i]) {
            case 1: inner[0xb] = (s16)0xff; break;
            case 2: inner[0xb] = 0; break;
            case 5: break;
        }
    }
    return 0;
}

#pragma scheduling on
void dll_109_free(int obj) {
    (*(void (*)(int))(*(int *)(*gCarryableInterface + 0x10)))(obj);
}

extern f32 lbl_803E3B40;
#pragma scheduling off
#pragma peephole off
void dll_109_render(int obj, int p1, int p2, int p3, int p4, s8 visible) {
    int *inner = ((GameObject *)obj)->extra;
    if (((Dll109State *)inner)->unkA == 0) {
        if ((*(int (*)(int, s32))(*(int *)(*gCarryableInterface + 0xc)))(obj, visible) != 0) {
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E3B40);
        }
    }
}

extern void Obj_SetActiveModelIndex(int *obj, int idx);
extern f64 lbl_803E3B60;
extern f32 lbl_803E3B50;
extern f32 lbl_803E3B54;
extern f32 lbl_803E3B58;
extern f32 lbl_803E3B5C;

void Fall_Ladders_update(int obj) {
    int def;
    FallLaddersState *state;
    f32 speed;

    def = *(int *)&((GameObject *)obj)->anim.placementData;
    state = ((GameObject *)obj)->extra;
    if (((GameObject *)obj)->anim.seqId == 0x548) {
        if (GameBit_Get(state->upperGameBit) != 0 && GameBit_Get(state->lowerGameBit) == 0) {
            (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
        }
        if (GameBit_Get(state->upperGameBit) == 0 && GameBit_Get(state->lowerGameBit) != 0) {
            (*gObjectTriggerInterface)->runSequence(1, (void *)obj, -1);
        }
    } else if (state->delay != 0) {
        state->delay -= (s16)timeDelta;
        if (state->delay <= 0) {
            state->motionState = 1;
            if (state->playStartSound != 0) {
                Sfx_PlayFromObject(obj, 0x4bc);
                state->playStartSound = 0;
            }
            state->delay = 0;
        }
    } else {
        if ((s8)state->motionState == 0 && GameBit_Get(state->upperGameBit) != 0) {
            state->delay = 10;
        }
        if ((s8)state->motionState == 1 && ((GameObject *)obj)->anim.localPosY >= ((ObjPlacement *)def)->posY) {
            ((GameObject *)obj)->anim.velocityY -= lbl_803E3B50;
            ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
            if (((GameObject *)obj)->anim.localPosY <= ((ObjPlacement *)def)->posY) {
                ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)def)->posY;
                ((GameObject *)obj)->anim.velocityY = lbl_803E3B54 * -((GameObject *)obj)->anim.velocityY;
                speed = ((GameObject *)obj)->anim.velocityY;
                if (speed < lbl_803E3B58) {
                    speed = -speed;
                }
                if (speed < lbl_803E3B5C) {
                    state->motionState = 2;
                }
            }
        }
    }
}

void Fall_Ladders_init(int *obj, s8 *def) {
    s16 *state = ((GameObject *)obj)->extra;
    *(s16 *)obj = (s16)((s32)*(s8 *)((char *)def + 0x18) << 8);
    state[3] = ((FallLaddersObjectDef *)def)->unk20;
    state[2] = ((FallLaddersObjectDef *)def)->unk1E;
    *(f32 *)state = (f32)(s32)((FallLaddersObjectDef *)def)->unk1A;
    ((GameObject *)obj)->objectFlags |= 0x6000;
    ((GameObject *)obj)->animEventCallback = (void *)Fall_Ladders_SeqFn;
    ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)def)->posY + *(f32 *)state;
    Obj_SetActiveModelIndex(obj, (s32)*(s8 *)((char *)def + 0x19));
    *(u8 *)((char *)state + 8) = 0;
    if (GameBit_Get(state[3]) == 0) {
        *(u8 *)((char *)state + 9) = 1;
    }
}

extern int textureLoadAsset(int id);
extern int *gameTextGet(int id);
extern int lbl_803219A0[];
extern int lbl_80321990[];
void infopoint_init(int *obj, u8 *def) {
    u8 *state = ((GameObject *)obj)->extra;
    int *txt;
    ((GameObject *)obj)->animEventCallback = (void *)InfoPoint_SeqFn;
    if (*(void **)lbl_803219A0 == NULL) {
        *(int *)lbl_803219A0 = textureLoadAsset(616);
    }
    *(int *)(state + 8) = (int)lbl_80321990;
    txt = gameTextGet(((InfopointObjectDef *)def)->unk18);
    *(int *)(state + 4) = **(int **)((char *)txt + 8);
    *(int *)(state + 0xc) = 100;
    *(int *)state = (int)txt;
    *(s16 *)obj = (s16)((s32)*(u8 *)((char *)def + 0x1c) << 8);
    *(int *)(state + 0x18) = 2;
    *(u8 *)(state + 0x10) = ((InfopointObjectDef *)def)->unk1B;
    *(s16 *)(state + 0x16) = 0;
    ((GameObject *)obj)->objectFlags |= 0x2000;
}

extern f32 lbl_803E3B7C;
extern f64 lbl_803E3B80;
extern f32 lbl_803E3B88;
extern f64 lbl_803E3B90;
extern f32 Vec_distance(f32 *a, f32 *b);
extern void objWorldToLocalPos(f32 *out, int obj, f32 *pos);
extern void Model_GetVertexPosition(int *model, int idx, f32 *out);
extern void PSVECScale(f32 *dst, f32 *src, f32 s);
extern f32 PSVECMag(f32 *v);

void decoration11a_hitDetect(int obj) {
    s16 modelId;
    f32 *state;
    int count;
    int *objects;
    f32 radius;
    f32 localPos[3];
    f32 delta;
    f32 xSq;
    f32 ySq;
    f32 zSq;

    modelId = ((GameObject *)obj)->anim.seqId;
    if (modelId == 0x7a1) {
        goto check_decor_objects;
    }
    if (modelId == 0x7a2) {
        goto check_decor_objects;
    }
    if (modelId != 0x7a3) {
        return;
    }

check_decor_objects:
    state = ((GameObject *)obj)->extra;
    objects = ObjGroup_GetObjects(2, &count);
    while (count != 0) {
        if (Vec_distance((f32 *)(*objects + 0x18), (f32 *)(obj + 0x18)) < state[6]) {
            if (*(void **)(*objects + 0x54) != NULL) {
                radius = (f32)*(s16 *)(*(int *)(*objects + 0x54) + 0x5a);
                objWorldToLocalPos(localPos, obj, (f32 *)(*objects + 0xc));

                if (localPos[0] < state[3]) {
                    delta = localPos[0] - state[3];
                    xSq = delta * delta;
                }
                else if (localPos[0] > state[0]) {
                    delta = localPos[0] - state[0];
                    xSq = delta * delta;
                }
                else {
                    xSq = lbl_803E3B7C;
                }

                if (localPos[1] < state[4]) {
                    delta = localPos[1] - state[4];
                    ySq = delta * delta;
                }
                else if (localPos[1] > state[1]) {
                    delta = localPos[1] - state[1];
                    ySq = delta * delta;
                }
                else {
                    ySq = lbl_803E3B7C;
                }

                if (localPos[2] < state[5]) {
                    delta = localPos[2] - state[5];
                    zSq = delta * delta;
                }
                else if (localPos[2] > state[2]) {
                    delta = localPos[2] - state[2];
                    zSq = delta * delta;
                }
                else {
                    zSq = lbl_803E3B7C;
                }

                if (lbl_803E3B7C + xSq + ySq + zSq < radius * radius) {
                    (*(ObjHitsPriorityState **)(*objects + 0x54))->lastHitObject = obj;
                    (*(ObjHitsPriorityState **)(*objects + 0x54))->contactFlags = 1;
                }
            }
        }
        count--;
        objects++;
    }
}

void decoration11a_init(int *obj, u8 *def) {
    ((GameObject *)obj)->anim.rotZ = (s16)((s32)def[24] << 8);
    ((GameObject *)obj)->anim.rotY = (s16)((s32)def[25] << 8);
    *(s16 *)obj = (s16)((s32)def[26] << 8);
    if (def[27] != 0) {
        ((GameObject *)obj)->anim.rootMotionScale = (f32)(u32)def[27] / lbl_803E3B88;
        if (((GameObject *)obj)->anim.rootMotionScale == lbl_803E3B7C) {
            ((GameObject *)obj)->anim.rootMotionScale = lbl_803E3B78;
        }
        ((GameObject *)obj)->anim.rootMotionScale = ((GameObject *)obj)->anim.rootMotionScale * *(f32 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 4);
    }
    {
        s16 model = ((GameObject *)obj)->anim.seqId;
        if (model == 1953) {
            goto calc_decor_bounds;
        }
        if (model == 1954) {
            goto calc_decor_bounds;
        }
        if (model == 1955) {
calc_decor_bounds:
        {
            int i;
            int *m;
            f32 *state;
            f32 tmp[3];
            f32 magB;
            f32 maxMag;

            state = ((GameObject *)obj)->extra;
            m = **(int ***)(*(int *)&((GameObject *)obj)->anim.banks);
            Model_GetVertexPosition(m, 0, state);
            Model_GetVertexPosition(m, 0, state + 3);
            for (i = 1; i < *(u16 *)((char *)m + 0xe4); i++) {
                Model_GetVertexPosition(m, i, tmp);
                decoration11a_expandBoundsWithVertex(tmp, state, state + 3);
            }
            PSVECScale(state, state, ((GameObject *)obj)->anim.rootMotionScale);
            PSVECScale(state + 3, state + 3, ((GameObject *)obj)->anim.rootMotionScale);
            magB = PSVECMag(state + 3);
            if (PSVECMag(state) > magB) {
                maxMag = PSVECMag(state);
            } else {
                maxMag = PSVECMag(state + 3);
            }
            state[6] = maxMag;
        }
        }
    }
}
