#include "main/dll/cfguardian_state.h"
#include "ghidra_import.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "global.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"
#include "main/objseq.h"

extern undefined4 getLActions();
extern undefined4 FUN_80006728();
extern undefined4 FUN_800067c0();
extern bool FUN_800067f0();
extern undefined8 FUN_8000680c();
extern undefined4 FUN_80006814();
extern undefined8 FUN_80006824();
extern undefined8 FUN_800069bc();
extern int FUN_80006a10();
extern undefined4 FUN_80006ba8();
extern undefined4 FUN_80017520();
extern int FUN_80017524();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175ec();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a40();
extern undefined4 FUN_80017a78();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ad0();
extern int FUN_80017b00();
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined8 ObjMsg_SendToObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern bool ObjTrigger_UpdateIdBlockFlag(int obj);
extern undefined4 ObjLink_DetachChild();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointWorldPosition();
extern int Obj_GetYawDeltaToObject();
extern undefined4 objAnimFn_80038f38();
extern undefined4 FUN_800392ec();
extern undefined4 FUN_80039468();
extern undefined4 FUN_8003964c();
extern undefined4 FUN_8003add8();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern void objRenderFn_8003b8f4(f32);
extern int FUN_80057690();
extern int FUN_800620e8();
extern int FUN_800632e8();
extern undefined4 FUN_8006f7a0();
extern int FUN_8007f56c();
extern undefined4 FUN_8007f5ec();
extern uint FUN_8007f66c();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f6e4();
extern undefined4 FUN_8007f718();
extern int FUN_8007f764();
extern int FUN_8007f924();
extern undefined4 FUN_80080f8c();
extern int FUN_800810ac();
extern undefined4 FUN_800810e8();
extern undefined4 FUN_80081110();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_801141e8();
extern undefined4 FUN_80114274();
extern undefined4 FUN_80114340();
extern int FUN_801145b0();
extern int FUN_801149b8();
extern undefined4 FUN_801149bc();
extern undefined4 FUN_80114b10();
extern undefined4 dll_2E_func03();
extern undefined4 FUN_801150a4();
extern undefined4 FUN_801150ac();
extern undefined4 FUN_8014ccac();
extern int FUN_8020a468();
extern int FUN_8020a490();
extern undefined4 FUN_8020a494();
extern undefined4 FUN_8020a4a4();
extern undefined4 FUN_8020a4ac();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double FUN_802480e8();
extern undefined4 FUN_80286830();
extern uint FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern byte FUN_80294c20();
extern double FUN_80294c6c();
extern undefined4 FUN_80294c74();
extern int FUN_80294d38();
extern undefined4 FUN_80294d40();
extern int FUN_80294d6c();
extern uint countLeadingZeros();

extern undefined4 DAT_802c2a40;
extern undefined4 DAT_802c2a44;
extern undefined4 DAT_802c2a48;
extern undefined4 DAT_802c2a4c;
extern undefined4 DAT_802c2a50;
extern undefined4 DAT_802c2a54;
extern undefined4 DAT_802c2a58;
extern undefined4 DAT_802c2a5c;
extern undefined4 DAT_802c2a60;
extern undefined4 DAT_802c2a64;
extern undefined4 DAT_8032349c;
extern undefined4 DAT_803235a4;
extern undefined4 DAT_80323698;
extern undefined4 DAT_803236b8;
extern undefined4 DAT_80323778;
extern undefined4 DAT_80323888;
extern undefined4 DAT_8032388c;
extern undefined4 DAT_80323890;
extern undefined4 DAT_803dc070;
extern undefined4 gScreensInterface;
extern WaterfxInterface **gWaterfxInterface;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern undefined4* DAT_803dd6e8;
extern EffectInterface **gPartfxInterface;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd740;
extern undefined4 DAT_803de790;
extern f64 DOUBLE_803e4db0;
extern f64 DOUBLE_803e4df8;
extern f64 DOUBLE_803e4e58;
extern f64 DOUBLE_803e4ea0;
extern f64 DOUBLE_803e4eb8;
extern f64 DOUBLE_803e4f08;
extern f64 DOUBLE_803e4f10;
extern f64 DOUBLE_803e4f28;
extern f64 DOUBLE_803e4f40;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 gTitleMenuLinkInterface;
extern f32 gTitleMenuItemInterface;
extern f32 gMapEventInterface;
extern f32 lbl_803DCAB4;
extern f32 lbl_803DCAC0;
extern f32 lbl_803DCAC4;
extern f32 lbl_803E4228;
extern f32 lbl_803E4DA8;
extern f32 lbl_803E4DB8;
extern f32 lbl_803E4DBC;
extern f32 lbl_803E4DC0;
extern f32 lbl_803E4DC4;
extern f32 lbl_803E4DC8;
extern f32 lbl_803E4DCC;
extern f32 lbl_803E4DD0;
extern f32 lbl_803E4DD4;
extern f32 lbl_803E4DD8;
extern f32 lbl_803E4DDC;
extern f32 lbl_803E4DE0;
extern f32 lbl_803E4DE4;
extern f32 lbl_803E4DE8;
extern f32 lbl_803E4DEC;
extern f32 lbl_803E4DF0;
extern f32 lbl_803E4DF4;
extern f32 lbl_803E4E00;
extern f32 lbl_803E4E04;
extern f32 lbl_803E4E08;
extern f32 lbl_803E4E0C;
extern f32 lbl_803E4E10;
extern f32 lbl_803E4E14;
extern f32 lbl_803E4E18;
extern f32 lbl_803E4E1C;
extern f32 lbl_803E4E20;
extern f32 lbl_803E4E24;
extern f32 lbl_803E4E28;
extern f32 lbl_803E4E2C;
extern f32 lbl_803E4E30;
extern f32 lbl_803E4E34;
extern f32 lbl_803E4E38;
extern f32 lbl_803E4E3C;
extern f32 lbl_803E4E40;
extern f32 lbl_803E4E44;
extern f32 lbl_803E4E48;
extern f32 lbl_803E4E4C;
extern f32 lbl_803E4E50;
extern f32 lbl_803E4E54;
extern f32 lbl_803E4E60;
extern f32 lbl_803E4E64;
extern f32 lbl_803E4E70;
extern f32 lbl_803E4E74;
extern f32 lbl_803E4E78;
extern f32 lbl_803E4E7C;
extern f32 lbl_803E4E80;
extern f32 lbl_803E4E84;
extern f32 lbl_803E4E88;
extern f32 lbl_803E4E8C;
extern f32 lbl_803E4E90;
extern f32 lbl_803E4E94;
extern f32 lbl_803E4E98;
extern f32 lbl_803E4E9C;
extern f32 lbl_803E4EB0;
extern f32 lbl_803E4EC4;
extern f32 lbl_803E4EC8;
extern f32 lbl_803E4ECC;
extern f32 lbl_803E4ED0;
extern f32 lbl_803E4ED4;
extern f32 lbl_803E4ED8;
extern f32 lbl_803E4EDC;
extern f32 lbl_803E4EE0;
extern f32 lbl_803E4EE4;
extern f32 lbl_803E4EE8;
extern f32 lbl_803E4EEC;
extern f32 lbl_803E4EF0;
extern f32 lbl_803E4EF8;
extern f32 lbl_803E4EFC;
extern f32 lbl_803E4F00;
extern f32 lbl_803E4F18;
extern f32 lbl_803E4F1C;
extern f32 lbl_803E4F24;
extern f32 lbl_803E4F30;
extern f32 lbl_803E4F38;
extern f32 lbl_803E4F3C;
extern f32 lbl_803E4F4C;
extern f32 lbl_803E4F58;
extern f32 lbl_803E4F5C;
extern f32 lbl_803E4F60;
extern f32 lbl_803E4F64;
extern f32 lbl_803E4F68;
extern f32 lbl_803E4F6C;
extern f32 lbl_803E4F70;
extern f32 lbl_803E4F74;

/*
 * --INFO--
 *
 * Function: FUN_8019b1d8
 * EN v1.0 Address: 0x8019B1D8
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x8019B3B8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b1d8(undefined4 param_1,undefined4 param_2,ushort *param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar4 >> 0x20);
  iVar2 = 0;
  for (iVar3 = 0; iVar3 < *(char *)((int)uVar4 + 0x1b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)((int)uVar4 + iVar3 + 0x13)) {
    case 0:
      if (param_3 != (ushort *)0x0) {
        FUN_80006824(uVar1,*param_3);
      }
      break;
    case 1:
      iVar2 = 1;
      break;
    case 2:
      iVar2 = 2;
      break;
    case 3:
      iVar2 = 3;
      break;
    case 4:
      iVar2 = 4;
      break;
    case 7:
      if (param_3 != (ushort *)0x0) {
        FUN_80006824(uVar1,param_3[1]);
      }
      break;
    case 9:
      FUN_80006824(uVar1,SFXsk_trwhin3);
    }
  }
  if ((iVar2 != 0) && (param_3 != (ushort *)0x0)) {
    FUN_80006824(uVar1,param_3[2]);
  }
  FUN_8028688c();
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_8019b2e0
 * EN v1.0 Address: 0x8019B2E0
 * EN v1.0 Size: 680b
 * EN v1.1 Address: 0x8019B754
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b2e0(double param_1,short *param_2,short *param_3,float *param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9)
{
  int iVar1;
  short sVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  
  if (param_3 == (short *)0x0) {
    uVar3 = 0;
  }
  else {
    local_50[0] = *(float *)(param_3 + 6) - *(float *)(param_2 + 6);
    dVar6 = (double)local_50[0];
    local_54 = *(float *)(param_3 + 8) - *(float *)(param_2 + 8);
    local_58 = *(float *)(param_3 + 10) - *(float *)(param_2 + 10);
    dVar4 = FUN_80293900((double)(local_58 * local_58 + (float)(dVar6 * dVar6) + local_54 * local_54
                                 ));
    if ((double)(float)((double)lbl_803E4DBC * param_1) <= dVar4) {
      FUN_8006f7a0(local_50,&local_54,&local_58);
      *(float *)(param_2 + 0x12) = lbl_803DC074 * (float)((double)local_50[0] * param_1);
      *(float *)(param_2 + 0x14) = lbl_803DC074 * (float)((double)local_54 * param_1);
      *(float *)(param_2 + 0x16) = lbl_803DC074 * (float)((double)local_58 * param_1);
      sVar2 = (*param_3 + -0x8000) - *param_2;
      if (0x8000 < sVar2) {
        sVar2 = sVar2 + 1;
      }
      if (sVar2 < -0x8000) {
        sVar2 = sVar2 + -1;
      }
      uStack_44 = (int)*param_2 ^ 0x80000000;
      local_48 = 0x43300000;
      uStack_3c = (int)sVar2 ^ 0x80000000;
      local_40 = 0x43300000;
      iVar1 = (int)((f32)(s32)uStack_44 +
                   (float)((double)((lbl_803E4DC0 +
                                    (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4db0
                                           )) * (float)(param_1 * (double)lbl_803DC074)) / dVar4))
      ;
      local_38 = (longlong)iVar1;
      *param_2 = (short)iVar1;
      dVar4 = (double)*(float *)(param_2 + 0x14);
      dVar5 = (double)*(float *)(param_2 + 0x16);
      FUN_80017a88((double)*(float *)(param_2 + 0x12),dVar4,dVar5,(int)param_2);
      if (param_2[0x50] != 0x1a) {
        FUN_800305f8((double)lbl_803E4DA8,dVar4,dVar5,dVar6,in_f5,in_f6,in_f7,in_f8,param_2,0x1a,0
                     ,param_5,param_6,param_7,param_8,param_9);
      }
      FUN_8002f6ac(param_1,(int)param_2,param_4);
      uVar3 = 0;
    }
    else {
      uVar3 = 1;
    }
  }
  return uVar3;
}


/*
 * --INFO--
 *
 * Function: FUN_8019b650
 * EN v1.0 Address: 0x8019B650
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8019BA44
 * EN v1.1 Size: 3800b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b650(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
            undefined4 param_10,undefined4 param_11,float *param_12,int param_13,undefined4 param_14
            ,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b658
 * EN v1.0 Address: 0x8019B658
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x8019C91C
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019b658(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  int iVar2;
  float *pfVar3;
  undefined4 *puVar4;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  pfVar3 = ((GameObject *)param_9)->extra;
  local_28 = DAT_802c2a58;
  local_24 = DAT_802c2a5c;
  local_20 = DAT_802c2a60;
  local_1c = DAT_802c2a64;
  if (((GameObject *)param_9)->unkB4 < 0) {
    FUN_800e8630(param_9);
    uVar1 = 0;
  }
  else {
    if (*(char *)(pfVar3 + 0x2a0) == '\x06') {
      puVar4 = &local_20;
    }
    else {
      puVar4 = &local_28;
    }
    iVar2 = FUN_8007f924(param_11);
    if ((iVar2 == 0x283) ||
       (iVar2 = FUN_801149b8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                             ,param_11,pfVar3,(short)*puVar4,(short)puVar4[1],param_14,param_15,
                             param_16), iVar2 == 0)) {
      if (*(char *)(param_11 + 0x80) == '\x02') {
        iVar2 = FUN_80017a98();
        FUN_80294d40(iVar2,10);
      }
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  return uVar1;
}


/*
 * --INFO--
 *
 * Function: FUN_8019c318
 * EN v1.0 Address: 0x8019C318
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x8019DAF4
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019c318(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,int param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  uint local_28;
  uint local_24;
  uint local_20 [4];
  
  psVar3 = ((GameObject *)param_9)->extra;
  local_28 = 0;
  while (iVar1 = ObjMsg_Pop(param_9,&local_24,local_20,&local_28), iVar1 != 0) {
    if (local_24 == 0x110001) {
      if ((*psVar3 == 0x54) && (0xaf < *(short *)(param_11 + 0x58))) {
        ObjMsg_SendToObject(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_20[0],
                     0x110001,param_9,0,param_13,param_14,param_15,param_16);
      }
    }
    else if ((int)local_24 < 0x110001) {
      if (local_24 == 0xa0005) {
        param_1 = FUN_80017698((int)*psVar3,1);
      }
    }
    else if (local_24 == 0x110003) {
      if ((*psVar3 == 0x56) && (0xaf < *(short *)(param_11 + 0x58))) {
        ObjMsg_SendToObject(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_20[0],
                     0x110003,param_9,0,param_13,param_14,param_15,param_16);
      }
    }
    else if ((((int)local_24 < 0x110003) && (*psVar3 == 0x55)) &&
            (0xaf < *(short *)(param_11 + 0x58))) {
      ObjMsg_SendToObject(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_20[0],
                   0x110002,param_9,0,param_13,param_14,param_15,param_16);
    }
  }
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar1 = iVar1 + 1) {
    if (((*(char *)(param_11 + iVar1 + 0x81) == '\x01') && (uVar2 = FUN_80017690(0x54), uVar2 != 0))
       && ((uVar2 = FUN_80017690(0x55), uVar2 != 0 && (uVar2 = FUN_80017690(0x56), uVar2 != 0)))) {
      FUN_80017698(0x4e0,1);
    }
  }
  return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_8019d238
 * EN v1.0 Address: 0x8019D238
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x8019E970
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8019d238(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)&((GameObject *)param_9)->extra;
  if ((((GameObject *)param_9)->anim.currentMove != 5) && (((GameObject *)param_9)->anim.currentMove != 0xd)) {
    FUN_800305f8((double)((GameObject *)param_9)->anim.currentMoveProgress,param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
  }
  if ((((GameObject *)param_9)->anim.currentMove == 5) && (lbl_803E4EC4 < ((GameObject *)param_9)->anim.velocityY)) {
    FUN_800305f8((double)((GameObject *)param_9)->anim.currentMoveProgress,param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
  }
  if ((((GameObject *)param_9)->anim.currentMove == 0xd) && (((GameObject *)param_9)->anim.velocityY < lbl_803E4EB0)) {
    FUN_800305f8((double)((GameObject *)param_9)->anim.currentMoveProgress,param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,5,0,param_12,param_13,param_14,param_15,param_16);
  }
  dVar2 = (double)((((GameObject *)param_9)->anim.velocityY * lbl_803DCAB4 + lbl_803E4EC8) * lbl_803E4ECC);
  if (dVar2 < (double)lbl_803E4EB0) {
    dVar2 = (double)lbl_803E4EB0;
  }
  if ((double)lbl_803E4ECC < dVar2) {
    dVar2 = (double)lbl_803E4ECC;
  }
  if (((GameObject *)param_9)->anim.currentMove == 0xd) {
    if (((GameObject *)param_9)->anim.currentMoveProgress <= lbl_803E4ECC) {
      *(byte *)(iVar1 + 0x244) = *(byte *)(iVar1 + 0x244) & 0xbf;
    }
    else if ((*(byte *)(iVar1 + 0x244) >> 6 & 1) == 0) {
      FUN_80006824(param_9,SFXand_spitout);
      *(byte *)(iVar1 + 0x244) = *(byte *)(iVar1 + 0x244) & 0xbf | 0x40;
    }
  }
  FUN_8002fc3c(dVar2,(double)lbl_803DC074);
  return 1;
}


/*
 * --INFO--
 *
 * Function: babycloudrunner_getObjectTypeId
 * EN v1.0 Address: 0x8019EBBC
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801A0A24
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void babycloudrunner_init_OLD_v1_1(int param_1)
{
  undefined4 *puVar1;

  puVar1 = ((GameObject *)param_1)->extra;
  *puVar1 = 0;
  puVar1[1] = 0;
  ObjHits_EnableObject(param_1);
  ((GameObject *)param_1)->anim.alpha = 0x80;
  return;
}

extern f32 lbl_803E422C;
extern f32 lbl_803E4244;
extern f32 lbl_803E4258;
extern u8 lbl_803DBE28;
extern u8 lbl_803DBE30;
extern void storeZeroToFloatParam(void* p);
extern uint GameBit_Get(int eventId);
extern int Obj_RemoveFromUpdateList(int *obj);

typedef struct BabyCloudrunnerFlags {
    u8 resetLatch : 1;
    u8 flags : 7;
} BabyCloudrunnerFlags;

/* Per-object extra state for the baby CloudRunner
 * (babycloudrunner_getExtraSize == 0x248). */
typedef struct BabyCloudRunnerState {
    f32 unk00;
    u8 pad04[0x38];        /* 0x18: position used for the sandworm handoff */
    u8 lookBlock[0x30];    /* 0x3c: fn_8003ADC4 head-track block */
    u8 audioBlock[0x3c];   /* 0x6c: objAudioFn block */
    f32 animSpeed;
    f32 scale;             /* 0xac: copied to the linked object's scale */
    int unkB0;
    int unkB4;
    int unkB8;
    int unkBC;
    int turnLatch;         /* 0xc0: sandworm_turnTowardTargetAnim turn/idle move latch */
    int behaviourState;    /* 0xc4: def[0x1c]; SeqFn 0..0xb dispatch */
    u8 padC8[4];
    int unkCC;
    s16 roostYaw;          /* 0xd0: heading captured at init */
    u8 padD2[0x42];
    void *linkedObj;       /* 0x114 */
    u8 pad118[0xc];
    u8 curveWalker[0x108]; /* 0x124: rom-curve follow block */
    u8 flags22C;           /* 1 = alive/active */
    u8 pad22D[3];
    int runnerState;       /* 0x230: 0 curve-seek, 1 follow, 2 chased, 3 freed */
    int runnerIndex;       /* 0x234: gamebit base index, -1 keyed off */
    f32 countdownTimer;    /* 0x238 */
    f32 curveSpeed;        /* 0x23c */
    void *mutterSfxTable;  /* 0x240 */
    u8 spitFlags;          /* 0x244: BabyCloudrunnerFlags / WormSpitByte overlay */
    u8 pad245[3];
} BabyCloudRunnerState;
STATIC_ASSERT(sizeof(BabyCloudRunnerState) == 0x248);

#pragma scheduling off
#pragma peephole off
void babycloudrunner_init(int *obj, u8 *def) {
    BabyCloudRunnerState *sub;

    ObjHits_EnableObject(obj);
    ObjMsg_AllocQueue(obj, 4);
    ((GameObject *)obj)->animEventCallback = (void *)babycloudrunner_SeqFn;
    *(s16*)obj = (s16)(def[0x1d] << 8);
    ObjGroup_AddObject(obj, 3);
    sub = ((GameObject *)obj)->extra;
    sub->unkB0 = 0;
    sub->unkB4 = 0;
    sub->unkB8 = 0;
    sub->unkBC = 0;
    sub->turnLatch = 0;
    sub->behaviourState = def[0x1c];
    sub->unkCC = 0;
    storeZeroToFloatParam(sub);
    sub->linkedObj = 0;
    sub->roostYaw = *(s16*)obj;
    sub->flags22C = 0;
    sub->animSpeed = lbl_803E422C;
    sub->runnerState = 0;
    if (GameBit_Get(*(s16*)(def + 0x22)) != 0) {
        ObjHits_DisableObject(obj);
        ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | 0x4000);
        sub->flags22C = (u8)(sub->flags22C & ~1);
        Obj_RemoveFromUpdateList(obj);
        ObjGroup_RemoveObject(obj, 3);
    } else {
        sub->runnerIndex = *(s16*)(def + 0x22) - 0x2fc;
        if (((GameObject *)obj)->anim.seqId == 0x788) {
            sub->runnerIndex = -1;
            sub->curveSpeed = lbl_803E4244;
            sub->mutterSfxTable = &lbl_803DBE30;
        } else {
            if (sub->runnerIndex < 0 || sub->runnerIndex > 4) {
                sub->runnerState = 3;
            }
            sub->curveSpeed = lbl_803E4258;
            sub->mutterSfxTable = &lbl_803DBE28;
            ObjGroup_AddObject(obj, 0x20);
        }
        ((BabyCloudrunnerFlags *)&sub->spitFlags)->resetLatch = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: babycloudrunner_render
 * EN v1.0 Address: 0x8019EC00
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801A0A70
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void babycloudrunner_render(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  s32 isVisible;

  isVisible = visible;
  if (isVisible != 0) {
    objRenderFn_8003b8f4(lbl_803E4228);
  }
  return;
}
#pragma peephole reset


/*
 * --INFO--
 *
 * Function: FUN_8019f1dc
 * EN v1.0 Address: 0x8019F1DC
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x801A1190
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019f1dc(void)
{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  ulonglong uVar11;
  int local_68;
  ushort local_64 [4];
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar11 = FUN_8028683c();
  uVar1 = (uint)(uVar11 >> 0x20);
  iVar5 = *(int *)(uVar1 + 0xb8);
  iVar2 = FUN_80017a98();
  iVar2 = *(int *)(iVar2 + 0xb8);
  *(float *)(iVar5 + 0x20) = lbl_803E4F58;
  if ((uVar11 & 0xff) == 0) {
    *(float *)(iVar5 + 0x24) = lbl_803E4F6C;
    *(float *)(iVar5 + 0x28) = lbl_803E4F70;
  }
  else {
    *(float *)(iVar5 + 0x24) = lbl_803E4F60 * *(float *)(iVar2 + 0x298) + lbl_803E4F5C;
    *(float *)(iVar5 + 0x28) = lbl_803E4F68 * *(float *)(iVar2 + 0x298) + lbl_803E4F64;
  }
  local_58 = lbl_803E4F58;
  local_54 = lbl_803E4F58;
  local_50 = lbl_803E4F58;
  local_5c = lbl_803E4F74;
  local_64[2] = 0;
  local_64[1] = 0;
  local_64[0] = *(ushort *)(iVar5 + 0x50);
  FUN_80017748(local_64,(float *)(iVar5 + 0x20));
  *(byte *)(iVar5 + 0x49) = *(byte *)(iVar5 + 0x49) | 1;
  FUN_80006824(uVar1,SFXsk_baptr6_c);
  *(byte *)(iVar5 + 0x49) = *(byte *)(iVar5 + 0x49) | 2;
  if ((*(byte *)(iVar5 + 0x48) >> 6 & 1) != 0) {
    iVar5 = *(int *)(uVar1 + 0x4c);
    iVar2 = 0;
    if (*(short *)(iVar5 + 0x1a) == 0) {
      iVar2 = ObjGroup_FindNearestObject(0x3a,uVar1,(float *)0x0);
    }
    else {
      piVar3 = ObjGroup_GetObjects(0x3a,&local_68);
      piVar6 = piVar3;
      for (iVar7 = 0; iVar7 < local_68; iVar7 = iVar7 + 1) {
        iVar4 = FUN_8020a468(*piVar6);
        if (*(short *)(iVar5 + 0x1a) == iVar4) {
          iVar2 = piVar3[iVar7];
          break;
        }
        piVar6 = piVar6 + 1;
      }
    }
    if (iVar2 != 0) {
      dVar10 = (double)*(float *)(uVar1 + 0xc);
      dVar9 = (double)*(float *)(uVar1 + 0x10);
      dVar8 = (double)*(float *)(uVar1 + 0x14);
      *(undefined4 *)(uVar1 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(uVar1 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(uVar1 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_800e8630(uVar1);
      *(float *)(uVar1 + 0xc) = (float)dVar10;
      *(float *)(uVar1 + 0x10) = (float)dVar9;
      *(float *)(uVar1 + 0x14) = (float)dVar8;
    }
  }
  FUN_80286888();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void cfguardian_release(void) {}
void cfguardian_initialise(void) {}

typedef struct { int a; int b; s16 c; } GuardianVec;
extern GuardianVec lbl_802C22C0;
extern GuardianVec lbl_802C22CC;
extern u8 lbl_8032284C[];
extern f32 lbl_803E4110;
extern void dll_2E_func0A(int a, int *obj);
extern void dll_2E_func05(int *obj, u8 *sub, int c, int d, int e);
extern void dll_2E_func08(u8 *sub, int b, int c);
extern void dll_2E_func09(u8 *sub, void *a, void *b, int c);
extern void objSeqInitFn_80080078(u8 *p, int n);

/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);

#pragma scheduling off
#pragma peephole off
void cfguardian_init(int *obj, u8 *params) {
    CfGuardianState *sub;
    GuardianVec stk1;
    GuardianVec stk2;

    sub = ((GameObject *)obj)->extra;
    stk1 = lbl_802C22C0;
    stk2 = lbl_802C22CC;
    if (sub == NULL) return;
    ObjMsg_AllocQueue(obj, 4);
    sub->questState = (u8)GameBit_Get(0x4b);
    ((GameObject *)obj)->unkF4 = 1;
    ((GameObject *)obj)->animEventCallback = (void *)cfguardian_SeqFn;
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    sub->landingPhase = 0;
    sub->moveSpeed = lbl_803E4110;
    sub->unkA90 = 6;
    sub->flagsA9B = 0;
    sub->flags611 = (u8)(sub->flags611 | 0x28);
    sub->chatterState = 1;
    sub->chatterAlt = 0;
    sub->chatterPick = 0;
    if (GameBit_Get(0x57) != 0) {
        sub->questState = 4;
        if ((s8)params[0x19] == 0) {
            ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | 0x4000);
            Obj_RemoveFromUpdateList(obj);
        }
    } else if (GameBit_Get(0x60) != 0 && (s8)params[0x19] == 0) {
        sub->questState = 4;
        dll_2E_func0A(8, obj);
    }
    ObjHits_EnableObject(obj);
    dll_2E_func05(obj, (u8*)sub, -0x2000, 0x2800, 4);
    dll_2E_func08((u8*)sub, 0x12c, 0x64);
    dll_2E_func09((u8*)sub, &stk2, &stk1, 4);
    objSeqInitFn_80080078(lbl_8032284C, 0xf);
    sub->flags611 = (u8)(sub->flags611 | 0x2);
}
#pragma peephole reset
#pragma scheduling reset

typedef struct { int a, b, c, d; } GuardianMsg;
extern GuardianMsg lbl_802C22D8;
extern int  dll_2E_func07(int* obj, ObjAnimUpdateState *animUpdate, u8* sub, int x, int y);
extern int  animatedObjGetSeqId(int* p);
extern void saveGame_saveObjectPos(int obj);
extern void* Obj_GetPlayerObject(void);
extern void playerAddRemoveMagic(void* player, int n);

/* EN v1.0 0x8019C3A0  size: 252b  cfguardian_SeqFn: guardian message handler.
 * Persists position on a negative cue, otherwise picks the active/idle
 * heading pair and routes a move request; on the magic-grant message it
 * tops the player back up. Returns 1 if the move was consumed. */
#pragma scheduling off
#pragma peephole off
int cfguardian_SeqFn(int* obj, int unused, ObjAnimUpdateState *animUpdate)
{
    int* sel;
    GuardianMsg stk;
    CfGuardianState* sub = ((GameObject *)obj)->extra;
    stk = lbl_802C22D8;
    if (((GameObject *)obj)->unkB4 < 0) {
        saveGame_saveObjectPos((int)obj);
        return 0;
    }
    if (sub->questState != 6) {
        sel = &stk.a;
    } else {
        sel = &stk.c;
    }
    if (animatedObjGetSeqId((int *)animUpdate) != 0x283) {
        if (dll_2E_func07(obj, animUpdate, (u8*)sub, (s16)sel[0], (s16)sel[1]) != 0) {
            return 1;
        }
    }
    if (animUpdate->triggerCommand == 2) {
        playerAddRemoveMagic(Obj_GetPlayerObject(), 0xa);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);
extern f32  lbl_803E4218;
extern f32  lbl_803E423C;
extern f32  lbl_803E4240;
extern f32  timeDelta;

/* EN v1.0 0x8019E568  size: 352b  sandworm_turnTowardTargetAnim: turn toward the target by
 * a fraction of the yaw delta; when roughly aligned play/advance the idle
 * move, otherwise start or speed-scale the turn move by the delta. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void sandworm_turnTowardTargetAnim(int* a, int* b, u8* c, int d)
{
    int shifted;
    fn_8003ADC4(a, b, (char*)c + 0x3c, 0x28, 0, 3);
    shifted = Obj_GetYawDeltaToObject((int)a, (int)b, 0) >> 3;
    *(s16*)a += shifted;
    if (d == 0) return;
    if ((s16)shifted > -200 && (s16)shifted < 200) {
        if (((BabyCloudRunnerState*)c)->turnLatch != 0) {
            ((BabyCloudRunnerState*)c)->turnLatch = 0;
            ObjAnim_SetCurrentMove((int)a, 0, lbl_803E4218, 0);
        } else {
            ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)((int)a, lbl_803E423C, timeDelta, 0);
        }
    } else {
        if (((BabyCloudRunnerState*)c)->turnLatch == 0) {
            ((BabyCloudRunnerState*)c)->turnLatch = 1;
            ObjAnim_SetCurrentMove((int)a, 9, lbl_803E4218, 0);
        } else {
            s16 t;
            if ((s16)shifted > 0) {
                t = (s16)shifted >> 2;
            } else {
                t = -(s16)shifted >> 2;
            }
            ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)a, (f32)t / lbl_803E4240, timeDelta, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset


/* EN v1.0 0x801A0614  size: 368b  cfprisoncage_SeqFn: drain the object's message
 * queue (re-arming its gamebit on the keyed message), then sync the
 * lit/active state from gamebit 0x44 and notify on completion. */
#pragma scheduling off
#pragma peephole off
int cfprisoncage_SeqFn(int* obj, int unused, ObjAnimUpdateState *animUpdate)
{
    int msg;
    int v;
    int w = 0;
    u8* sub = *(u8**)&((GameObject *)obj)->anim.placementData;
    if (GameBit_Get(*(s16*)(sub + 0x18)) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x8);
        animUpdate->sequenceControlFlags |= 4;
        return 0;
    }
    if (((GameObject *)obj)->anim.seqId == 0x127) {
        return 0;
    }
    while (ObjMsg_Pop(obj, &msg, &v, &w) != 0) {
        if (msg == 0xa0005) {
            GameBit_Set(*(s16*)(sub + 0x18), 1);
        }
    }
    if (GameBit_Get(0x44) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x10);
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x10);
    }
    if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0) {
        if ((*gGameUIInterface)->isEventReady(0x44) != 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x8);
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern f32  Vec_distance(void* a, void* b);
extern f32  s16toFloat(int a, int b);
extern void objAudioFn_800393f8(int obj, void* p, int a, int b, int c, int d);
extern void gameBitIncrement(int bit);
extern void Sfx_PlayFromObject(int obj, int sfxId);

/* EN v1.0 0x8019E6C8  size: 316b  babycloudrunner_func0B: when the player
 * gets within the trigger radius and the runner is in state 3, fire its
 * burst (notify, bump the counter, set the gamebit); otherwise just play
 * the idle audio cue. */
#pragma scheduling off
#pragma peephole off
int babycloudrunner_func0B(void* p)
{
    int* obj;
    int flag;
    u8* r;
    BabyCloudRunnerState* sub;
    u8* q;
    void* player;
    obj = (int*)p;
    sub = ((GameObject *)obj)->extra;
    q = *(u8**)&((GameObject *)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    r = *(u8**)&((GameObject *)obj)->anim.placementData;
    flag = 0;
    if (Vec_distance((char*)player + 0x18, (char*)obj + 0x18) < (f32)(s16)*(s16*)(r + 0x1a)) {
        if (sub->runnerState == 3) {
            if ((((GameObject *)obj)->objectFlags & 0x1000) == 0) {
                flag = 1;
            }
        }
    }
    if (flag != 0) {
        s16toFloat((int)sub, 0x3c);
        ((GameObject *)obj)->unkF4 = 1;
        *(s16*)obj = sub->roostYaw;
        (*gObjectTriggerInterface)->runSequence(4, obj, -1);
        sub->unk00 = lbl_803E4244;
        gameBitIncrement(0x901);
        sub->behaviourState = 0xc;
        GameBit_Set(*(s16*)(q + 0x1e), 1);
        ((GameObject *)obj)->unkF4 = 0;
        return 1;
    }
    objAudioFn_800393f8((int)obj, (char*)sub + 0x6c, 0x296, 0x1000, -1, 1);
    Sfx_PlayFromObject((int)obj, SFXsk_baptr9_c);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
void windlift_hitDetect(void) {}
void windlift_release(void) {}
void windlift_initialise(void) {}
void cfpowerbase_free(void) {}
void cfpowerbase_hitDetect(void) {}
void cfpowerbase_release(void) {}
void cfpowerbase_initialise(void) {}

typedef struct { f32 f0, f4, f8, fc, f10, f14; u8 b18, b19, b1a, b1b; } CrystalBeam;

/* Per-object extra state for the CloudRunner main crystal
 * (cfmaincrystal_getExtraSize == 0x160). */
typedef struct CfMainCrystalState {
    f32 pylonX[3];         /* per-pylon beam source position */
    f32 crystalX;
    f32 pylonY[3];
    f32 crystalY;
    f32 pylonZ[3];
    f32 crystalZ;
    s16 pylonTimer[3];     /* 0x30: 0 unseen; ramps to 0x78 once reported */
    s16 crystalKnown;      /* 0x36 */
    CrystalBeam beams[10]; /* 0x38 */
    s16 charge;            /* 0x150: convergence charge frames */
    f32 humVolume;         /* 0x154 */
    int unk158;
    u8 chime[4];           /* 0x15c: per-beam chime timers */
} CfMainCrystalState;
STATIC_ASSERT(sizeof(CfMainCrystalState) == 0x160);

/* Per-object extra state for the CloudRunner power base
 * (cfpowerbase_getExtraSize == 0x6). */
typedef struct CfPowerBaseState {
    s16 typeBit;   /* gamebit 0x54..0x56, from params+0x1e */
    s16 litBit;    /* gamebit 0x51..0x53 gating the lit state */
    s8 typeIndex;  /* 0/1/2 trigger argument */
    u8 pad5;
} CfPowerBaseState;
STATIC_ASSERT(sizeof(CfPowerBaseState) == 0x6);

/* Per-object extra state for the CloudRunner prison guard
 * (cfprisonguard_getExtraSize == 0x3c). */
typedef struct CfPrisonGuardState {
    u8 pad00[0x30];
    f32 alarmRamp;    /* particle ramp advanced while above threshold */
    s16 stateTimer;
    s8 capturedLatch; /* last GameBit 0x50 value */
    s8 guardState;    /* 0 idle .. 7 forced-chase */
    u8 flags;         /* 1 spawn-pulse pending, 2 freed-check, 4 alarm raised */
    u8 flags39;       /* 0x80 cleared every update */
    u8 pad3A[2];
} CfPrisonGuardState;
STATIC_ASSERT(sizeof(CfPrisonGuardState) == 0x3c);

/* Per-object extra state for the CloudRunner prison uncle
 * (cfprisonuncle_getExtraSize == 0xa8). */
typedef struct CfPrisonUncleState {
    int target;          /* keyed type-0x3d object */
    u8 lookBlock[0x30];  /* fn_8003ADC4 head-track block */
    u8 audioBlock[0x30]; /* objAudioFn block */
    int unk64;
    int unk68;
    u8 pad6C[4];
    s16 unk70;
    u8 pad72;
    s8 captured;         /* GameBit 0x4d latch */
    s8 kicked;           /* fn_8019FC84 one-shot */
    u8 pad75[0x33];
} CfPrisonUncleState;
STATIC_ASSERT(sizeof(CfPrisonUncleState) == 0xa8);

/* Per-object extra state for the robot light beacon
 * (gcrobotlightbea_getExtraSize == 0xc). */
typedef struct GcRobotLightBeaState {
    void *light; /* modelLightStruct point light */
    int unk4;
    u8 hitFlags; /* 0x80 = player caught in the beam */
    u8 pad9[3];
} GcRobotLightBeaState;
STATIC_ASSERT(sizeof(GcRobotLightBeaState) == 0xc);

/* spiritdoorspirit_getExtraSize == 0x1. */
typedef struct SpiritDoorSpiritState {
    u8 active; /* gamebit not yet set: render + group 0x4e membership */
} SpiritDoorSpiritState;

#include "main/dll/DR/gunpowderbarrel_state.h"

typedef struct WindliftPlacement {
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x22 - 0x1C];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} WindliftPlacement;


typedef struct CfprisoncagePlacement {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    u8 pad1A[0x20 - 0x1A];
} CfprisoncagePlacement;


typedef struct GunpowderbarrelLaunchAtTargetPlacement {
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
} GunpowderbarrelLaunchAtTargetPlacement;


typedef struct SpiritdoorspiritPlacement {
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} SpiritdoorspiritPlacement;


typedef struct CfguardianState {
    u8 pad0[0x68C - 0x0];
    void *unk68C;
    u8 pad690[0xA9C - 0x690];
} CfguardianState;


typedef struct BabycloudrunnerObjectDef {
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} BabycloudrunnerObjectDef;


typedef struct CfmaincrystalObjectDef {
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} CfmaincrystalObjectDef;


typedef struct CfprisoncageObjectDef {
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} CfprisoncageObjectDef;


typedef struct WindliftObjectDef {
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} WindliftObjectDef;


typedef struct CfprisonguardPlacement {
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} CfprisonguardPlacement;


typedef struct BabycloudrunnerPlacement {
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} BabycloudrunnerPlacement;


/* EN v1.0 0x8019D8B4  size: 308b  cfpowerbase_init: seed header and the
 * sub's type from spawn params, map the type id (0x54..0x56) to a model
 * and gamebit, then gate the active/lit state bits on those gamebits. */
#pragma scheduling off
#pragma peephole off
void cfpowerbase_init(int* obj, u8* params) {
    CfPowerBaseState* sub = ((GameObject *)obj)->extra;
    s16 type;
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    sub->typeBit = *(s16*)(params + 0x1e);
    type = sub->typeBit;
    switch (type) {
    case 0x54:
        sub->litBit = 0x51;
        sub->typeIndex = 0;
        break;
    case 0x55:
        sub->litBit = 0x52;
        sub->typeIndex = 1;
        Obj_SetActiveModelIndex(obj, 2);
        break;
    case 0x56:
        sub->litBit = 0x53;
        sub->typeIndex = 2;
        Obj_SetActiveModelIndex(obj, 1);
        break;
    }
    ((GameObject *)obj)->animEventCallback = (void *)cfpowerbase_SeqFn;
    ObjMsg_AllocQueue(obj, 2);
    if (GameBit_Get(sub->litBit) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x10);
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x10);
    }
    if (GameBit_Get(sub->typeBit) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x8);
        ((GameObject *)obj)->unkF4 = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset


/* EN v1.0 0x8019D77C  size: 312b  cfpowerbase_update: track its gamebit's
 * lit state, fire the queued state-change trigger, and when the base is
 * powered and its UI condition clears, mark it done and notify. */
#pragma scheduling off
#pragma peephole off
void cfpowerbase_update(int* obj) {
    CfPowerBaseState* sub = ((GameObject *)obj)->extra;
    if (GameBit_Get(sub->litBit) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x10);
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x10);
    }
    if (((GameObject *)obj)->unkF4 != 0) {
        (*gObjectTriggerInterface)->preempt((int)obj, 0xfa);
        (*gObjectTriggerInterface)->runSequence(sub->typeIndex, obj, 3);
        ((GameObject *)obj)->unkF4 = 0;
    }
    if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0) {
        if ((*gGameUIInterface)->isEventReady(sub->litBit) != 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x8);
            GameBit_Set(sub->litBit, 0);
            GameBit_Set(0x973, 0);
            (*gObjectTriggerInterface)->runSequence(sub->typeIndex, obj, -1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
void cfmaincrystal_hitDetect(void) {}
void cfmaincrystal_release(void) {}
void cfmaincrystal_initialise(void) {}
void babycloudrunner_hitDetect(void) {}
void babycloudrunner_release(void) {}
void babycloudrunner_initialise(void) {}
void cfprisonguard_free(void) {}
void cfprisonguard_release(void) {}
void cfprisonguard_initialise(void) {}

typedef struct { u8 top : 1; u8 rest : 7; } Bit80;

/* EN v1.0 0x8019FBD0  size: 172b  cfprisonguard_init: set up the guard's
 * substate (update fn cfprisonguard_SeqFn, message queue), seed its header from
 * the spawn params, and apply the alarm-active gating bits. */
#pragma scheduling off
#pragma peephole off
void cfprisonguard_init(int* obj, u8* params) {
    CfPrisonGuardState* sub = ((GameObject *)obj)->extra;
    sub->flags = 1;
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    ((GameObject *)obj)->animEventCallback = (void *)cfprisonguard_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    sub->capturedLatch = 1;
    if (GameBit_Get(0x4d) != 0) {
        sub->flags = (u8)(sub->flags | 4);
    }
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x10);
    ((Bit80*)&sub->flags39)->top = 1;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E4268;
extern int waterfx_consumePendingImpactNearPoint(f32 *vec, f32 r);
extern int objGetAnimState80A(void *obj);

#pragma scheduling off
#pragma peephole off
void cfprisonguard_update(int *obj) {
    CfPrisonGuardState *sub;
    int *player;
    u8 *def;
    int bit44;
    f32 dist;

    sub = ((GameObject *)obj)->extra;
    player = (int*)Obj_GetPlayerObject();
    def = *(u8**)&((GameObject *)obj)->anim.placementData;
    if (((u32)sub->flags39 >> 7) & 1u) {
        sub->flags39 = (u8)(sub->flags39 & ~0x80);
    }
    if (GameBit_Get(((CfprisonguardPlacement *)def)->unk1E) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x8);
        ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | 0x4000);
        ObjHits_DisableObject(obj);
        Obj_RemoveFromUpdateList(obj);
        return;
    }
    bit44 = GameBit_Get(0x44);
    dist = Vec_distance((char*)obj + 0x18, (char*)player + 0x18);
    if (sub->flags == 1) {
        waterfx_consumePendingImpactNearPoint(&((GameObject *)obj)->anim.localPosX, lbl_803E4268);
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        sub->flags = 2;
    }
    if (bit44 == 0) {
        if (sub->guardState != 4) {
            if (dist >= (f32)(s32)((CfprisonguardPlacement *)def)->unk1A) {
                if (waterfx_consumePendingImpactNearPoint(&((GameObject *)obj)->anim.localPosX, lbl_803E4268) == 0) return;
            }
        }
        if (objGetAnimState80A(player) != 0x40) {
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
void cfprisonuncle_free(void) {}
void cfprisonuncle_hitDetect(void) {}
void cfprisonuncle_release(void) {}
void cfprisonuncle_initialise(void) {}

extern int  objModelGetVecFn_800395d8(int obj, int idx);
extern void objAudioFn_80039270(int obj, void* p, int id);
extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
extern u8   framesThisStep;
extern f32  lbl_803E428C;

/* EN v1.0 0x8019FEDC  size: 536b  cfprisonuncle_update: while not captured,
 * drain pending messages, re-acquire the keyed target object, then either
 * track/animate toward the player (firing the alert trigger) or, once
 * captured, raise the done flag and notify. */
#pragma scheduling off
#pragma peephole off
void cfprisonuncle_update(int* obj)
{
    CfPrisonUncleState* sub = ((GameObject *)obj)->extra;
    void* player;
    int m2, objectIndex, objectCount, m1, m3;
    int* objects;
    int i;
    if (sub == NULL) return;
    if (GameBit_Get(0x50) != 0) return;
    if (ObjMsg_Pop(obj, &m1, &m2, &m3) != 0) {
        *(void**)&sub->target = NULL;
    }
    if (*(void**)&sub->target == NULL) {
        objects = ObjList_GetObjects(&objectIndex, &objectCount);
        for (i = objectIndex; i < objectCount; i++) {
            if (*(s16*)((char*)objects[i] + 0x44) == 0x3d) {
                sub->target = objects[i];
                i = objectCount;
            }
        }
    }
    ObjTrigger_UpdateIdBlockFlag((int)obj);
    sub->captured = (s8)GameBit_Get(0x4d);
    if (sub->captured == 0) {
        player = Obj_GetPlayerObject();
        fn_8003ADC4(obj, player, (char*)sub + 4, 0x41, 0, 3);
        if ((int)randomGetRange(0, 0x1e) == 0) {
            objAudioFn_80039270((int)obj, (char*)sub + 0x34, 0x297);
        }
        if (ObjTrigger_IsSet((int)obj) != 0) {
            fn_8003ADC4(obj, player, (char*)sub + 4, 0x41, 0, 3);
            *(s16*)objModelGetVecFn_800395d8((int)obj, 1) = -0xaaa;
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
        } else {
            objAnimFn_80038f38((int)obj, (char*)sub + 0x34);
            ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E428C, (f32)(u32)framesThisStep, 0);
        }
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x8);
        if (((GameObject *)obj)->unkB4 == -1) {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
void gcrobotlightbea_render(void) {}
void gcrobotlightbea_release(void) {}
void gcrobotlightbea_initialise(void) {}

extern f32 lbl_803E4298;
extern f32 lbl_803E429C;

/* EN v1.0 0x801A01E8  size: 296b  gcrobotlightbea_hitDetect: clear the hit
 * flag, then re-set it only if the priority hit is the (undisguised) player
 * and lands inside the beacon's bounding box. */
#pragma scheduling off
#pragma peephole off
void gcrobotlightbea_hitDetect(int* obj)
{
    int out;
    f32 vec[3];
    void* hit;
    GcRobotLightBeaState* sub = ((GameObject *)obj)->extra;
    ((Bit80*)&sub->hitFlags)->top = 0;
    if (((GameObject *)obj)->unkC4 == NULL) return;
    if (ObjHits_GetPriorityHit((int)obj, &hit, 0, 0) == 0) {
        hit = (void *)(*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject;
        if (hit == NULL) return;
    }
    if (hit != Obj_GetPlayerObject()) return;
    if (playerIsDisguised(hit) != 0) return;
    vec[0] = ((ObjHitsPriorityState *)hit)->primaryRadiusSquared;
    vec[1] = lbl_803E4298 + ((ObjHitsPriorityState *)hit)->localPosX;
    vec[2] = ((ObjHitsPriorityState *)hit)->localPosY;
    if (voxmaps_traceWorldLine((void *)((int)obj + 0xc), vec) == 0) return;
    if (((GameObject *)obj)->unkF4 != 0 ||
        objBboxFn_800640cc((int)obj + 0xc, vec, 0, &out, (int)obj, 4, -1, 0, 0) == 0) {
        ((Bit80*)&sub->hitFlags)->top = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset
void cfperch_render(void) {}
void cfperch_hitDetect(void) {}
void cfperch_release(void) {}
void cfperch_initialise(void) {}
void cfprisoncage_free(void) {}
void cfprisoncage_release(void) {}
void cfprisoncage_initialise(void) {}

#pragma scheduling off
#pragma peephole off
void cfprisoncage_update(int *obj) {
    extern ObjectTriggerInterface **gObjectTriggerInterface;
    int v;
    if (((GameObject *)obj)->unkF4 != 0) {
        switch (((GameObject *)obj)->anim.seqId) {
        case 0x127: v = 0; break;
        case 0x128:
        default:    v = 1; break;
        }
        (*gObjectTriggerInterface)->runSequence(v, obj, -1);
        ((GameObject *)obj)->unkF4 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset
void spiritdoorspirit_hitDetect(void) {}
void spiritdoorspirit_release(void) {}
void spiritdoorspirit_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int cfguardian_getExtraSize(void) { return 0xa9c; }
int cfguardian_getObjectTypeId(void) { return 0x41; }
int windlift_getExtraSize(void) { return 0x178; }
int windlift_getObjectTypeId(void) { return 0x0; }
int cfpowerbase_getExtraSize(void) { return 0x6; }
int cfpowerbase_getObjectTypeId(void) { return 0x1; }
int cfmaincrystal_getExtraSize(void) { return 0x160; }
int cfmaincrystal_getObjectTypeId(void) { return 0x1; }
int babycloudrunner_getExtraSize(void) { return 0x248; }
int cfprisonguard_getExtraSize(void) { return 0x3c; }
int cfprisonguard_getObjectTypeId(void) { return 0x49; }
int cfprisonuncle_getExtraSize(void) { return 0xa8; }
int cfprisonuncle_getObjectTypeId(void) { return 0x9; }
int gcrobotlightbea_getExtraSize(void) { return 0xc; }
int gcrobotlightbea_getObjectTypeId(void) { return 0x0; }
int cfperch_getExtraSize(void) { return 0x0; }
int cfperch_getObjectTypeId(void) { return 0x0; }
int cfprisoncage_getExtraSize(void) { return 0x0; }
int spiritdoorspirit_getExtraSize(void) { return 0x1; }
int spiritdoorspirit_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4190;
extern f32 lbl_803E41D0;
extern f32 lbl_803E4210;
extern f32 lbl_803E42B0;
#pragma peephole off
void windlift_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4190); }
void cfpowerbase_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E41D0); }
void cfmaincrystal_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4210); }
void cfprisoncage_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E42B0); }
#pragma peephole reset

extern f32   lbl_803E4280;
extern f32   lbl_803E4260;
extern f32   lbl_803E4264;
extern f32   lbl_803E4284;
extern void  objParticleFn_80099d84(int obj, f32 f, int a, int b);

/* EN v1.0 0x8019F93C  size: 188b  cfprisonguard_render: render the guard
 * model when visible, ramp its alarm timer at sub->_30 each frame, and
 * once it crosses the threshold spawn a one-shot particle. */
#pragma scheduling off
#pragma peephole off
void cfprisonguard_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    CfPrisonGuardState* sub = ((GameObject *)obj)->extra;
    if (visible != 0) {
        objRenderFn_8003b8f4(lbl_803E4280);
    }
    if (visible != 0) {
        f32 t = sub->alarmRamp;
        if (t > lbl_803E4260) {
            sub->alarmRamp = lbl_803E4264 * (f32)(u32)framesThisStep + t;
            if (sub->alarmRamp < lbl_803E4284) {
                objParticleFn_80099d84((int)obj, lbl_803E4280, 3, 0);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
void spiritdoorspirit_free(int x) { ObjGroup_RemoveObject(x, 0x4e); }
#pragma scheduling reset

/* if (o->_X == K) return A; else return B; */
#pragma peephole off
int cfprisoncage_getObjectTypeId(int *obj) { if (((GameObject *)obj)->anim.seqId == 0x128) return 0x8; return 0x0; }
#pragma peephole reset

/* chained byte bit-extract. */
u32 fn_801A0174(int *obj) { return (((GcRobotLightBeaState*)((int**)obj)[0xb8/4])->hitFlags >> 7) & 1; }
u32 gunpowderbarrel_isHeld(int *obj) { return (((GunpowderBarrelState*)((int**)obj)[0xb8/4])->heldFlags >> 5) & 1; }

typedef struct { u8 playerHeld : 1; u8 _pad0 : 1; u8 held : 1; u8 _pad1 : 5; } GpbHeldByte;
extern f32 lbl_803E42C0;

/* EN v1.0 0x801A0BDC  size: 56b  gunpowderbarrel_setHeldState: flag the
 * barrel as held, mark obj active, and clear its physics-sleep bit. */
#pragma scheduling off
#pragma peephole off
void gunpowderbarrel_setHeldState(int* obj) {
    GunpowderBarrelState* sub = ((GameObject *)obj)->extra;
    ((GpbHeldByte*)&sub->heldFlags)->held = 1;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8);
    sub->motionFlags = (u8)(sub->motionFlags & ~2);
}

/* EN v1.0 0x801A0B90  size: 76b  gunpowderbarrel_clearHeldState: zero the
 * barrel's velocity/throw vectors, mark it sleeping, clear obj-active and
 * the held flag. */
void gunpowderbarrel_clearHeldState(int* obj) {
    GunpowderBarrelState* sub = ((GameObject *)obj)->extra;
    f32 z = lbl_803E42C0;
    sub->throwVelY = z;
    sub->throwVelX = z;
    sub->throwVelZ = z;
    sub->motionFlags = (u8)(sub->motionFlags | 1);
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~8);
    sub->unk38 = z;
    ((GpbHeldByte*)&sub->heldFlags)->held = 0;
}

/* EN v1.0 0x801A0E04  size: 244b  gunpowderbarrel_setPlayerHeldState: when
 * grabbed by the player, copy the held-pose and enable hit reactions; when
 * released, restore the default pose and clear them. */
void gunpowderbarrel_setPlayerHeldState(int* obj, u8 heldByPlayer) {
    GunpowderBarrelState* sub = ((GameObject *)obj)->extra;
    u8* h = *(u8**)&((GameObject *)obj)->anim.hitReactState;
    if (heldByPlayer != 0) {
        h[0x6a] = 1;
        h[0x6b] = 1;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 8);
        ((GpbHeldByte*)&sub->heldFlags)->playerHeld = 1;
        sub->motionFlags = (u8)(sub->motionFlags & ~2);
        ObjHits_SetFlags((int)obj, 0x480);
        ObjHits_ClearSourceMask((int)obj, 1);
        ObjHits_EnableObject((int)obj);
        ObjHits_SyncObjectPositionIfDirty((int)obj);
    } else {
        h[0x6a] = (*(u8**)&((GameObject *)obj)->anim.modelInstance)[0x63];
        h[0x6b] = (*(u8**)&((GameObject *)obj)->anim.modelInstance)[0x64];
        ((GpbHeldByte*)&sub->heldFlags)->playerHeld = 0;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~8);
        ObjHits_ClearFlags((int)obj, 0x400);
        sub->motionFlags = (u8)(sub->motionFlags | 1);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* state-transition: kicks player into mode 2 when sandworm not yet eaten. */
#pragma peephole off
int fn_8019FC84(int *obj, int unused, ObjAnimUpdateState *animUpdate) {
    CfPrisonUncleState *p = ((GameObject *)obj)->extra;
    if (p->kicked != 0) return 0;
    if (animUpdate->triggerCommand == 2) {
        p->kicked = 1;
        playerAddRemoveMagic(Obj_GetPlayerObject(), 2);
    }
    return 0;
}
#pragma peephole reset

/* GameBit-gated byte write. */
#pragma scheduling off
int fn_801A04F4(int obj, int unused, ObjAnimUpdateState *animUpdate) {
    if (GameBit_Get(0x4d) != 0) {
        animUpdate->sequenceControlFlags = 4;
    }
    return 0;
}
#pragma scheduling reset

/* plain forwarder. */
extern int waterSpellStone1Fn_8019b4c8();
void cfguardian_update(void) { waterSpellStone1Fn_8019b4c8(); }

/* Drift-recovery: add new fns with v1.0 names. */
extern f32 lbl_803E42B8;
extern f32 lbl_803E4130;
extern f32 lbl_803E416C;
extern void modelLightStruct_freeSlot(int* p);
/* ObjLink_DetachChild already declared above as undefined4 ObjLink_DetachChild() */
extern void dll_2E_func06(int* a, int* b, int c);
extern void objfx_spawnHitEmitterAtPos(f32* p, int a, int b, int c, int d);
extern f32 fn_80296214(void* p);
/* ObjMsg_AllocQueue already declared as undefined */
extern void Music_Trigger(int a, int b);
extern int ObjHits_GetPriorityHitWithPosition(int* obj, int a, int b, int c, f32* out_x, f32* out_y, f32* out_z);

#pragma scheduling off
#pragma peephole off

int babycloudrunner_getObjectTypeId(void) { return 0; }

void spiritdoorspirit_init(int* obj)
{
    SpiritDoorSpiritState* state = ((GameObject *)obj)->extra;
    state->active = 0;
    *(s8 *)&((GameObject *)obj)->anim.alpha = 0;
}

extern f32 lbl_803DBE78;
extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);

void spiritdoorspirit_update(int *obj) {
    SpiritDoorSpiritState *sub;
    u8 *def;

    sub = ((GameObject *)obj)->extra;
    def = *(u8**)&((GameObject *)obj)->anim.placementData;
    if (sub->active == 0) {
        sub->active = (u8)(GameBit_Get(((SpiritdoorspiritPlacement *)def)->unk1E) == 0);
        if (sub->active != 0) {
            ObjGroup_AddObject(obj, 0x4e);
        }
        if (((GameObject *)obj)->anim.alpha != 0) {
            ((GameObject *)obj)->anim.alpha = (u8)(((GameObject *)obj)->anim.alpha - 1);
        }
    } else {
        fn_80098B18((int)obj, lbl_803DBE78, 5, 0, 0, 0);
        sub->active = (u8)(GameBit_Get(((SpiritdoorspiritPlacement *)def)->unk1E) == 0);
        if (sub->active == 0) {
            ObjGroup_RemoveObject(obj, 0x4e);
        }
        if (((GameObject *)obj)->anim.alpha < 0xff) {
            ((GameObject *)obj)->anim.alpha = (u8)(((GameObject *)obj)->anim.alpha + 1);
        }
    }
}

int babycloudrunner_setScale(int* obj)
{
    BabyCloudRunnerState* state = ((GameObject *)obj)->extra;
    return !(state->flags22C & 1);
}

void cfperch_init(int* obj)
{
    ((GameObject *)obj)->unkF4 = 1;
    ((GameObject *)obj)->animEventCallback = (void*)fn_801A04F4;
}

void cfmaincrystal_free(int* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void cfperch_free(int* obj)
{
    ObjMsg_SendToObjects(62, 0, obj, 0x40001, 0);
}

void babycloudrunner_free(int* obj)
{
    ObjGroup_RemoveObject(obj, 32);
    ObjGroup_RemoveObject(obj, 3);
}

void gcrobotlightbea_init(int* obj)
{
    GcRobotLightBeaState* state = ((GameObject *)obj)->extra;
    state->light = 0;
    state->unk4 = 0;
    ObjHits_EnableObject(obj);
    ((GameObject *)obj)->anim.alpha = 0x80;
}

extern f32 lbl_803E42A0;
extern f32 lbl_803E42A4;
extern f32 lbl_80322C38[];
extern f32 lbl_803DBE58;
extern f32 lbl_803DBE5C;
extern void *modelLightStruct_createPointLight(int a, int b, int c, int d);
extern void modelLightStruct_setDistanceAttenuation(void *light, f32 a, f32 b);
extern void modelLightStruct_setPosition(void *light, f32 x, f32 y, f32 z);
extern void Obj_TransformLocalVectorByWorldMatrix(int *obj, void *out, void *in);
extern void voxmaps_traceScaledVectorEnd(f32 *dst, void *posA, f32 *dir, f32 factor);
extern f32 PSVECDistance(void *a, void *b);
extern void PSVECScale(void *in, void *out, f32 scale);
extern void getAmbientColor(int mode, u8 *r, u8 *g, u8 *b);
extern void modelLightStruct_setDiffuseColor(void *p, int r, int g, int b, int a);

void gcrobotlightbea_update(int *obj) {
    GcRobotLightBeaState *sub;
    f32 vec[3];
    f32 vec2[3];
    u8 b_byte, g_byte, r_byte;

    sub = ((GameObject *)obj)->extra;
    if (sub->light == NULL) {
        sub->light = modelLightStruct_createPointLight(0xfa, 0xfa, 0xfa, 1);
        if (sub->light != NULL) {
            modelLightStruct_setDistanceAttenuation(sub->light, lbl_803DBE58, lbl_803E42A0 + lbl_803DBE58);
        }
    }
    ObjHits_SetHitVolumeSlot(obj, 0x17, 0, 0);
    vec[0] = lbl_80322C38[0];
    vec[1] = lbl_80322C38[1];
    vec[2] = lbl_80322C38[2];
    Obj_TransformLocalVectorByWorldMatrix(obj, vec, vec);
    voxmaps_traceScaledVectorEnd(vec2, (char*)obj + 0xc, vec, lbl_803DBE5C);
    PSVECDistance((char*)obj + 0xc, vec2);
    PSVECScale(lbl_80322C38, vec2, 0);
    getAmbientColor(0, &r_byte, &g_byte, &b_byte);
    if (sub->light != NULL) {
        modelLightStruct_setDiffuseColor(sub->light,
            (s32)(lbl_803E42A4 * (f32)(u32)r_byte),
            (s32)(lbl_803E42A4 * (f32)(u32)g_byte),
            (s32)(lbl_803E42A4 * (f32)(u32)b_byte),
            0xff);
        modelLightStruct_setPosition(sub->light, vec2[0], vec2[1], vec2[2]);
    }
}

void spiritdoorspirit_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    SpiritDoorSpiritState* state = ((GameObject *)obj)->extra;
    if ((s32)visible != 0) {
        if (state->active != 0) {
            ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E42B8);
        }
    }
}

void cfprisonguard_hitDetect(int* obj)
{
    CfPrisonGuardState* state = ((GameObject *)obj)->extra;
    if (ObjHits_GetPriorityHit(obj, NULL, NULL, NULL) == 19) {
        state->guardState = 7;
    }
}

void gcrobotlightbea_free(int* obj)
{
    GcRobotLightBeaState* state = ((GameObject *)obj)->extra;
    if (state->light != NULL) {
        modelLightStruct_freeSlot((int*)state);
    }
    if (((GameObject *)obj)->unkC4 != NULL) {
        ObjLink_DetachChild(((GameObject *)obj)->unkC4, obj);
    }
}

void cfguardian_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* state = ((GameObject *)obj)->extra;
    if ((s32)visible != 0) {
        objRenderFn_8003b8f4(lbl_803E4130);
        dll_2E_func06(obj, state, 0);
    }
}

void cfprisoncage_hitDetect(int* obj)
{
    f32 pos_z, pos_y, pos_x;
    if (ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &pos_x, &pos_y, &pos_z) != 0) {
        objfx_spawnHitEmitterAtPos(&pos_x, 8, 200, 128, 0);
    }
}

extern f32 lbl_803E42B4;
void cfprisoncage_init(int *obj, u8 *def) {
    ObjMsg_AllocQueue(obj, 1);
    *(s16 *)obj = (s16)((s32)def[0x1a] << 8);
    ((GameObject *)obj)->unkF4 = 1;
    ((GameObject *)obj)->animEventCallback = (void *)cfprisoncage_SeqFn;
    if (((GameObject *)obj)->anim.seqId == 296) {
        if (GameBit_Get(((CfprisoncageObjectDef *)def)->unk18) != 0) {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E42B4, 0);
        } else {
            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E42B4, 0);
        }
    } else {
        if (GameBit_Get(((CfprisoncageObjectDef *)def)->unk18) != 0) {
            (*gObjectTriggerInterface)->preempt((int)obj, 60);
        }
    }
}

void windlift_free(int* obj)
{
    void* p = Obj_GetPlayerObject();
    if (p == NULL || fn_80296214(p) == lbl_803E416C) {
        Music_Trigger(189, 0);
    }
    ObjGroup_RemoveObject(obj, 73);
}

void cfguardian_free(int* obj, int p2)
{
    char* state = ((GameObject *)obj)->extra;
    if (p2 == 0) {
        int i;
        for (i = 0; i < 6; i++) {
            int* sub = *(int**)&((CfguardianState *)state)->unk68C;
            if (sub != NULL) {
                Obj_FreeObject(sub);
            }
            state += 4;
        }
    }
}

void gunpowderbarrel_setScale(int* obj, f32* params)
{
    int* state = ((GameObject *)obj)->extra;
    if (((GunpowderBarrelState*)state)->heldByCarryInterface != 0) return;
    if (((GunpowderBarrelState*)state)->fuseFrames != 0) return;
    ((GunpowderBarrelState*)state)->throwVelY = ((GunpowderBarrelState*)state)->throwVelY + params[1];
    ((GunpowderBarrelState*)state)->throwVelX = ((GunpowderBarrelState*)state)->throwVelX + params[0];
    ((GunpowderBarrelState*)state)->throwVelZ = ((GunpowderBarrelState*)state)->throwVelZ + params[2];
    ((GunpowderBarrelState*)state)->motionFlags = (u8)(((GunpowderBarrelState*)state)->motionFlags | 1);
}

int gunpowderbarrel_canBeGrabbed(int* obj)
{
    GunpowderBarrelState* state = ((GameObject *)obj)->extra;
    int result = 0;
    if (state->heldByCarryInterface == 0 &&
        state->respawnTimer == lbl_803E42C0 &&
        ((int(*)(GunpowderBarrelState*))(*(*(void****)&lbl_803DCAC0))[5])(state) == 0) {
        result = 1;
    }
    return result;
}

void cfprisonuncle_init(int* obj)
{
    CfPrisonUncleState* state;
    ObjMsg_AllocQueue(obj, 1);
    ((GameObject *)obj)->animEventCallback = (void*)fn_8019FC84;
    state = ((GameObject *)obj)->extra;
    state->unk64 = 464;
    state->unk68 = 465;
    state->unk70 = 0;
    state->kicked = 0;
    if ((u32)GameBit_Get(77) != 0u) {
        GameBit_Set(80, 1);
    }
}

#pragma peephole reset
#pragma scheduling reset

/* copy 3 floats within same struct */
void cfguardian_hitDetect(int *obj) {
    ((GameObject *)obj)->anim.previousLocalPosX = ((GameObject *)obj)->anim.localPosX;
    ((GameObject *)obj)->anim.previousLocalPosY = ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)obj)->anim.previousLocalPosZ = ((GameObject *)obj)->anim.localPosZ;
}

#pragma scheduling off
#pragma dont_inline on
int *findRomCurvePointNearObject(int *obj, int p2, int *outVec, int p4) {
    int *result = NULL;
    int local[2];
    int found;

    if (p4 == 1) {
        local[0] = 0;
        local[1] = 0;
    } else {
        local[0] = 25;
        local[1] = 21;
    }

    found = (*gRomCurveInterface)->find(
        local, 2, p2,
        ((GameObject *)obj)->anim.localPosX,
        ((GameObject *)obj)->anim.localPosY,
        ((GameObject *)obj)->anim.localPosZ);

    if (found > -1) {
        result = (int *)(*gRomCurveInterface)->getById(found);
        if (outVec != NULL) {
            *(f32 *)((char *)outVec + 0) = *(f32 *)((char *)result + 8);
            *(f32 *)((char *)outVec + 4) = *(f32 *)((char *)result + 12);
            *(f32 *)((char *)outVec + 8) = *(f32 *)((char *)result + 16);
        }
    }
    return result;
}
#pragma dont_inline reset
#pragma scheduling reset

extern void fn_8019D9F0(int *obj);
extern int *lbl_803DDB10;
#pragma peephole off
#pragma scheduling off
void cfmaincrystal_update(int *obj) {
    uint payload;
    uint msgType;
    uint srcObjId;
    s8 t;
    t = ((s8 *)*(int *)&((GameObject *)obj)->anim.placementData)[0x19];
    switch (t) {
    case 0:
        fn_8019D9F0(obj);
        break;
    case 1:
        payload = 0;
        while (ObjMsg_Pop(obj, &msgType, &srcObjId, &payload) != 0) {
            if (msgType == 0x110004) {
                ObjMsg_SendToObject((void *)srcObjId, 0x110004, obj, 0);
            }
        }
        lbl_803DDB10 = obj;
        *(s16 *)obj = (s16)(*(s16 *)obj + (s32)framesThisStep * 0xb6);
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
int cfpowerbase_SeqFn(int p1, int unused, ObjAnimUpdateState *animUpdate)
{
  extern int ObjMsg_Pop(int, int *, int *, int *);
  CfPowerBaseState *sub = ((GameObject *)p1)->extra;
  u8 *animUpdateBytes = (u8 *)animUpdate;
  int msgArg;
  int msgType;
  int msgFlag = 0;
  int i;

  while (ObjMsg_Pop(p1, &msgType, &msgArg, &msgFlag) != 0) {
    switch (msgType) {
      case 0x110001:
        if (sub->typeBit == 84 && *(s16 *)(animUpdateBytes + 0x58) > 175) {
          ObjMsg_SendToObject((void *)msgArg, 0x110001, p1, 0);
        }
        break;
      case 0x110002:
        if (sub->typeBit == 85 && *(s16 *)(animUpdateBytes + 0x58) > 175) {
          ObjMsg_SendToObject((void *)msgArg, 0x110002, p1, 0);
        }
        break;
      case 0x110003:
        if (sub->typeBit == 86 && *(s16 *)(animUpdateBytes + 0x58) > 175) {
          ObjMsg_SendToObject((void *)msgArg, 0x110003, p1, 0);
        }
        break;
      case 0xA0005:
        GameBit_Set(sub->typeBit, 1);
        break;
    }
  }

  for (i = 0; i < animUpdate->eventCount; i++) {
    if (animUpdate->eventIds[i] == 1) {
      if (GameBit_Get(84) != 0 && GameBit_Get(85) != 0 && GameBit_Get(86) != 0) {
        GameBit_Set(1248, 1);
      }
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cfperch_update(int *obj) {
    if (((GameObject *)obj)->unkF4 != 0) {
        if (GameBit_Get(0x50) == 0) {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
    ((GameObject *)obj)->unkF4 = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cfmaincrystal_init(int *obj, u8 *def) {
    CfMainCrystalState *state = ((GameObject *)obj)->extra;
    *(s16 *)obj = (s16)((s32)*(s8 *)((char *)def + 0x18) << 8);
    if (*(s8 *)((char *)def + 0x19) == 0) {
        state->chime[0] = 0x28;
        state->chime[1] = 0;
        state->chime[2] = 0;
        state->chime[3] = 0x46;
        ((ObjAnimComponent *)obj)->bankIndex = 1;
        state->unk158 = 0;
    }
    ObjMsg_AllocQueue(obj, 2);
}
#pragma peephole reset
#pragma scheduling reset

extern void vecRotateZXY(s16* rotIn, f32* outVec);
extern int barrelgener_getLinkId(int barrel);
extern f32 lbl_803E42C4;
extern f32 lbl_803E42C8;
extern f32 lbl_803E42CC;
extern f32 lbl_803E42D0;
extern f32 lbl_803E42D4;
extern f32 lbl_803E42D8;
extern f32 lbl_803E42DC;

/* gunpowderbarrel_launchAtTarget: gunpowder-barrel "throw at target" launch. Seeds state's
 * launch velocity (state+0x20..28) from a per-axis pair scaled by the
 * player's strength (player_state[0x298]), or a fixed pair when the flag
 * is clear. Builds a rotation-vec from state[0x50], runs the 3-vec rotor
 * via vecRotateZXY, sets thrown/inflight flags, plays sfx 0xd3. When
 * state[0x48] bit 0x40 is set, looks up the linked barrel by data[0x1a]
 * (or the nearest one if 0), temporarily moves obj to that barrel's
 * position so saveGame_saveObjectPos latches the target slot, then
 * restores. */
#pragma scheduling off
#pragma peephole off
void gunpowderbarrel_launchAtTarget(int obj, u8 flag) {
    GunpowderBarrelState* state = ((GameObject *)obj)->extra;
    u8* playerState;
    s16 stk[8];
    f32 fz;
    int target;
    f32 sx, sy, sz;

    playerState = *(u8**)((u8*)Obj_GetPlayerObject() + 0xb8);
    state->throwVelX = lbl_803E42C0;
    if (flag != 0) {
        state->throwVelY = lbl_803E42C8 * *(f32*)(playerState + 0x298) + lbl_803E42C4;
        state->throwVelZ = lbl_803E42D0 * *(f32*)(playerState + 0x298) + lbl_803E42CC;
    } else {
        state->throwVelY = lbl_803E42D4;
        state->throwVelZ = lbl_803E42D8;
    }
    fz = lbl_803E42C0;
    *(f32*)((u8*)stk + 0xc) = fz;
    *(f32*)((u8*)stk + 0x10) = fz;
    *(f32*)((u8*)stk + 0x14) = fz;
    *(f32*)((u8*)stk + 0x8) = lbl_803E42DC;
    stk[2] = 0;
    stk[1] = 0;
    stk[0] = state->launchYaw;
    vecRotateZXY(stk, &state->throwVelX);
    state->motionFlags = (u8)(state->motionFlags | 1);
    Sfx_PlayFromObject(obj, SFXsk_baptr6_c);
    state->motionFlags = (u8)(state->motionFlags | 2);
    if ((state->configFlags & 0x40) != 0) {
        u8* params = *(u8**)&((GameObject *)obj)->anim.placementData;
        target = 0;
        if (*(s16*)(params + 0x1a) != 0) {
            int count;
            int* barrels = (int*)ObjGroup_GetObjects(0x3a, &count);
            int i;
            int* p = barrels;
            for (i = 0; i < count; i++) {
                if (((GunpowderbarrelLaunchAtTargetPlacement *)params)->unk1A == barrelgener_getLinkId(*p)) {
                    target = barrels[i];
                    break;
                }
                p++;
            }
        } else {
            target = ObjGroup_FindNearestObject(0x3a, obj, (f32*)0);
        }
        if (target != 0) {
            sx = ((GameObject *)obj)->anim.localPosX;
            sy = ((GameObject *)obj)->anim.localPosY;
            sz = ((GameObject *)obj)->anim.localPosZ;
            ((GameObject *)obj)->anim.localPosX = ((GameObject *)target)->anim.localPosX;
            ((GameObject *)obj)->anim.localPosY = ((GameObject *)target)->anim.localPosY;
            ((GameObject *)obj)->anim.localPosZ = ((GameObject *)target)->anim.localPosZ;
            saveGame_saveObjectPos(obj);
            ((GameObject *)obj)->anim.localPosX = sx;
            ((GameObject *)obj)->anim.localPosY = sy;
            ((GameObject *)obj)->anim.localPosZ = sz;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E4230;
extern f32 lbl_803E4234;
extern f32 lbl_803DBE4C;

typedef struct { u8 _p0 : 1; u8 spitLatch : 1; u8 _p1 : 6; } WormSpitByte;

/* EN v1.0 0x8019E3F4  size: 372b  fn_8019E3F4: pick the burrow/surface move
 * from the vertical speed, clamp the playback rate, latch the spit SFX
 * while surfacing fast, and advance the current move. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
int fn_8019E3F4(int* obj)
{
    f32 speed;
    BabyCloudRunnerState* sub = ((GameObject *)obj)->extra;
    if (((GameObject *)obj)->anim.currentMove != 5 && ((GameObject *)obj)->anim.currentMove != 0xd) {
        ObjAnim_SetCurrentMove((int)obj, 0xd, ((GameObject *)obj)->anim.currentMoveProgress, 0);
    }
    if (((GameObject *)obj)->anim.currentMove == 5 && ((GameObject *)obj)->anim.velocityY > lbl_803E422C) {
        ObjAnim_SetCurrentMove((int)obj, 0xd, ((GameObject *)obj)->anim.currentMoveProgress, 0);
    }
    if (((GameObject *)obj)->anim.currentMove == 0xd && ((GameObject *)obj)->anim.velocityY < lbl_803E4218) {
        ObjAnim_SetCurrentMove((int)obj, 5, ((GameObject *)obj)->anim.currentMoveProgress, 0);
    }
    speed = ((GameObject *)obj)->anim.velocityY * lbl_803DBE4C + lbl_803E4230;
    speed *= lbl_803E4234;
    if (speed < lbl_803E4218) {
        speed = lbl_803E4218;
    }
    if (speed > lbl_803E4234) {
        speed = lbl_803E4234;
    }
    if (((GameObject *)obj)->anim.currentMove == 0xd) {
        if (((GameObject *)obj)->anim.currentMoveProgress > lbl_803E4234) {
            if (!((WormSpitByte*)&sub->spitFlags)->spitLatch) {
                Sfx_PlayFromObject((int)obj, SFXand_spitout);
                ((WormSpitByte*)&sub->spitFlags)->spitLatch = 1;
            }
        } else {
            ((WormSpitByte*)&sub->spitFlags)->spitLatch = 0;
        }
    }
    ((int(*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)((int)obj, speed, timeDelta, 0);
    return 1;
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

extern int objUpdateOpacity(int sub);
extern f32 lbl_803E4288;

/* EN v1.0 0x8019FCF4  size: 484b  cfprisonuncle_render: render the uncle and/or
 * his held model depending on the rescue gamebits, opacity and visibility;
 * when path-following, snap the held model to the path point first. */
#pragma scheduling off
#pragma peephole off
void cfprisonuncle_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    CfPrisonUncleState* sub = ((GameObject *)obj)->extra;
    if (GameBit_Get(0x50) != 0) {
        if (*(void**)&sub->target != NULL && objUpdateOpacity(sub->target) != 0) {
            ((void(*)(int,int,int,int,int,f32))objRenderFn_8003b8f4)(sub->target, p2, p3, p4, p5, lbl_803E4288);
        }
    } else if (GameBit_Get(0x4d) != 0 && visible != 0) {
        ((void(*)(int*,int,int,int,int,f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4288);
        if (*(void**)&sub->target != NULL && objUpdateOpacity(sub->target) != 0) {
            ((void(*)(int,int,int,int,int,f32))objRenderFn_8003b8f4)(sub->target, p2, p3, p4, p5, lbl_803E4288);
        }
    } else if (sub != NULL && *(void**)&sub->target != NULL) {
        if (sub->captured == 0) {
            if (visible != 0) {
                if (objUpdateOpacity(sub->target) != 0) {
                    ((void(*)(int,int,int,int,int,f32))objRenderFn_8003b8f4)(sub->target, p2, p3, p4, p5, lbl_803E4288);
                    ObjPath_GetPointWorldPosition(sub->target, 0, (char*)obj + 0xc, (char*)obj + 0x10, (char*)obj + 0x14, 0);
                }
                ((void(*)(int*,int,int,int,int,f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4288);
            }
        } else {
            if (objUpdateOpacity(sub->target) != 0) {
                ((void(*)(int,int,int,int,int,f32))objRenderFn_8003b8f4)(sub->target, p2, p3, p4, p5, lbl_803E4288);
            }
            if (visible != 0) {
                ((void(*)(int*,int,int,int,int,f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4288);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32  sqrtf(f32 x);
extern void normalize(f32* x, f32* y, f32* z);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern f32  lbl_803E4124;
extern f32  lbl_803E4128;

/* EN v1.0 0x8019B1D8  size: 544b  fn_8019B1D8: steer the object toward the
 * target: scale its velocity along the normalized delta, blend the yaw by
 * speed over distance, move it and keep the chase move playing. Returns 1
 * when already within the closing threshold. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
int fn_8019B1D8(int* obj, int* target, f32 speed, int p4)
{
    f32 dist;
    f32 dx;
    f32 dy;
    f32 dz;
    s16 d;
    if (target == NULL) {
        return 0;
    }
    dx = ((GameObject *)target)->anim.localPosX - ((GameObject *)obj)->anim.localPosX;
    dy = ((GameObject *)target)->anim.localPosY - ((GameObject *)obj)->anim.localPosY;
    dz = ((GameObject *)target)->anim.localPosZ - ((GameObject *)obj)->anim.localPosZ;
    dist = sqrtf(dz * dz + (dx * dx + dy * dy));
    if (dist < lbl_803E4124 * speed) {
        return 1;
    }
    normalize(&dx, &dy, &dz);
    ((GameObject *)obj)->anim.velocityX = timeDelta * (dx * speed);
    ((GameObject *)obj)->anim.velocityY = timeDelta * (dy * speed);
    ((GameObject *)obj)->anim.velocityZ = timeDelta * (dz * speed);
    d = (*(s16*)target + 0x8000) - (u16)*(s16*)obj;
    if (d > 0x8000) {
        d = d - 0xffff;
    }
    if (d < -0x8000) {
        d = d + 0xffff;
    }
    *(s16*)obj = (f32)*(s16*)obj + ((lbl_803E4128 + (f32)d) * (speed * timeDelta)) / dist;
    objMove((int)obj, ((GameObject *)obj)->anim.velocityX, ((GameObject *)obj)->anim.velocityY, ((GameObject *)obj)->anim.velocityZ);
    if (((GameObject *)obj)->anim.currentMove != 0x1a) {
        ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
    }
    ((int(*)(int*, f32, int))ObjAnim_SampleRootCurvePhase)(obj, speed, p4);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

extern int seqStreamLookupFn_8007fff8(void *table, int count, int key);
extern u8  lbl_80322A48[];
extern u8  lbl_80322A68[];
extern f32 lbl_803E41C8;
extern f32 lbl_803E41CC;
extern f32 lbl_803E4168;

typedef struct {
    int i0;
    f32 f4;
    f32 f8;
    f32 fc;
    u8  b10;
    u8  b11;
    u8  pad12[2];
    int link14;
} WindLiftSlot;

typedef struct {
    int duration;
    int seqId;
    int delay;
    int gamebit;
    int pad10;
    int timer;
    WindLiftSlot slots[14];
    int pad168;
    int pad16c;
    f32 liftHeight;
    u8  musicOn : 1;
    u8  active : 1;
    u8  _f2 : 6;
} WindLiftSub;

/* EN v1.0 0x8019D2AC  size: 708b  windlift_init: look up the lift's sequence
 * timings, scale its rise height from the def byte, arm it from the
 * gamebits and clear all 14 rider slots. */
#pragma scheduling off
#pragma peephole off
void windlift_init(int* obj, u8* def)
{
    int i;
    WindLiftSub* sub = ((GameObject *)obj)->extra;
    sub->seqId = ((WindliftObjectDef *)def)->unk1E;
    sub->duration = seqStreamLookupFn_8007fff8(lbl_80322A48, 4, sub->seqId);
    sub->gamebit = seqStreamLookupFn_8007fff8(lbl_80322A68, 3, sub->seqId);
    if (sub->gamebit == 0) {
        sub->gamebit = -1;
    }
    if (sub->duration == 0) {
        sub->duration = 100;
    }
    sub->delay = ((WindliftObjectDef *)def)->unk1C;
    sub->timer = 0;
    if (*(s8*)(def + 0x19) != 0) {
        sub->liftHeight = lbl_803E41C8 * (f32)*(s8*)(def + 0x19);
    } else {
        sub->liftHeight = lbl_803E41CC;
    }
    ((GameObject *)obj)->anim.rootMotionScale = (*(f32*)(*(char**)&((GameObject *)obj)->anim.modelInstance + 4) * sub->liftHeight) / lbl_803E41CC;
    if (GameBit_Get(0x57) != 0 || sub->duration >= 0xa) {
        sub->timer = 0x3c;
    }
    sub->active = 1;
    if (sub->gamebit != -1) {
        if (GameBit_Get(sub->gamebit) != 0) {
            sub->timer = 0x3c;
        } else {
            sub->active = 0;
            ((GameObject *)obj)->anim.alpha = 0;
        }
    }
    {
        f32 v2 = lbl_803E416C;
        f32 v1 = lbl_803E4168;
        for (i = 0; i < 14; i++) {
            sub->slots[i].b10 = 0;
            sub->slots[i].b10 &= ~0xf1;
            sub->slots[i].f4 = v1;
            sub->slots[i].fc = v2;
            sub->slots[i].f8 = v2;
            sub->slots[i].i0 = 0;
            sub->slots[i].b11 = 0;
        }
    }
    ObjGroup_AddObject(obj, 0x49);
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E42E0;
extern f32 lbl_803E42E4;
extern const f32 lbl_803E42E8;
extern f32 lbl_803E42EC;
extern f32 lbl_803E42F0;

/* EN v1.0 0x801A0F58  size: 728b  fn_801A0F58: home the object on the nearest
 * group-0x1e object above it, scaling velocity and the two heading words by
 * approach rate; on a steep approach play the dive cue and bump the target's
 * cycle phase. */
#pragma scheduling off
#pragma peephole off
void fn_801A0F58(int* obj, s16 a, s16 b)
{
    f32 dx;
    f32 dz;
    f32 dy2;
    f32 scale;
    f32 rate;
    f32 dy;
    int v;
    int w;
    char* player;
    char* near;
    f32 radius = lbl_803E42E0;
    player = (char*)Obj_GetPlayerObject();
    near = (char*)ObjGroup_FindNearestObject(0x1e, obj, &radius);
    if (near == NULL) {
        return;
    }
    dy = *(f32*)(near + 0x10) - *(f32*)(player + 0x10);
    dy = (dy >= 0.0f) ? dy : -dy;
    if (dy < lbl_803E42E4) {
        return;
    }
    dx = *(f32*)(near + 0xc) - ((GameObject *)obj)->anim.localPosX;
    dy2 = *(f32*)(near + 0x10) - ((GameObject *)obj)->anim.localPosY;
    scale = 0.0f;
    if (dy2 > scale) {
        return;
    }
    dz = *(f32*)(near + 0x14) - ((GameObject *)obj)->anim.localPosZ;
    rate = (dy2 != scale) ? ((GameObject *)obj)->anim.velocityY / dy2 : scale;
    if (rate >= lbl_803E42DC) {
        Sfx_PlayFromObject((int)obj, 0xd2);
        rate = lbl_803E42DC;
        ((GameObject *)obj)->anim.velocityY = dy2;
        *(f32*)(near + 0xc) += lbl_803E42E8;
        *(f32*)(near + 0x2c) += lbl_803E42E8;
        if (*(f32*)(near + 0x2c) > lbl_803E42EC) {
            *(f32*)(near + 0xc) -= *(f32*)(near + 0x2c);
            *(f32*)(near + 0x2c) = 0.0f;
        }
        ((GameObject *)obj)->anim.rotY = 0;
        ((GameObject *)obj)->anim.rotZ = 0;
        a = 0;
        b = 0;
    }
    ((GameObject *)obj)->anim.velocityX = dx * rate;
    ((GameObject *)obj)->anim.velocityZ = dz * rate;
    v = a;
    if (v != 0) {
        f32 t;
        if (v == 1) {
            t = (lbl_803E42F0 - (f32)(u16)((GameObject *)obj)->anim.rotY) * rate;
        } else {
            t = (f32)(u16)((GameObject *)obj)->anim.rotY * (rate * (f32)v);
        }
        ((GameObject *)obj)->anim.rotY = (f32)((GameObject *)obj)->anim.rotY + t;
    }
    w = b;
    if (w != 0) {
        f32 t;
        if (w == 1) {
            t = 0.0f;
        } else {
            t = (f32)(u16)((GameObject *)obj)->anim.rotZ * (rate * (f32)w);
        }
        ((GameObject *)obj)->anim.rotZ = (f32)((GameObject *)obj)->anim.rotZ + t;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void* getTrickyObject(void);
extern f32 lbl_803E4248;

/* EN v1.0 0x8019E81C  size: 920b  babycloudrunner_SeqFn: range-check the
 * runner against the player and its trigger radii, chirp for queued cues,
 * then steer toward the player (or Tricky) per the current behaviour state. */
#pragma scheduling off
#pragma peephole off
int babycloudrunner_SeqFn(int* obj, int unused, ObjAnimUpdateState *animUpdate)
{
    u8 *animUpdateBytes = (u8 *)animUpdate;
    s8 inRange;
    s8 i;
    int yaw;
    char* player;
    f32 dx;
    f32 dz;
    f32 distSq;
    u8* def = *(u8**)&((GameObject *)obj)->anim.placementData;
    BabyCloudRunnerState* sub = ((GameObject *)obj)->extra;
    if (((GameObject *)obj)->unkB4 == 4) {
        return 0;
    }
    animUpdate->sequenceEventActive = 0;
    player = (char*)Obj_GetPlayerObject();
    dx = *(f32*)(player + 0xc) - *(f32*)(def + 8);
    dz = *(f32*)(player + 0x14) - *(f32*)(def + 0x10);
    distSq = dx * dx + dz * dz;
    if (distSq < (f32)((*(s16*)(def + 0x1a) / 2) * (*(s16*)(def + 0x1a) / 2))) {
        inRange = 1;
    } else {
        inRange = 0;
    }
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
    {
        BabyCloudRunnerState* sub2 = ((GameObject *)obj)->extra;
        char* pp = (char*)Obj_GetPlayerObject();
        u8* def2 = *(u8**)&((GameObject *)obj)->anim.placementData;
        int found = 0;
        if (Vec_distance(pp + 0x18, (char*)obj + 0x18) < (f32)*(s16*)(def2 + 0x1a)
            && sub2->runnerState == 3
            && (((GameObject *)obj)->objectFlags & 0x1000) == 0) {
            found = 1;
        }
        if (found != 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x10;
        } else {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
        }
    }
    if (inRange == 0 && sub->runnerState == 2) {
        f32 radius = (f32)*(s16*)(def + 0x18);
        if ((void*)ObjGroup_FindNearestObject(3, obj, &radius) != NULL) {
            inRange = 1;
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++) {
        if (animUpdate->eventIds[i] == 1) {
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
        }
    }
    sub->behaviourState = 0;
    switch (sub->behaviourState) {
    case 10:
    case 11:
        if (sub->linkedObj != NULL) {
            sub->scale *= lbl_803E4248;
            *(f32*)((char*)sub->linkedObj + 8) = sub->scale;
        }
        sub->behaviourState = 0xb;
        if (Vec_distance((char*)obj + 0x18, player + 0x18) < (f32)*(s16*)(def + 0x1a)
            && (*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0) {
            sub->behaviourState = 7;
            return 4;
        }
        break;
    case 0:
    case 8:
        animUpdate->hitVolumePair &= ~0x2;
        yaw = Obj_GetYawDeltaToObject((int)obj, (int)player, 0);
        fn_8003ADC4(obj, (int*)player, (char*)sub + 0x3c, 0x28, 0, 3);
        *(s16*)obj += (s16)yaw / 8;
        if (inRange != 0) {
            animUpdateBytes[0x90] |= 4;
        } else {
            animUpdateBytes[0x90] = 8;
        }
        break;
    case 5:
        animUpdate->hitVolumePair &= ~0x2;
        yaw = Obj_GetYawDeltaToObject((int)obj, (int)getTrickyObject(), 0);
        fn_8003ADC4(obj, (int*)getTrickyObject(), (char*)sub + 0x3c, 0x28, 0, 3);
        *(s16*)obj += (s16)yaw / 8;
        break;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern void Sfx_StopObjectChannel(int obj, int ch);


/* EN v1.0 0x8019F540  size: 1000b  cfprisonguard_SeqFn: drive the guard state
 * machine - ramp/reset the alarm on cues, bail when captured or freed, watch
 * the player distance/water impacts and chase or stand down, with idle digging
 * SFX and queued-message drain. */
#pragma scheduling off
#pragma peephole off
int cfprisonguard_SeqFn(int* obj, int unused, ObjAnimUpdateState *animUpdate)
{
    char* player;
    CfPrisonGuardState* sub = ((GameObject *)obj)->extra;
    s8 gb50;
    s8 gb48;
    s8 moved;
    f32 dist;
    int msgB;
    int msgA;
    int payload = 0;
    u8* def = *(u8**)&((GameObject *)obj)->anim.placementData;
    switch (animUpdate->triggerCommand) {
    case 0x29:
        sub->alarmRamp = lbl_803E4260;
        break;
    case 4:
        sub->guardState = 6;
        return 0;
    case 5:
        sub->alarmRamp = lbl_803E4264 * (f32)framesThisStep + sub->alarmRamp;
        break;
    }
    if (((GameObject *)obj)->unkB4 < 0) {
        return 0;
    }
    ObjHits_EnableObject(obj);
    gb50 = GameBit_Get(0x50);
    gb48 = GameBit_Get(0x48);
    if ((sub->flags & 2) != 0 && GameBit_Get(0x4d) != 0) {
        sub->flags &= ~0x2;
        return 4;
    }
    if (gb50 != 0) {
        return 4;
    }
    if (gb50 != 0 || sub->guardState == 5) {
        sub->guardState = 5;
        return 0;
    }
    moved = 0;
    player = (char*)Obj_GetPlayerObject();
    switch (sub->guardState) {
    case 0:
        fn_8003B228(obj, sub);
        dist = Vec_distance((char*)obj + 0x18, player + 0x18);
        if (gb48 == 0) {
            if (dist < (f32)((CfprisonguardPlacement *)def)->unk1A
                || waterfx_consumePendingImpactNearPoint(&((GameObject *)obj)->anim.localPosX, lbl_803E4268) != 0) {
                if (objGetAnimState80A(player) != 0x40) {
                    moved = 1;
                    sub->guardState = 4;
                } else {
                    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                    sub->guardState = 5;
                    sub->stateTimer = 0x14;
                    (*gObjectTriggerInterface)->runSequence(2, obj, -1);
                    return 4;
                }
            }
        }
        break;
    case 2:
        if ((sub->stateTimer -= framesThisStep) <= 0) {
            sub->guardState = 1;
        }
        fn_8003B228(obj, sub);
        break;
    case 1:
        dist = Vec_distance((char*)obj + 0x18, player + 0x18);
        if (gb48 == 0) {
            if (dist < (f32)((CfprisonguardPlacement *)def)->unk1A) {
                if (objGetAnimState80A(player) != 0x40) {
                    moved = 1;
                    sub->guardState = 4;
                } else {
                    sub->guardState = 2;
                }
            }
        }
        break;
    case 3:
        if ((sub->stateTimer -= framesThisStep) <= 0) {
            sub->guardState = 0;
        }
        break;
    case 5:
        return 0;
    case 6:
        return 0;
    case 7:
        moved = 1;
        sub->guardState = 4;
        break;
    }
    if (((GameObject *)obj)->anim.currentMove == 0x103 || ((GameObject *)obj)->anim.currentMove == 0x2e) {
        Sfx_PlayFromObject((int)obj, SFXsk_doggydig11);
    } else {
        Sfx_StopObjectChannel((int)obj, 0x10);
    }
    if (gb50 != 0 && sub->capturedLatch == 0) {
        moved = 1;
    }
    if (moved != 0) {
        return 4;
    }
    sub->capturedLatch = gb50;
    animUpdate->sequenceEventActive = 0;
    while (ObjMsg_Pop(obj, &msgA, &msgB, &payload) != 0) {
    }
    if (animUpdate->triggerCommand == 1) {
        getLActions(obj, obj, 0x18, 0, 0, 0);
        animUpdate->triggerCommand = 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern f32  Vec_xzDistance(void* a, void* b);
extern void fn_80296220(int* rider, f32 v);
extern f32 lbl_803E4170;
extern f32 lbl_803E4174;
extern f32 lbl_803E4178;
extern f32 lbl_803E417C;
extern f32 lbl_803E4180;
extern f32 lbl_803E4184;
extern f32 lbl_803E4188;
extern f32 lbl_803E418C;
extern f32 lbl_803E4194;
extern f32 lbl_803E4198;
extern f32 lbl_803E419C;
extern f32 lbl_803E41A0;
extern f32 lbl_803E41A4;
extern f32 lbl_803E41A8;
extern f32 lbl_803E41AC;
extern f32 lbl_803E41B0;
extern f32 lbl_803E41B4;
extern f32 lbl_803E41B8;

/* EN v1.0 0x8019C784  size: 1396b  fn_8019C784: per-rider wind lift physics -
 * track the rider while above the lift and in range, send the lift/drop
 * messages on state edges, and integrate the rise speed with ramp-up,
 * oscillation damping and player-mode handoff. */
#pragma scheduling off
#pragma peephole off
void fn_8019C784(int* obj, int* rider, WindLiftSlot* slot, f32 pull, int gb, int pm, uint dur, f32 height)
{
    char* player;
    f32 dy;
    f32 dist;
    f32 factor;
    f32 scale;
    u8 flags;
    u8 fl;
    int fe;
    player = (char*)Obj_GetPlayerObject();
    dy = *(f32*)((char*)rider + 0x10) - ((GameObject *)obj)->anim.localPosY;
    if (dy < lbl_803E416C) {
        return;
    }
    dist = Vec_xzDistance((char*)rider + 0x18, (char*)obj + 0x18);
    if (dist > lbl_803E4170 + height && (slot->b10 & 0xe0) == 0) {
        return;
    }
    flags = slot->b10;
    if ((flags & 0x80) != 0 && gb != 0) {
        return;
    }
    if (dist < height) {
        if ((flags & 0xe0) == 0 || (flags & 0x80) != 0) {
            if (gb != 0 && (!flags & 0x80) != 0 && dy < lbl_803E4174) {
                slot->b10 |= 0x80;
                return;
            }
            if ((flags & 0x2) != 0) {
                if (dy / pull > lbl_803E4178) {
                    slot->b10 |= 0x4;
                    slot->b10 &= ~0x8;
                } else {
                    slot->b10 |= 0x8;
                    slot->b10 &= ~0x4;
                }
                slot->b10 &= ~0x2;
            }
            if (gb == 0) {
                slot->b10 |= 0x40;
                slot->b10 &= ~0x20;
                ObjMsg_SendToObject(rider, 0xf, obj, (((slot->b10 & 0xe0) >> 4) << 8) | dur);
                slot->b10 &= ~0x80;
            } else {
                if (dy > lbl_803E417C) {
                    ObjMsg_SendToObject(rider, 0xf, obj, (((slot->b10 & 0xe0) >> 4) << 8) | dur);
                }
                slot->b10 |= 0x20;
                slot->b10 &= ~0x40;
            }
        }
        scale = lbl_803E4180;
        fl = slot->b10;
        fe = fl & 0xe;
        if (fe != 0 && (fl & 8) != 0 && gb == 0) {
            pull = pull * lbl_803E4184;
        }
        pull = pull * lbl_803E4184;
        if (pull <= lbl_803E4170) {
            return;
        }
        if (dy < lbl_803E4188) {
            dy = lbl_803E4188;
        }
        if (gb == 0) {
            f32 lim = pull - (pull / lbl_803E418C) * (slot->fc * (slot->fc * slot->fc));
            f32 t;
            if (dy > lim) {
                t = lbl_803E416C;
            } else {
                f32 d = lim - dy;
                if (d > lbl_803E4174) {
                    t = lbl_803E4190;
                } else {
                    t = d / lbl_803E4174;
                }
            }
            factor = t;
            slot->b10 |= 1;
            if (((slot->fc < lbl_803E4194 && slot->b11 % 2 != 0)
                 || (slot->fc > lbl_803E4198 && slot->b11 % 2 == 0))
                && (slot->b10 & 8) != 0) {
                if (slot->b11++ > 2) {
                    slot->b10 &= ~0x8;
                    slot->b10 |= 0x4;
                }
            }
        } else {
            f32 v = slot->fc;
            f32 thr;
            if (fe != 0) {
                thr = lbl_803E4168;
            } else {
                thr = lbl_803E419C;
            }
            if (v > thr) {
                slot->b11 = 1;
            }
            scale = scale * lbl_803E41A0;
            if (slot->b11 == 0) {
                f32 c;
                if ((slot->b10 & 0xe) != 0) {
                    c = lbl_803E4190 - dy / (lbl_803E41A4 * pull);
                } else {
                    c = lbl_803E4190 - dy / (lbl_803E41A8 * pull);
                }
                if (c < lbl_803E416C) {
                    c = lbl_803E416C;
                }
                factor = c * c;
            } else {
                factor = lbl_803E41AC;
            }
        }
        slot->f8 = scale * factor - lbl_803E41B0;
        slot->fc = slot->fc + slot->f8;
        if (slot->fc > lbl_803E41B4) {
            slot->fc = lbl_803E41B4;
        }
        if (lbl_803E416C == slot->fc) {
            slot->fc = lbl_803E41B8;
        }
        if (dy < lbl_803E4174 && gb != 0) {
            slot->fc = lbl_803E416C;
            slot->b11 = 0;
            ObjMsg_SendToObject(rider, 0x10, obj, gb);
            slot->b10 |= 0x80;
            if (pm != 0) {
                *(f32*)(player + 0x28) = lbl_803E416C;
            }
        }
        if (pm != 0) {
            fn_80296220(rider, slot->fc);
        } else {
            *(f32*)((char*)rider + 0x10) = slot->fc * timeDelta + *(f32*)((char*)rider + 0x10);
            *(f32*)((char*)rider + 0x28) = slot->fc * timeDelta;
        }
    } else {
        if (pm != 0) {
            fn_80296220(rider, lbl_803E416C);
        }
        if (pm == 0) {
            ObjMsg_SendToObject(rider, 0x10, obj, gb);
            slot->b10 &= ~0xf1;
            slot->fc = lbl_803E416C;
            slot->b11 = 0;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int  Obj_SetActiveModelIndex(int* obj, int idx);
extern f32  lbl_803E41BC;

/* EN v1.0 0x8019CD98  size: 1300b  windlift_update: fade the lift opacity
 * with its gamebit, spin up over the first second, then assign every nearby
 * group-0x16 object (and the player) to a rider slot and run the lift
 * physics on each. */
#pragma scheduling off
#pragma peephole off
void windlift_update(int* obj)
{
    u8* def;
    WindLiftSub* sub = ((GameObject *)obj)->extra;
    int level;
    int gb2;
    char* player;
    f32 pull;
    int idx;
    int j;
    int found;
    int count;
    int** objs;
    def = *(u8**)&((GameObject *)obj)->anim.placementData;
    if (sub->active) {
        level = (int)(lbl_803E41BC * timeDelta + (f32)(int)((GameObject *)obj)->anim.alpha);
        if (sub->gamebit != -1 && GameBit_Get(sub->gamebit) == 0) {
            sub->active = 0;
        }
    } else {
        level = (int)-(lbl_803E41BC * timeDelta - (f32)(int)((GameObject *)obj)->anim.alpha);
        if (sub->gamebit != -1 && GameBit_Get(sub->gamebit) != 0) {
            sub->active = 1;
        }
    }
    ((GameObject *)obj)->anim.alpha = (level < 0) ? 0 : ((level > 0xff) ? 0xff : level);
    if ((GameBit_Get(0x57) != 0 || sub->duration > 0xa) && sub->active) {
        int t = sub->timer;
        sub->timer = t + 1;
        if (t < 0x3c && GameBit_Get(sub->seqId) == 0) {
            *(s16*)obj -= ((framesThisStep * 100) * (sub->timer * sub->timer)) / 0x3c;
            Obj_SetActiveModelIndex(obj, 0);
            return;
        }
        Obj_SetActiveModelIndex(obj, 1);
        gb2 = GameBit_Get(sub->delay);
        {
            int m = (u16)framesThisStep * 0xb6;
            *(s16*)obj -= m * ((gb2 << 2) + 0xe);
        }
        pull = (f32)((WindliftPlacement *)def)->unk1A;
        player = (char*)Obj_GetPlayerObject();
        if (GameBit_Get(sub->seqId) != 0) {
            if (!sub->musicOn) {
                sub->musicOn = 1;
                Music_Trigger(0xbd, 1);
            }
            if (player != NULL) {
                fn_8019C784(obj, (int*)player, &sub->slots[0], pull, gb2, 1, sub->duration, sub->liftHeight);
            }
        } else {
            if (sub->musicOn) {
                Music_Trigger(0xbd, 0);
                sub->musicOn = 0;
            }
            if ((sub->slots[0].b10 & 0xe0) != 0) {
                u8 b;
                fn_80296220((int*)player, lbl_803E416C);
                b = sub->slots[0].b10;
                if ((b & 0xe) != 0) {
                    sub->slots[0].b10 = b | 2;
                }
                sub->slots[0].fc = lbl_803E416C;
                sub->slots[0].b11 = 0;
                sub->slots[0].b10 &= ~0xf1;
            }
        }
        objs = (int**)ObjGroup_GetObjects(0x16, &count);
        count = count + 1;
        if (count > 0xe) {
            count = 0xe;
        }
        for (j = 1; j < 14; j++) {
            sub->slots[j].link14 = -1;
        }
        for (idx = 1; idx < count; idx++) {
            found = -1;
            for (j = 1; j < 14; j++) {
                if ((u32)sub->slots[j].i0 == (u32)*objs) {
                    found = j;
                }
            }
            if (found == -1) {
                for (j = 1; j < 0xe; j++) {
                    if ((u32)sub->slots[j].i0 == 0) {
                        found = j;
                        sub->slots[j].b10 = 0;
                        sub->slots[j].b10 &= ~0xf1;
                        sub->slots[j].f4 = lbl_803E4168;
                        sub->slots[j].fc = lbl_803E416C;
                        sub->slots[j].f8 = lbl_803E416C;
                        sub->slots[j].i0 = 0;
                        sub->slots[j].b11 = 0;
                        j = 2000;
                    }
                }
                if (found == -1) {
                    return;
                }
                sub->slots[found].i0 = (int)*objs;
            }
            sub->slots[found].link14 = found;
            {
                int* rider = *objs;
                if ((*(u16*)((char*)rider + 0xb0) & 0x1000) != 0) {
                    objs++;
                } else if (rider != NULL) {
                    fn_8019C784(obj, *objs++, &sub->slots[found], pull, gb2, 0, sub->duration, sub->liftHeight);
                }
            }
        }
        for (j = 1; j < 14; j++) {
            if (sub->slots[j].link14 == -1) {
                sub->slots[j].i0 = 0;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int  fn_80080150(void* p);
extern int  timerCountDown(void* p);
extern int  randFn_80080100(int n);
extern void Obj_UpdateRomCurveFollowVelocity(int* obj, void* p, f32 a, f32 b, f32 c, int d);
extern void Obj_SmoothTurnAnglesTowardVelocity(int* obj, void* p, int n, f32 a, f32 b);
extern void fn_8014C66C(int* a, void* b);
extern int  dll_2E_func0D(int* obj, void* p, f32 f, int c, f32* a, f32* b);
extern int  lbl_80322B28[];
extern f32  lbl_803DBE38;
extern f32  lbl_803DBE3C;
extern f32  lbl_803DBE40;
extern f32  lbl_803DBE44;
extern f32  lbl_803DBE48;
extern f32  lbl_803E4238;
extern f32  lbl_803E424C;
extern f32  lbl_803E4250;
extern f32  lbl_803E4254;

typedef struct { s16 a, b, c; u8 pad[6]; f32 x, y, z; } RunnerTarget;

/* EN v1.0 0x8019EC34  size: 1908b  babycloudrunner_update: full runner brain -
 * despawn on its gamebit, run the captured/timer flow, follow its rom curve
 * while fleeing, hand off to the nearest sandworm, and once freed steer home
 * to the roost point. */
#pragma scheduling off
#pragma peephole off
void babycloudrunner_update(int* obj)
{
    char* player;
    BabyCloudRunnerState* sub;
    u8* def = *(u8**)&((GameObject *)obj)->anim.placementData;
    int found;
    u8* def2;
    int* near;
    BabyCloudRunnerState* sub2;
    int inRange;
    RunnerTarget tgt;
    int mode;
    f32 radius;
    sub = ((GameObject *)obj)->extra;
    player = (char*)Obj_GetPlayerObject();
    getTrickyObject();
    if (GameBit_Get(*(s16*)(def + 0x22)) != 0) {
        ((GameObject *)obj)->anim.flags |= 0x4000;
        sub->flags22C &= ~1;
        Obj_RemoveFromUpdateList(obj);
        ObjGroup_RemoveObject(obj, 0x20);
        ObjGroup_RemoveObject(obj, 3);
    }
    if (sub->runnerState == 2 && GameBit_Get(0x66) != 0) {
        (*gObjectTriggerInterface)->runSequence(6, obj, -1);
        (*gGameUIInterface)->airMeterSetShutdown();
    } else if (fn_80080150(sub) != 0) {
        sub->flags22C |= 1;
        sub->behaviourState = 0;
        if (((GameObject *)obj)->unkF4 < 0) {
            if (*(s16*)(def + 0x22) != -1) {
                GameBit_Set(*(s16*)(def + 0x22), 1);
            }
            ObjHits_DisableObject(obj);
            ((GameObject *)obj)->anim.flags |= 0x4000;
            sub->flags22C &= ~1;
            Obj_RemoveFromUpdateList(obj);
            ObjGroup_RemoveObject(obj, 0x20);
            ObjGroup_RemoveObject(obj, 3);
            ((GameObject *)obj)->anim.flags |= 0x4000;
        } else {
            ((GameObject *)obj)->unkF4 = ((GameObject *)obj)->unkF4 - 1;
        }
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        if (sub->runnerState == 0) {
            mode = 0x19;
            if ((*gRomCurveInterface)->initCurve((char*)sub + 0x124, obj, lbl_803E424C, &mode, 0) == 0) {
                sub->runnerState = 1;
                storeZeroToFloatParam((char*)sub + 0x238);
            }
        } else {
            if (randFn_80080100(500) != 0) {
                int r = randomGetRange(0, 3);
                objAudioFn_80039270((int)obj, (char*)sub + 0x6c, (u16)((s16*)sub->mutterSfxTable)[r]);
            }
            objAnimFn_80038f38((int)obj, (char*)sub + 0x6c);
            if (sub->runnerState == 1 || sub->runnerState == 2) {
                f32 speed = sub->curveSpeed;
                Obj_UpdateRomCurveFollowVelocity(obj, (char*)sub + 0x124, speed, lbl_803E4238 * speed, lbl_803E4250 * speed, 1);
                Obj_SmoothTurnAnglesTowardVelocity(obj, (char*)obj + 0x24, 0x1e, lbl_803E4238, lbl_803E4254);
                objMove((int)obj, *(f32*)((char*)obj + 0x24), *(f32*)((char*)obj + 0x28), *(f32*)((char*)obj + 0x2c));
                if (sub->runnerState == 1) {
                    if (sub->runnerIndex != -1 && GameBit_Get(sub->runnerIndex + 0xb2a) != 0) {
                        sub->runnerState = 2;
                        GameBit_Set(0x66, 0);
                        (*gGameUIInterface)->initAirMeter(lbl_80322B28[sub->runnerIndex], 0x5d1);
                        s16toFloat((int)((char*)sub + 0x238), (s16)lbl_80322B28[sub->runnerIndex]);
                    }
                    fn_8019E3F4(obj);
                    return;
                }
                if (sub->runnerState == 2) {
                    near = (int*)ObjGroup_FindNearestObject(3, obj, 0);
                    if (near == NULL || Vec_distance((char*)near + 0x18, (char*)sub + 0x18) >= lbl_803DBE38) {
                        if (near != NULL) {
                            fn_8014C66C(near, Obj_GetPlayerObject());
                        }
                    } else {
                        sandworm_turnTowardTargetAnim(obj, near, (u8*)sub, 0);
                        if (Vec_distance((char*)Obj_GetPlayerObject() + 0x18, (char*)near + 0x18) <= lbl_803DBE3C) {
                            fn_8014C66C(near, Obj_GetPlayerObject());
                        } else {
                            fn_8014C66C(near, obj);
                            if (((GameObject *)obj)->anim.currentMove != 0xd) {
                                ObjAnim_SetCurrentMove((int)obj, 0xd, ((GameObject *)obj)->anim.currentMoveProgress, 0);
                            }
                            ((int (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E422C, timeDelta, 0);
                        }
                    }
                    fn_8019E3F4(obj);
                }
            }
            inRange = Vec_distance((char*)obj + 0x18, player + 0x18) < (f32)(*(s16*)(def + 0x1a) / 2);
            if (sub->runnerState == 2) {
                radius = (f32)*(s16*)(def + 0x18);
                if (fn_80080150((char*)sub + 0x238) != 0) {
                    if ((*(u16*)((char*)Obj_GetPlayerObject() + 0xb0) & 0x1000) == 0 && timerCountDown((char*)sub + 0x238) != 0) {
                        (*gObjectTriggerInterface)->runSequence(6, obj, -1);
                        (*gGameUIInterface)->airMeterSetShutdown();
                        return;
                    }
                    (*gGameUIInterface)->runAirMeter((int)sub->countdownTimer);
                }
                if (inRange == 0 && (void*)ObjGroup_FindNearestObject(3, obj, &radius) != NULL) {
                    inRange = 1;
                }
                if (GameBit_Get(sub->runnerIndex + 0xb2e) != 0) {
                    sub->runnerState = 3;
                    (*gGameUIInterface)->airMeterSetShutdown();
                    Sfx_PlayFromObject((int)obj, SFXsp_lf_mutter4);
                    storeZeroToFloatParam((char*)sub + 0x238);
                }
            } else {
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
                sub2 = ((GameObject *)obj)->extra;
                {
                    char* pp = (char*)Obj_GetPlayerObject();
                    def2 = *(u8**)&((GameObject *)obj)->anim.placementData;
                    found = 0;
                    if (Vec_distance(pp + 0x18, (char*)obj + 0x18) < (f32)*(s16*)(def2 + 0x1a)
                        && sub2->runnerState == 3
                        && (((GameObject *)obj)->objectFlags & 0x1000) == 0) {
                        found = 1;
                    }
                }
                if (found != 0) {
                    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x10;
                } else {
                    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
                }
            }
            if (sub->runnerState == 3) {
                if (!((WormSpitByte*)&sub->spitFlags)->_p0) {
                    tgt.x = *(f32*)(def + 8);
                    tgt.y = *(f32*)(def + 0xc);
                    tgt.z = *(f32*)(def + 0x10);
                    tgt.a = sub->roostYaw;
                    tgt.b = 0;
                    tgt.c = 0;
                    ((GameObject *)obj)->anim.rotY = 0;
                    ((GameObject *)obj)->anim.rotZ = 0;
                    if (dll_2E_func0D(obj, &tgt, lbl_803DBE40, -1, &lbl_803DBE44, &lbl_803DBE48) != 0) {
                        ((WormSpitByte*)&sub->spitFlags)->_p0 = 1;
                        GameBit_Set(0x66, 0);
                    }
                    ((int (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803DBE44, timeDelta, 0);
                } else {
                    if (inRange != 0) {
                        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                        sub->unkB0 = 1;
                    }
                    sandworm_turnTowardTargetAnim(obj, (int*)Obj_GetPlayerObject(), (u8*)sub, 1);
                    if (((int (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)((int)obj, sub->animSpeed, timeDelta, 0) != 0) {
                        if (randFn_80080100(2) != 0) {
                            ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E4218, 0);
                        } else {
                            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E4218, 0);
                        }
                    }
                }
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void getEnvfxAct(int a, int b, int c, int d);
extern int  Sfx_IsPlayingFromObjectChannel(int obj, int ch);
extern void Sfx_SetObjectChannelVolume(int obj, int ch, int max, f32 vol);
extern void PSVECNormalize(f32* out, f32* in);
extern f32 lbl_803E41D8;
extern f32 lbl_803E41DC;
extern f32 lbl_803E41E0;
extern f32 lbl_803E41E4;
extern f32 lbl_803E41E8;
extern f32 lbl_803E41EC;
extern f32 lbl_803E41F0;
extern f32 lbl_803E41F4;
extern f32 lbl_803E41F8;
extern f32 lbl_803E41FC;
extern f32 lbl_803E4200;
extern f32 lbl_803E4204;

extern void Camera_EnableViewYOffset(void);
typedef struct { s16 a, b, c, d; u8 pad[4]; f32 x, y, z; } PartPayload;

/* EN v1.0 0x8019D9F0  size: 2112b  fn_8019D9F0: main crystal beam update -
 * collect the three pylon positions from messages, re-request missing ones,
 * emit the beam particles toward the crystal (and down from each pylon),
 * ramp the convergence charge, hum volume and per-beam chime timers. */
#pragma scheduling off
#pragma peephole off
void fn_8019D9F0(int* obj)
{
    char* p16;
    char* p32;
    int i;
    CfMainCrystalState* sub = ((GameObject *)obj)->extra;
    int idx;
    int count;
    PartPayload pay;
    f32 dir[3];
    int msgSrc;
    int msgType;
    int payload = 0;
    Obj_GetPlayerObject();
    Camera_EnableViewYOffset();
    while (ObjMsg_Pop(obj, &msgType, &msgSrc, &payload) != 0) {
        switch (msgType) {
        case 0x110001:
            sub->pylonX[0] = *(f32*)((char*)msgSrc + 0xc);
            sub->pylonY[0] = lbl_803E41D8;
            sub->pylonZ[0] = *(f32*)((char*)msgSrc + 0x14);
            sub->pylonTimer[0] = 1;
            break;
        case 0x110002:
            sub->pylonX[1] = *(f32*)((char*)msgSrc + 0xc);
            sub->pylonY[1] = lbl_803E41D8;
            sub->pylonZ[1] = *(f32*)((char*)msgSrc + 0x14);
            sub->pylonTimer[1] = 1;
            break;
        case 0x110003:
            sub->pylonX[2] = *(f32*)((char*)msgSrc + 0xc);
            sub->pylonY[2] = lbl_803E41D8;
            sub->pylonZ[2] = *(f32*)((char*)msgSrc + 0x14);
            sub->pylonTimer[2] = 1;
            break;
        case 0x110004:
            sub->crystalX = *(f32*)((char*)msgSrc + 0xc);
            sub->crystalY = *(f32*)((char*)msgSrc + 0x10);
            sub->crystalZ = *(f32*)((char*)msgSrc + 0x14);
            sub->crystalKnown = 1;
            break;
        }
    }
    if (sub->crystalKnown == 0) {
        ObjMsg_SendToObjects(0xdc, 5, obj, 0x110004, 0);
    }
    if (GameBit_Get(0x54) != 0 && sub->pylonTimer[0] == 0) {
        ObjMsg_SendToObjects(0xda, 4, obj, 0x110001, 0);
    }
    if (GameBit_Get(0x55) != 0 && sub->pylonTimer[1] == 0) {
        ObjMsg_SendToObjects(0xda, 4, obj, 0x110002, 0);
    }
    if (GameBit_Get(0x56) != 0 && sub->pylonTimer[2] == 0) {
        ObjMsg_SendToObjects(0xda, 4, obj, 0x110003, 0);
    }
    sub->beams[0].b1b = 0;
    sub->beams[1].b1b = 0;
    sub->beams[2].b1b = 0;
    sub->beams[3].b1b = 0;
    sub->beams[4].b1b = 0;
    sub->beams[5].b1b = 0;
    sub->beams[6].b1b = 0;
    sub->beams[7].b1b = 0;
    sub->beams[8].b1b = 0;
    sub->beams[9].b1b = 0;
    count = 0;
    idx = 0;
    if (sub->crystalKnown != 0) {
        if (GameBit_Get(0x57) != 0) {
            if (sub->pylonTimer[0] != 0) {
                sub->pylonTimer[0] = 0x78;
            }
            if (sub->pylonTimer[1] != 0) {
                sub->pylonTimer[1] = 0x78;
            }
            if (sub->pylonTimer[2] != 0) {
                sub->pylonTimer[2] = 0x78;
            }
            sub->charge = 0x5a;
        }
        i = 0;
        p16 = (char*)sub;
        p32 = (char*)sub;
        do {
            if (i < 3 && *(s16*)(p16 + 0x30) != 0) {
                CrystalBeam* sl = &sub->beams[idx++];
                sl->b1b = 1;
                sl->b18 = 0x7f;
                sl->b19 = 0x7f;
                sl->b1a = 0xff;
                sl->f0 = sub->crystalX;
                sl->f8 = lbl_803E41DC + sub->crystalY;
                sl->f10 = sub->crystalZ;
                dir[0] = *(f32*)p32 - sl->f0;
                dir[1] = (lbl_803E41E0 + *(f32*)(p32 + 0x10)) - sl->f8;
                dir[2] = *(f32*)(p32 + 0x20) - sl->f10;
                PSVECNormalize(dir, dir);
                pay.x = *(f32*)p32 - sub->crystalX;
                pay.y = (lbl_803E41E0 + *(f32*)(p32 + 0x10)) - sub->crystalY;
                pay.z = *(f32*)(p32 + 0x20) - sub->crystalZ;
                dir[0] = -dir[0];
                dir[1] = -dir[1];
                dir[2] = -dir[2];
                pay.d = i;
                (*gPartfxInterface)->spawnObject(obj, 0x7f4, &pay, 2, -1, dir);
                dir[0] = *(f32*)p32 - *(f32*)((char*)lbl_803DDB10 + 0xc);
                dir[1] = lbl_803E41E4;
                dir[2] = *(f32*)(p32 + 0x20) - *(f32*)((char*)lbl_803DDB10 + 0x14);
                PSVECNormalize(dir, dir);
                pay.x = lbl_803E41E8;
                pay.y = lbl_803E41DC;
                pay.z = lbl_803E41E8;
                pay.d = i + 3;
                (*gPartfxInterface)->spawnObject(lbl_803DDB10, 0x7f4, &pay, 2, -1, dir);
                pay.x = *(f32*)p32;
                pay.y = *(f32*)(p32 + 0x10);
                pay.z = *(f32*)(p32 + 0x20);
                if (sub->chime[3] > 0x14) {
                    pay.x = *(f32*)p32;
                    pay.y = *(f32*)(p32 + 0x10);
                    pay.z = *(f32*)(p32 + 0x20);
                    pay.c = i;
                }
                pay.x = *(f32*)p32;
                pay.y = *(f32*)(p32 + 0x10);
                pay.z = *(f32*)(p32 + 0x20);
                pay.c = i;
                sub->beams[idx++].b1b = 1;
                count++;
            }
            p16 += 2;
            p32 += 4;
            i++;
        } while (i < 3);
        if (sub->pylonTimer[0] + (sub->pylonTimer[1] + sub->pylonTimer[2]) < 0x12c
            && (int)randomGetRange(0, 3) == 0) {
            (*gPartfxInterface)->spawnObject(obj, 0x81, NULL, 0, -1, NULL);
        }
        if (sub->pylonTimer[0] != 0 || sub->pylonTimer[1] != 0 || sub->pylonTimer[2] != 0) {
            if (sub->chime[0] > 0x64) {
                sub->chime[0] = 0;
            }
            if (sub->chime[1] > 0x64) {
                sub->chime[1] = 0;
            }
            if (sub->chime[2] > 0x64) {
                sub->chime[2] = 0;
            }
            if (sub->chime[3] > 0x14) {
                sub->chime[3] = 0;
            }
            sub->chime[0] += framesThisStep;
            sub->chime[1] += framesThisStep;
            sub->chime[2] += framesThisStep;
            sub->chime[3] += framesThisStep;
        }
        if (count == 3) {
            if (sub->charge == 0) {
                Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
                getEnvfxAct(0, 0, 0x7f, 0);
            }
            sub->charge += framesThisStep;
        }
        if (sub->charge >= 0x3c) {
            f32 fr = (f32)(sub->charge - 0x3c) / lbl_803E41EC;
            CrystalBeam* sl = &sub->beams[idx];
            sl->b1b = 1;
            sl->b18 = 0;
            sl->b19 = 0;
            sl->b1a = 0;
            sl->f0 = ((GameObject *)obj)->anim.localPosX;
            sl->f8 = lbl_803E41F0 + ((GameObject *)obj)->anim.localPosY;
            sl->f10 = ((GameObject *)obj)->anim.localPosZ;
            sl->f4 = sl->f0;
            sl->fc = -(lbl_803E41F4 * fr - sl->f8);
            sl->f14 = sl->f10;
        }
        *(s16*)obj += framesThisStep * (count * 0x7e);
    }
    if (count != 0) {
        if (Sfx_IsPlayingFromObjectChannel((int)obj, 0x40) == 0) {
            Sfx_PlayFromObject((int)obj, SFXsk_planteater11);
            sub->humVolume = lbl_803E41F8;
        } else {
            f32 vol = lbl_803E41FC + (f32)count / lbl_803E4200;
            sub->humVolume = (vol - sub->humVolume) * lbl_803E4204 + sub->humVolume;
            if (sub->charge >= 0x3c) {
                sub->humVolume = vol;
            }
            Sfx_SetObjectChannelVolume((int)obj, 0x40, 0x64, sub->humVolume);
        }
    }
    i = 0;
    p16 = (char*)sub;
    do {
        s16 v = *(s16*)(p16 + 0x30);
        if (v != 0 && v < 0x80) {
            *(s16*)(p16 + 0x30) = v + framesThisStep;
            if (v == 1 && *(s16*)(p16 + 0x30) > 1) {
                Sfx_PlayFromObject((int)obj, SFXsk_toysq2_c);
            }
            if (v < 0x1e && *(s16*)(p16 + 0x30) >= 0x1e) {
                Sfx_PlayFromObject((int)obj, SFXsk_trbark1);
            }
        }
        p16 += 2;
        i++;
    } while (i < 3);
    *(s16*)obj += framesThisStep * 0x2a;
}
#pragma peephole reset
#pragma scheduling reset

extern int  fn_8019AF64(int* obj, void* path, f32 f, int phase, void* spd);
extern void fn_8019AE3C(int* obj, void* evbuf, void* p);
extern int  fn_80296A14(int p);
extern void dll_2E_func04(void* sub);
extern void dll_2E_func0C(int a, void* p);
extern void buttonDisable(int a, int b);
extern void characterDoEyeAnims(int* obj, void* p);
extern int  hitDetectFn_800658a4(int* obj, f32 x, f32 y, f32 z, f32* out, int p);
extern int  lbl_80322954[];
extern u8   lbl_803DBE20;
extern f32  oneOverTimeDelta;
extern f32  lbl_803E4134;
extern f32  lbl_803E4138;
extern f32  lbl_803E413C;
extern f32  lbl_803E4140;
extern f32  lbl_803E4144;
extern f32  lbl_803E4148;
extern f32  lbl_803E414C;
extern f32  lbl_803E4150;
extern f32  lbl_803E4154;
extern f32  lbl_803E4158;
extern f32  lbl_803E415C;
extern f32  lbl_803E412C;

/* EN v1.0 0x8019B4C8  size: 3800b  waterSpellStone1Fn_8019b4c8: cfguardian
 * brain - sixteen-state quest progression for the CloudRunner guardian, with
 * sandworm avoidance, path flights, landing physics, sequenced triggers and
 * idle chatter. */
#pragma scheduling off
#pragma peephole off
int waterSpellStone1Fn_8019b4c8(int* obj)
{
    u8* def;
    char* player;
    CfGuardianState* sub;
    u8 evbuf[0x1c];
    f32 v[3];
    f32 k;
    f32 nearDist = lbl_803E412C;
    f32 ground = lbl_803E4130;
    def = *(u8**)&((GameObject *)obj)->anim.placementData;
    evbuf[0x1b] = 0;
    sub = ((GameObject *)obj)->extra;
    sub->flagsA9B &= ~0x2;
    sub->moveSpeed = lbl_803E4134;
    player = (char*)Obj_GetPlayerObject();
    ObjTrigger_UpdateIdBlockFlag((int)obj);
    if (*(s8*)(def + 0x19) == 1 && GameBit_Get(0x57) == 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        return 0;
    }
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
    switch (sub->questState) {
    case 0:
        if (sub->chatterState == 2) {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x94f) != 0) {
            sub->questState = 1;
        }
        break;
    case 1:
        if (sub->chatterState == 2) {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x4e) != 0) {
            sub->questState = 3;
            ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
            ((GameObject *)obj)->unkF4 = 0;
            GameBit_Set(0x48, 1);
            sub->flagsA9B |= 1;
        }
        break;
    case 2:
        if (sub->chatterState == 2) {
            sub->chatterState = 1;
        }
        sub->flagsA9B |= 2;
        if (fn_8019AF64(obj, (u8*)sub + 0x6bc, lbl_803E4138, 0, (u8*)sub + 0x7fc) != 0) {
            sub->flagsA9B &= ~1;
            sub->questState = 4;
        }
        break;
    case 3:
        (*gObjectTriggerInterface)->runSequence(2, obj, -1);
        GameBit_Set(0x60, 1);
        sub->questState = 2;
        break;
    case 4:
        if (GameBit_Get(0x57) != 0) {
            if (*(s8*)(def + 0x19) != 1) {
                sub->questState = 0xf;
                sub->chatterAlt = 0;
            } else {
                sub->questState = 0xe;
                sub->chatterAlt = 0;
            }
        } else if (sub->chatterState == 2) {
            sub->chatterState = 1;
            sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
        }
        break;
    case 6:
        if (sub->landingPhase == 0) {
            if (sub->chatterState == 2) {
                sub->chatterState = 1;
            }
        } else {
            if (sub->landingPhase >= 2) {
                ((GameObject *)obj)->anim.velocityX = lbl_803E4110;
                ((GameObject *)obj)->anim.velocityZ = lbl_803E4110;
                ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
                hitDetectFn_800658a4(obj, ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ, &ground, 0);
                *(s16*)obj = (s16)((0xc0 << (*(s16*)obj + 8)) >> 1);
                (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~0x400;
                if (ground <= lbl_803E4130) {
                    sub->landingPhase = 2;
                    ((GameObject *)obj)->anim.localPosY -= ground;
                    sub->chatterState = 1;
                    ((GameObject *)obj)->unkF4 = 0;
                    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E4110, 0);
                    {
                        char* pt = (char*)findRomCurvePointNearObject(obj, 0, 0, 2);
                        f32 d;
                        sub->homeX = *(f32*)(pt + 8);
                        sub->homeY = *(f32*)(pt + 0xc);
                        sub->homeZ = *(f32*)(pt + 0x10);
                        sub->homeYaw = (s16)(*(s8*)(pt + 0x2c) << 8);
                        d = sub->homeY - ((GameObject *)obj)->anim.localPosY;
                        d = (d >= lbl_803E4110) ? d : -d;
                        if (d < lbl_803E413C) {
                            ObjGroup_AddObject(obj, 0x16);
                            sub->questState = 7;
                            ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
                        }
                    }
                } else {
                    ((GameObject *)obj)->anim.velocityY -= lbl_803E4140;
                }
            } else {
                f32 w = lbl_803E4144 * ((GameObject *)obj)->anim.velocityY;
                w = (w >= lbl_803E4110) ? w : -w;
                *(s16*)obj = (f32)*(s16*)obj + w;
                sub->moveSpeed = lbl_803E4148;
                if (GameBit_Get(0x8e9) != 0) {
                    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E4110, 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x32);
                    ((GameObject *)obj)->anim.velocityY = lbl_803E4110;
                    ObjGroup_RemoveObject(obj, 0x16);
                    ((GameObject *)obj)->anim.velocityX = lbl_803E4110;
                    ((GameObject *)obj)->anim.velocityY = lbl_803E414C;
                    ((GameObject *)obj)->anim.velocityZ = lbl_803E4110;
                    sub->landingPhase = 2;
                    sub->flagsA9B &= ~1;
                }
            }
            if (sub->landingPhase < 2) {
                ((GameObject *)obj)->anim.localPosX = timeDelta * ((GameObject *)obj)->anim.velocityX + ((GameObject *)obj)->anim.localPosX;
                ((GameObject *)obj)->anim.localPosZ = timeDelta * ((GameObject *)obj)->anim.velocityZ + ((GameObject *)obj)->anim.localPosZ;
                if (sub->unkA5E != 0) {
                    ((GameObject *)obj)->anim.velocityX = lbl_803E4150 * -((GameObject *)obj)->anim.velocityX;
                    ((GameObject *)obj)->anim.velocityZ = lbl_803E4150 * -((GameObject *)obj)->anim.velocityZ;
                }
                v[0] = ((GameObject *)obj)->anim.localPosX - ((GameObject *)obj)->anim.previousLocalPosX;
                v[1] = ((GameObject *)obj)->anim.localPosY - ((GameObject *)obj)->anim.previousLocalPosY;
                v[2] = ((GameObject *)obj)->anim.localPosZ - ((GameObject *)obj)->anim.previousLocalPosZ;
                k = lbl_803E4154 * oneOverTimeDelta;
                v[0] = v[0] * k;
                v[1] = v[1] * k;
                v[2] = v[2] * k;
                ((GameObject *)obj)->anim.velocityX = v[0] + ((GameObject *)obj)->anim.velocityX;
                ((GameObject *)obj)->anim.velocityY = v[1] + ((GameObject *)obj)->anim.velocityY;
                ((GameObject *)obj)->anim.velocityZ = v[2] + ((GameObject *)obj)->anim.velocityZ;
                ((GameObject *)obj)->anim.velocityX = lbl_803E4138 * ((GameObject *)obj)->anim.velocityX;
                ((GameObject *)obj)->anim.velocityY = lbl_803E4138 * ((GameObject *)obj)->anim.velocityY;
                ((GameObject *)obj)->anim.velocityZ = lbl_803E4138 * ((GameObject *)obj)->anim.velocityZ;
            }
        }
        break;
    case 7:
        if (sub->chatterState == 2) {
            sub->chatterState = 1;
        }
        sub->flagsA9B |= 2;
        if (fn_8019AF64(obj, (u8*)sub + 0x6bc, lbl_803E4138, 1, (u8*)sub + 0x7fc) != 0) {
            sub->questState = 8;
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x32);
        }
        break;
    case 8:
        if ((void*)ObjGroup_FindNearestObject(3, obj, &nearDist) != NULL && nearDist < lbl_803E4158) {
            dll_2E_func04(sub);
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
        }
        if (nearDist > lbl_803E4158 && Vec_xzDistance(player + 0x18, (char*)obj + 0x18) < lbl_803E413C) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x10;
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0) {
                dll_2E_func0C(0xf, (u8*)sub + 0xa68);
                sub->flagsA9B |= 5;
                lbl_80322954[sub->questState] = 0;
            }
            if (sub->chatterState == 2) {
                sub->chatterState = 1;
                sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
            }
        } else {
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0xe) {
                sub->chatterState = 2;
                sub->flagsA9B |= 5;
                dll_2E_func0A(0xe, (int*)((u8*)sub + 0xa68));
                lbl_80322954[sub->questState] = 0xe;
            }
        }
        if ((sub->flagsA9B & 4) != 0
            && fn_8019B1D8(obj, (int*)((u8*)sub + 0xa68), lbl_803E4128, (int)((u8*)sub + 0x7fc)) != 0) {
            ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
            sub->flagsA9B &= ~0x5;
        }
        if (GameBit_Get(0x43) != 0) {
            sub->questState = 9;
            sub->chatterAlt = 0;
        }
        break;
    case 9:
        if ((void*)ObjGroup_FindNearestObject(3, obj, &nearDist) != NULL && nearDist < lbl_803E4158) {
            dll_2E_func04(sub);
        }
        if (nearDist > lbl_803E4158 && Vec_xzDistance(player + 0x18, (char*)obj + 0x18) < lbl_803E413C) {
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0) {
                dll_2E_func0C(0xf, (u8*)sub + 0xa68);
                sub->flagsA9B |= 5;
                lbl_80322954[sub->questState] = 0;
            }
            if (sub->chatterState == 2) {
                sub->chatterState = 1;
                sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
            }
        } else {
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0xe) {
                sub->chatterState = 2;
                sub->flagsA9B |= 5;
                dll_2E_func0A(0xe, (int*)((u8*)sub + 0xa68));
                lbl_80322954[sub->questState] = 0xe;
            }
        }
        if ((sub->flagsA9B & 4) != 0
            && fn_8019B1D8(obj, (int*)((u8*)sub + 0xa68), lbl_803E4128, (int)((u8*)sub + 0x7fc)) != 0) {
            ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
            sub->flagsA9B &= ~0x5;
        }
        if (GameBit_Get(0x4be) != 0) {
            sub->questState = 0xa;
            ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
            ((GameObject *)obj)->unkF4 = 0;
        }
        break;
    case 10:
        if (sub->chatterState == 2) {
            sub->chatterState = 1;
        }
        sub->flagsA9B |= 2;
        if (fn_8019AF64(obj, (u8*)sub + 0x6bc, lbl_803E415C, 2, (u8*)sub + 0x7fc) != 0) {
            sub->questState = 0xb;
        }
        break;
    case 11:
        if (sub->chatterState == 2) {
            sub->chatterState = 1;
        }
        ((GameObject *)obj)->anim.alpha = 0;
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~1;
        Obj_RemoveFromUpdateList(obj);
        ((GameObject *)obj)->anim.flags |= 0x4000;
        sub->questState = 0xf;
        break;
    case 12:
        if (sub->chatterState == 2) {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x4b7) != 0) {
            (*gCameraInterface)->setTarget((int)obj);
            (*gObjectTriggerInterface)->runSequence(0xb, obj, -1);
            GameBit_Set(0x4b7, 0);
        }
        if (GameBit_Get(0x49a) != 0) {
            sub->questState = 0xd;
        }
        break;
    case 13:
        if (sub->chatterState == 2) {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x4b7) != 0) {
            (*gCameraInterface)->setTarget((int)obj);
            (*gObjectTriggerInterface)->runSequence(0xa, obj, -1);
            GameBit_Set(0x4b7, 0);
        }
        if (GameBit_Get(0x4aa) != 0) {
            sub->questState = 0xe;
        }
        break;
    case 14:
        if (sub->chatterState == 2) {
            sub->chatterState = 1;
        }
        break;
    case 15:
        ((GameObject *)obj)->anim.flags |= 0x4000;
        Obj_RemoveFromUpdateList(obj);
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~1;
        break;
    }
    dll_2E_func03(obj, sub);
    if (ObjTrigger_IsSet(obj) != 0) {
        buttonDisable(0, 0x100);
        if ((*gGameUIInterface)->isEventReady(0x2e8) != 0) {
            GameBit_Set(0x4ab, 1);
        } else if (sub->chatterState == 1) {
            int* tbl = (int*)seqStreamLookupFn_8007fff8(lbl_8032284C, 0xf, sub->questState);
            int pick;
            if (fn_80296A14((int)player) > 3) {
                pick = tbl[0];
            } else {
                pick = tbl[1];
            }
            if (sub->chatterPick % 2 != 0 && tbl[2] != -1) {
                pick = tbl[2];
            }
            sub->chatterPick += 1;
            if (pick != -1) {
                sub->chatterState = 2;
                (*gObjectTriggerInterface)->runSequence(pick, obj, -1);
            }
        }
    }
    if (GameBit_Get(0x902) != 0) {
        int* tbl2 = (int*)seqStreamLookupFn_8007fff8(lbl_8032284C, 0xf, sub->questState);
        if (tbl2[0] != -1) {
            sub->chatterState = 2;
            (*gObjectTriggerInterface)->runSequence(tbl2[0], obj, -1);
            GameBit_Set(0x902, 0);
        }
    }
    {
        int mv = lbl_80322954[sub->questState];
        if (mv != -1 && (sub->flagsA9B & 1) == 0 && ((GameObject *)obj)->anim.currentMove != mv) {
            ObjAnim_SetCurrentMove((int)obj, mv, lbl_803E4110, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x50);
        }
    }
    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, sub->moveSpeed, (f32)framesThisStep, evbuf) != 0
        && (sub->flagsA9B & 1) != 0
        && ((GameObject *)obj)->anim.currentMove != 0x1a
        && ((GameObject *)obj)->anim.currentMove != 9) {
        sub->flagsA9B &= ~1;
    }
    fn_8019AE3C(obj, evbuf, &lbl_803DBE20);
    if (randFn_80080100(0x3c) != 0) {
        objAudioFn_800393f8((int)obj, (u8*)sub + 0x624, 0xdf, 0x1000, -1, 0);
    }
    objAnimFn_80038f38((int)obj, (u8*)sub + 0x624);
    characterDoEyeAnims(obj, (u8*)sub + 0x654);
    if (sub->questState != GameBit_Get(0x4b)) {
        GameBit_Set(0x4b);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
