#include "ghidra_import.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objanim.h"

#define SFXmn_sml_trex_fstep 0x7e
#define SFXsk_baptr6_c 0xd3
#define SFXsk_baptr9_c 0xd4
#define SFXsk_planteater11 0xd5
#define SFXsk_toysq2_c 0xd6
#define SFXsk_trbark1 0xd7
#define SFXsk_trwhin3 0xe1
#define SFXsk_doggydig11 0xe3
#define SFXsp_lf_mutter4 0x109
#define SFXand_spitout 0x334

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
extern undefined4 gWaterfxInterface;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
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
 * Function: FUN_8019b2dc
 * EN v1.0 Address: 0x8019B2DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019B4E0
 * EN v1.1 Size: 628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b2dc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,float *param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
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
 * Function: FUN_8019b588
 * EN v1.0 Address: 0x8019B588
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x8019B974
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8019b588(int param_1,undefined4 param_2,undefined4 *param_3,int param_4)
{
  int iVar1;
  int iVar2;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar2 = 0;
  if (param_4 == 1) {
    local_18 = 0;
    local_14 = 0;
  }
  else {
    local_18 = 0x19;
    local_14 = 0x15;
  }
  iVar1 = (**(code **)(*DAT_803dd71c + 0x14))
                    ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                     (double)*(float *)(param_1 + 0x14),&local_18,2,param_2);
  if ((-1 < iVar1) && (iVar2 = (**(code **)(*DAT_803dd71c + 0x1c))(), param_3 != (undefined4 *)0x0))
  {
    *param_3 = *(undefined4 *)(iVar2 + 8);
    param_3[1] = *(undefined4 *)(iVar2 + 0xc);
    param_3[2] = *(undefined4 *)(iVar2 + 0x10);
  }
  return iVar2;
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
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  local_28 = DAT_802c2a58;
  local_24 = DAT_802c2a5c;
  local_20 = DAT_802c2a60;
  local_1c = DAT_802c2a64;
  if (*(short *)(param_9 + 0xb4) < 0) {
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
 * Function: FUN_8019b7cc
 * EN v1.0 Address: 0x8019B7CC
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x8019CA28
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b7cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (param_10 == 0) {
    iVar2 = 0;
    do {
      if (*(int *)(iVar1 + 0x68c) != 0) {
        param_1 = FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               *(int *)(iVar1 + 0x68c));
      }
      iVar1 = iVar1 + 4;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 6);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b8ac
 * EN v1.0 Address: 0x8019B8AC
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x8019CA88
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b8ac(short *param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  if (visible != '\0') {
    FUN_8003b818((int)param_1);
    FUN_801149bc(param_1,iVar1,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b8fc
 * EN v1.0 Address: 0x8019B8FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019CAFC
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b8fc(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
                 undefined4 param_10,undefined4 param_11,float *param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  FUN_8019b650(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
               param_11,param_12,param_13,param_14,param_15,param_16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b900
 * EN v1.0 Address: 0x8019B900
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019CB1C
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b900(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019b904
 * EN v1.0 Address: 0x8019B904
 * EN v1.0 Size: 1708b
 * EN v1.1 Address: 0x8019CD00
 * EN v1.1 Size: 1412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b904(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,uint param_12,int param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  byte bVar2;
  float fVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  double dVar10;
  double extraout_f1;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 uVar14;
  
  uVar14 = FUN_80286838();
  uVar5 = (uint)((ulonglong)uVar14 >> 0x20);
  iVar7 = (int)uVar14;
  iVar8 = param_13;
  uVar9 = param_14;
  dVar10 = param_2;
  dVar12 = extraout_f1;
  iVar6 = FUN_80017a98();
  dVar13 = (double)(*(float *)(iVar7 + 0x10) - *(float *)(uVar5 + 0x10));
  if (((double)lbl_803E4E04 <= dVar13) &&
     ((dVar11 = (double)FUN_80017710((float *)(iVar7 + 0x18),(float *)(uVar5 + 0x18)),
      dVar11 <= (double)(float)((double)lbl_803E4E08 + dVar10) ||
      ((*(byte *)(param_11 + 0x10) & 0xe0) != 0)))) {
    bVar2 = *(byte *)(param_11 + 0x10);
    if (((bVar2 & 0x80) == 0) || (param_12 == 0)) {
      if (dVar10 <= dVar11) {
        if (param_13 == 0) {
          ObjMsg_SendToObject(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7,0x10,
                       uVar5,param_12,iVar8,uVar9,param_15,param_16);
          *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xe;
          *(float *)(param_11 + 0xc) = lbl_803E4E04;
          *(undefined *)(param_11 + 0x11) = 0;
        }
        else {
          FUN_80294c74((double)lbl_803E4E04,iVar7);
        }
      }
      else {
        if (((bVar2 & 0xe0) == 0) || ((bVar2 & 0x80) != 0)) {
          if ((param_12 != 0) &&
             ((uVar4 = countLeadingZeros((uint)bVar2), (uVar4 >> 5 & 0x80) != 0 &&
              (dVar13 < (double)lbl_803E4E0C)))) {
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x80;
            goto LAB_8019d244;
          }
          if ((bVar2 & 2) != 0) {
            dVar11 = (double)(float)(dVar13 / dVar12);
            if (dVar11 <= (double)lbl_803E4E10) {
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 8;
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xfb;
            }
            else {
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 4;
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xf7;
            }
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xfd;
          }
          if (param_12 == 0) {
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x40;
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xdf;
            ObjMsg_SendToObject(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7,0xf,
                         uVar5,((int)(*(byte *)(param_11 + 0x10) & 0xe0) >> 4) << 8 | param_14,iVar8
                         ,uVar9,param_15,param_16);
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0x7f;
          }
          else {
            if ((double)lbl_803E4E14 < dVar13) {
              ObjMsg_SendToObject(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7,0xf,
                           uVar5,((int)(*(byte *)(param_11 + 0x10) & 0xe0) >> 4) << 8 | param_14,
                           iVar8,uVar9,param_15,param_16);
            }
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x20;
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xbf;
          }
        }
        dVar10 = (double)lbl_803E4E18;
        bVar2 = *(byte *)(param_11 + 0x10);
        if ((((bVar2 & 0xe) != 0) && ((bVar2 & 8) != 0)) && (param_12 == 0)) {
          dVar12 = (double)(float)(dVar12 * (double)lbl_803E4E1C);
        }
        fVar1 = (float)(dVar12 * (double)lbl_803E4E1C);
        if (lbl_803E4E08 < fVar1) {
          if (dVar13 < (double)lbl_803E4E20) {
            dVar13 = (double)lbl_803E4E20;
          }
          if (param_12 == 0) {
            fVar3 = *(float *)(param_11 + 0xc);
            dVar12 = -(double)((fVar1 / lbl_803E4E24) * fVar3 * fVar3 * fVar3 - fVar1);
            if (dVar13 <= dVar12) {
              fVar1 = (float)(dVar12 - dVar13);
              if (fVar1 <= lbl_803E4E0C) {
                dVar11 = (double)(fVar1 / lbl_803E4E0C);
              }
              else {
                dVar11 = (double)lbl_803E4E28;
              }
            }
            else {
              dVar11 = (double)lbl_803E4E04;
            }
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 1;
            dVar12 = (double)*(float *)(param_11 + 0xc);
            if ((((dVar12 < (double)lbl_803E4E2C) && ((*(byte *)(param_11 + 0x11) & 1) != 0)) ||
                (((double)lbl_803E4E30 < dVar12 && ((*(byte *)(param_11 + 0x11) & 1) == 0)))) &&
               (((*(byte *)(param_11 + 0x10) & 8) != 0 &&
                (bVar2 = *(byte *)(param_11 + 0x11), *(byte *)(param_11 + 0x11) = bVar2 + 1,
                2 < bVar2)))) {
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xf7;
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 4;
            }
          }
          else {
            dVar12 = (double)*(float *)(param_11 + 0xc);
            fVar3 = lbl_803E4E34;
            if ((bVar2 & 0xe) != 0) {
              fVar3 = lbl_803E4E00;
            }
            if ((double)fVar3 < dVar12) {
              *(undefined *)(param_11 + 0x11) = 1;
            }
            dVar10 = (double)(float)(dVar10 * (double)lbl_803E4E38);
            if (*(char *)(param_11 + 0x11) == '\0') {
              fVar3 = lbl_803E4E40;
              if ((*(byte *)(param_11 + 0x10) & 0xe) != 0) {
                fVar3 = lbl_803E4E3C;
              }
              fVar1 = lbl_803E4E28 - (float)(dVar13 / (double)(fVar3 * fVar1));
              dVar12 = (double)lbl_803E4E28;
              if (fVar1 < lbl_803E4E04) {
                fVar1 = lbl_803E4E04;
              }
              dVar11 = (double)(fVar1 * fVar1);
            }
            else {
              dVar11 = (double)lbl_803E4E44;
            }
          }
          *(float *)(param_11 + 8) = (float)(dVar10 * dVar11 - (double)lbl_803E4E48);
          *(float *)(param_11 + 0xc) = *(float *)(param_11 + 0xc) + *(float *)(param_11 + 8);
          if (lbl_803E4E4C < *(float *)(param_11 + 0xc)) {
            *(float *)(param_11 + 0xc) = lbl_803E4E4C;
          }
          dVar10 = (double)lbl_803E4E04;
          if (dVar10 == (double)*(float *)(param_11 + 0xc)) {
            *(float *)(param_11 + 0xc) = lbl_803E4E50;
          }
          if ((dVar13 < (double)lbl_803E4E0C) && (param_12 != 0)) {
            *(float *)(param_11 + 0xc) = lbl_803E4E04;
            *(undefined *)(param_11 + 0x11) = 0;
            ObjMsg_SendToObject(dVar10,dVar12,dVar11,param_4,param_5,param_6,param_7,param_8,iVar7,0x10,
                         uVar5,param_12,iVar8,uVar9,param_15,param_16);
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x80;
            if (param_13 != 0) {
              *(float *)(iVar6 + 0x28) = lbl_803E4E04;
            }
          }
          if (param_13 == 0) {
            *(float *)(iVar7 + 0x10) =
                 *(float *)(param_11 + 0xc) * lbl_803DC074 + *(float *)(iVar7 + 0x10);
            *(float *)(iVar7 + 0x28) = *(float *)(param_11 + 0xc) * lbl_803DC074;
          }
          else {
            FUN_80294c74((double)*(float *)(param_11 + 0xc),iVar7);
          }
        }
      }
    }
  }
LAB_8019d244:
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019bfb0
 * EN v1.0 Address: 0x8019BFB0
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x8019D284
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019bfb0(int param_1)
{
  int iVar1;
  double dVar2;
  
  iVar1 = FUN_80017a98();
  if ((iVar1 == 0) || (dVar2 = FUN_80294c6c(iVar1), (double)lbl_803E4E04 == dVar2)) {
    FUN_800067c0((int *)0xbd,0);
  }
  ObjGroup_RemoveObject(param_1,0x49);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019c00c
 * EN v1.0 Address: 0x8019C00C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019D2E0
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c00c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019c034
 * EN v1.0 Address: 0x8019C034
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019D314
 * EN v1.1 Size: 1300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c034(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019c038
 * EN v1.0 Address: 0x8019C038
 * EN v1.0 Size: 736b
 * EN v1.1 Address: 0x8019D828
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c038(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  
  piVar5 = *(int **)(param_1 + 0xb8);
  piVar5[1] = (int)*(short *)(param_2 + 0x1e);
  iVar3 = FUN_8007f56c((int *)&DAT_80323698,4,piVar5[1]);
  *piVar5 = iVar3;
  iVar3 = FUN_8007f56c((int *)&DAT_803236b8,3,piVar5[1]);
  piVar5[3] = iVar3;
  if (piVar5[3] == 0) {
    piVar5[3] = -1;
  }
  if (*piVar5 == 0) {
    *piVar5 = 100;
  }
  piVar5[2] = (int)*(short *)(param_2 + 0x1c);
  piVar5[5] = 0;
  if ((int)*(char *)(param_2 + 0x19) == 0) {
    piVar5[0x5c] = (int)lbl_803E4E64;
  }
  else {
    piVar5[0x5c] = (int)(lbl_803E4E60 *
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)*(char *)(param_2 + 0x19) ^ 0x80000000) -
                               DOUBLE_803e4e58));
  }
  *(float *)(param_1 + 8) =
       (*(float *)(*(int *)(param_1 + 0x50) + 4) * (float)piVar5[0x5c]) / lbl_803E4E64;
  uVar4 = FUN_80017690(0x57);
  if ((uVar4 != 0) || (9 < *piVar5)) {
    piVar5[5] = 0x3c;
  }
  *(byte *)(piVar5 + 0x5d) = *(byte *)(piVar5 + 0x5d) & 0xbf | 0x40;
  if (piVar5[3] != 0xffffffff) {
    uVar4 = FUN_80017690(piVar5[3]);
    if (uVar4 == 0) {
      *(byte *)(piVar5 + 0x5d) = *(byte *)(piVar5 + 0x5d) & 0xbf;
      *(undefined *)(param_1 + 0x36) = 0;
    }
    else {
      piVar5[5] = 0x3c;
    }
  }
  fVar2 = lbl_803E4E04;
  fVar1 = lbl_803E4E00;
  iVar3 = 2;
  do {
    *(undefined *)(piVar5 + 10) = 0;
    *(byte *)(piVar5 + 10) = *(byte *)(piVar5 + 10) & 0xe;
    piVar5[7] = (int)fVar1;
    piVar5[9] = (int)fVar2;
    piVar5[8] = (int)fVar2;
    piVar5[6] = 0;
    *(undefined *)((int)piVar5 + 0x29) = 0;
    *(undefined *)(piVar5 + 0x10) = 0;
    *(byte *)(piVar5 + 0x10) = *(byte *)(piVar5 + 0x10) & 0xe;
    piVar5[0xd] = (int)fVar1;
    piVar5[0xf] = (int)fVar2;
    piVar5[0xe] = (int)fVar2;
    piVar5[0xc] = 0;
    *(undefined *)((int)piVar5 + 0x41) = 0;
    *(undefined *)(piVar5 + 0x16) = 0;
    *(byte *)(piVar5 + 0x16) = *(byte *)(piVar5 + 0x16) & 0xe;
    piVar5[0x13] = (int)fVar1;
    piVar5[0x15] = (int)fVar2;
    piVar5[0x14] = (int)fVar2;
    piVar5[0x12] = 0;
    *(undefined *)((int)piVar5 + 0x59) = 0;
    *(undefined *)(piVar5 + 0x1c) = 0;
    *(byte *)(piVar5 + 0x1c) = *(byte *)(piVar5 + 0x1c) & 0xe;
    piVar5[0x19] = (int)fVar1;
    piVar5[0x1b] = (int)fVar2;
    piVar5[0x1a] = (int)fVar2;
    piVar5[0x18] = 0;
    *(undefined *)((int)piVar5 + 0x71) = 0;
    *(undefined *)(piVar5 + 0x22) = 0;
    *(byte *)(piVar5 + 0x22) = *(byte *)(piVar5 + 0x22) & 0xe;
    piVar5[0x1f] = (int)fVar1;
    piVar5[0x21] = (int)fVar2;
    piVar5[0x20] = (int)fVar2;
    piVar5[0x1e] = 0;
    *(undefined *)((int)piVar5 + 0x89) = 0;
    *(undefined *)(piVar5 + 0x28) = 0;
    *(byte *)(piVar5 + 0x28) = *(byte *)(piVar5 + 0x28) & 0xe;
    piVar5[0x25] = (int)fVar1;
    piVar5[0x27] = (int)fVar2;
    piVar5[0x26] = (int)fVar2;
    piVar5[0x24] = 0;
    *(undefined *)((int)piVar5 + 0xa1) = 0;
    *(undefined *)(piVar5 + 0x2e) = 0;
    *(byte *)(piVar5 + 0x2e) = *(byte *)(piVar5 + 0x2e) & 0xe;
    piVar5[0x2b] = (int)fVar1;
    piVar5[0x2d] = (int)fVar2;
    piVar5[0x2c] = (int)fVar2;
    piVar5[0x2a] = 0;
    *(undefined *)((int)piVar5 + 0xb9) = 0;
    piVar5 = piVar5 + 0x2a;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  ObjGroup_AddObject(param_1,0x49);
  return;
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
  
  psVar3 = *(short **)(param_9 + 0xb8);
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
 * Function: FUN_8019c668
 * EN v1.0 Address: 0x8019C668
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019DCC4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c668(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019c690
 * EN v1.0 Address: 0x8019C690
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x8019DCF8
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c690(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80017690((int)*(short *)(iVar3 + 2));
  if (uVar1 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if (*(int *)(param_1 + 0xf4) != 0) {
    (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,0xfa);
    (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 4),param_1,3);
    *(undefined4 *)(param_1 + 0xf4) = 0;
  }
  if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
     (iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))((int)*(short *)(iVar3 + 2)), iVar2 != 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_80017698((int)*(short *)(iVar3 + 2),0);
    FUN_80017698(0x973,0);
    (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 4),param_1,0xffffffff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019c7c8
 * EN v1.0 Address: 0x8019C7C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019DE30
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c7c8(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019c7cc
 * EN v1.0 Address: 0x8019C7CC
 * EN v1.0 Size: 2464b
 * EN v1.1 Address: 0x8019DF6C
 * EN v1.1 Size: 2128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019c7cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  short *psVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  float *pfVar6;
  bool bVar7;
  undefined4 in_r7;
  float *in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar8;
  float *pfVar9;
  int iVar10;
  short sVar11;
  float *pfVar12;
  float *pfVar13;
  undefined8 uVar14;
  uint local_58;
  uint local_54;
  uint local_50;
  float local_4c;
  float local_48;
  float local_44;
  undefined auStack_40 [4];
  short local_3c;
  short local_3a;
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack_24;
  
  psVar2 = (short *)FUN_80286838();
  pfVar9 = *(float **)(psVar2 + 0x5c);
  local_58 = 0;
  FUN_80017a98();
  uVar14 = FUN_800069bc();
  while (iVar3 = ObjMsg_Pop((int)psVar2,&local_54,&local_50,&local_58), iVar3 != 0) {
    if (local_54 == 0x110003) {
      pfVar9[2] = *(float *)(local_50 + 0xc);
      pfVar9[6] = lbl_803E4E70;
      pfVar9[10] = *(float *)(local_50 + 0x14);
      *(undefined2 *)(pfVar9 + 0xd) = 1;
    }
    else if ((int)local_54 < 0x110003) {
      if (local_54 == 0x110001) {
        *pfVar9 = *(float *)(local_50 + 0xc);
        pfVar9[4] = lbl_803E4E70;
        pfVar9[8] = *(float *)(local_50 + 0x14);
        *(undefined2 *)(pfVar9 + 0xc) = 1;
      }
      else if (0x110000 < (int)local_54) {
        pfVar9[1] = *(float *)(local_50 + 0xc);
        pfVar9[5] = lbl_803E4E70;
        pfVar9[9] = *(float *)(local_50 + 0x14);
        *(undefined2 *)((int)pfVar9 + 0x32) = 1;
      }
    }
    else if ((int)local_54 < 0x110005) {
      pfVar9[3] = *(float *)(local_50 + 0xc);
      pfVar9[7] = *(float *)(local_50 + 0x10);
      pfVar9[0xb] = *(float *)(local_50 + 0x14);
      *(undefined2 *)((int)pfVar9 + 0x36) = 1;
    }
  }
  if (*(short *)((int)pfVar9 + 0x36) == 0) {
    in_r7 = 0;
    uVar14 = ObjMsg_SendToObjects(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xdc,5,
                          (uint)psVar2,0x110004,0,in_r8,in_r9,in_r10);
  }
  uVar4 = FUN_80017690(0x54);
  if ((uVar4 != 0) && (*(short *)(pfVar9 + 0xc) == 0)) {
    in_r7 = 0;
    uVar14 = ObjMsg_SendToObjects(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xda,4,
                          (uint)psVar2,0x110001,0,in_r8,in_r9,in_r10);
  }
  uVar4 = FUN_80017690(0x55);
  if ((uVar4 != 0) && (*(short *)((int)pfVar9 + 0x32) == 0)) {
    in_r7 = 0;
    uVar14 = ObjMsg_SendToObjects(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xda,4,
                          (uint)psVar2,0x110002,0,in_r8,in_r9,in_r10);
  }
  uVar4 = FUN_80017690(0x56);
  if ((uVar4 != 0) && (*(short *)(pfVar9 + 0xd) == 0)) {
    in_r7 = 0;
    ObjMsg_SendToObjects(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xda,4,(uint)psVar2,
                 0x110003,0,in_r8,in_r9,in_r10);
  }
  *(undefined *)((int)pfVar9 + 0x53) = 0;
  *(undefined *)((int)pfVar9 + 0x6f) = 0;
  *(undefined *)((int)pfVar9 + 0x8b) = 0;
  *(undefined *)((int)pfVar9 + 0xa7) = 0;
  *(undefined *)((int)pfVar9 + 0xc3) = 0;
  *(undefined *)((int)pfVar9 + 0xdf) = 0;
  *(undefined *)((int)pfVar9 + 0xfb) = 0;
  *(undefined *)((int)pfVar9 + 0x117) = 0;
  *(undefined *)((int)pfVar9 + 0x133) = 0;
  *(undefined *)((int)pfVar9 + 0x14f) = 0;
  uVar4 = 0;
  iVar3 = 0;
  if (*(short *)((int)pfVar9 + 0x36) != 0) {
    uVar5 = FUN_80017690(0x57);
    if (uVar5 != 0) {
      if (*(short *)(pfVar9 + 0xc) != 0) {
        *(undefined2 *)(pfVar9 + 0xc) = 0x78;
      }
      if (*(short *)((int)pfVar9 + 0x32) != 0) {
        *(undefined2 *)((int)pfVar9 + 0x32) = 0x78;
      }
      if (*(short *)(pfVar9 + 0xd) != 0) {
        *(undefined2 *)(pfVar9 + 0xd) = 0x78;
      }
      *(undefined2 *)(pfVar9 + 0x54) = 0x5a;
    }
    iVar10 = 0;
    pfVar12 = pfVar9;
    pfVar13 = pfVar9;
    do {
      if ((iVar10 < 3) && (*(short *)(pfVar13 + 0xc) != 0)) {
        iVar8 = iVar3 + 1;
        pfVar6 = pfVar9 + iVar3 * 7 + 0xe;
        *(undefined *)((int)pfVar6 + 0x1b) = 1;
        *(undefined *)(pfVar6 + 6) = 0x7f;
        *(undefined *)((int)pfVar6 + 0x19) = 0x7f;
        *(undefined *)((int)pfVar6 + 0x1a) = 0xff;
        *pfVar6 = pfVar9[3];
        pfVar6[2] = lbl_803E4E74 + pfVar9[7];
        pfVar6[4] = pfVar9[0xb];
        local_4c = *pfVar12 - *pfVar6;
        local_48 = (lbl_803E4E78 + pfVar12[4]) - pfVar6[2];
        local_44 = pfVar12[8] - pfVar6[4];
        FUN_80247ef8(&local_4c,&local_4c);
        local_34 = *pfVar12 - pfVar9[3];
        local_30 = (lbl_803E4E78 + pfVar12[4]) - pfVar9[7];
        local_2c = pfVar12[8] - pfVar9[0xb];
        local_4c = -local_4c;
        local_48 = -local_48;
        local_44 = -local_44;
        sVar11 = (short)iVar10;
        local_3a = sVar11;
        (**(code **)(*DAT_803dd708 + 8))(psVar2,0x7f4,auStack_40,2,0xffffffff,&local_4c);
        local_4c = *pfVar12 - *(float *)(DAT_803de790 + 0xc);
        local_48 = lbl_803E4E7C;
        local_44 = pfVar12[8] - *(float *)(DAT_803de790 + 0x14);
        FUN_80247ef8(&local_4c,&local_4c);
        local_34 = lbl_803E4E80;
        local_30 = lbl_803E4E74;
        local_2c = lbl_803E4E80;
        local_3a = sVar11 + 3;
        in_r7 = 0xffffffff;
        in_r8 = &local_4c;
        in_r9 = *DAT_803dd708;
        (**(code **)(in_r9 + 8))(DAT_803de790,0x7f4,auStack_40,2);
        param_2 = (double)*pfVar12;
        local_34 = *pfVar12;
        local_30 = pfVar12[4];
        local_2c = pfVar12[8];
        iVar3 = iVar3 + 2;
        *(undefined *)((int)pfVar9 + iVar8 * 0x1c + 0x53) = 1;
        uVar4 = uVar4 + 1;
        local_3c = sVar11;
      }
      pfVar13 = (float *)((int)pfVar13 + 2);
      pfVar12 = pfVar12 + 1;
      iVar10 = iVar10 + 1;
    } while (iVar10 < 3);
    if (((int)*(short *)(pfVar9 + 0xc) +
         (int)*(short *)((int)pfVar9 + 0x32) + (int)*(short *)(pfVar9 + 0xd) < 300) &&
       (uVar5 = randomGetRange(0,3), uVar5 == 0)) {
      in_r7 = 0xffffffff;
      in_r8 = (float *)0x0;
      in_r9 = *DAT_803dd708;
      (**(code **)(in_r9 + 8))(psVar2,0x81,0,0);
    }
    if (((*(short *)(pfVar9 + 0xc) != 0) || (*(short *)((int)pfVar9 + 0x32) != 0)) ||
       (*(short *)(pfVar9 + 0xd) != 0)) {
      if (100 < *(byte *)(pfVar9 + 0x57)) {
        *(undefined *)(pfVar9 + 0x57) = 0;
      }
      if (100 < *(byte *)((int)pfVar9 + 0x15d)) {
        *(undefined *)((int)pfVar9 + 0x15d) = 0;
      }
      if (100 < *(byte *)((int)pfVar9 + 0x15e)) {
        *(undefined *)((int)pfVar9 + 0x15e) = 0;
      }
      if (0x14 < *(byte *)((int)pfVar9 + 0x15f)) {
        *(undefined *)((int)pfVar9 + 0x15f) = 0;
      }
      *(byte *)(pfVar9 + 0x57) = *(char *)(pfVar9 + 0x57) + DAT_803dc070;
      *(byte *)((int)pfVar9 + 0x15d) = *(char *)((int)pfVar9 + 0x15d) + DAT_803dc070;
      *(byte *)((int)pfVar9 + 0x15e) = *(char *)((int)pfVar9 + 0x15e) + DAT_803dc070;
      *(byte *)((int)pfVar9 + 0x15f) = *(char *)((int)pfVar9 + 0x15f) + DAT_803dc070;
    }
    if (uVar4 == 3) {
      if (*(short *)(pfVar9 + 0x54) == 0) {
        uVar14 = FUN_80006824(0,SFXmn_sml_trex_fstep);
        FUN_80006728(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x7f,0,in_r7
                     ,in_r8,in_r9,in_r10);
      }
      *(ushort *)(pfVar9 + 0x54) = *(short *)(pfVar9 + 0x54) + (ushort)DAT_803dc070;
    }
    if (0x3b < *(short *)(pfVar9 + 0x54)) {
      uStack_24 = (int)*(short *)(pfVar9 + 0x54) - 0x3cU ^ 0x80000000;
      local_28 = 0x43300000;
      fVar1 = (f32)(s32)uStack_24 / lbl_803E4E84;
      pfVar12 = pfVar9 + iVar3 * 7 + 0xe;
      *(undefined *)((int)pfVar12 + 0x1b) = 1;
      *(undefined *)(pfVar12 + 6) = 0;
      *(undefined *)((int)pfVar12 + 0x19) = 0;
      *(undefined *)((int)pfVar12 + 0x1a) = 0;
      *pfVar12 = *(float *)(psVar2 + 6);
      pfVar12[2] = lbl_803E4E88 + *(float *)(psVar2 + 8);
      pfVar12[4] = *(float *)(psVar2 + 10);
      pfVar12[1] = *pfVar12;
      pfVar12[3] = -(lbl_803E4E8C * fVar1 - pfVar12[2]);
      pfVar12[5] = pfVar12[4];
    }
    *psVar2 = *psVar2 + (ushort)DAT_803dc070 * (short)uVar4 * 0x7e;
  }
  if (uVar4 != 0) {
    bVar7 = FUN_800067f0((int)psVar2,0x40);
    if (bVar7) {
      uStack_24 = uVar4 ^ 0x80000000;
      local_28 = 0x43300000;
      fVar1 = lbl_803E4E94 +
              (f32)(s32)uStack_24 / lbl_803E4E98;
      pfVar9[0x55] = (fVar1 - pfVar9[0x55]) * lbl_803E4E9C + pfVar9[0x55];
      if (0x3b < *(short *)(pfVar9 + 0x54)) {
        pfVar9[0x55] = fVar1;
      }
      FUN_80006814((double)pfVar9[0x55],(int)psVar2,0x40,100);
    }
    else {
      FUN_80006824((uint)psVar2,SFXsk_planteater11);
      pfVar9[0x55] = lbl_803E4E90;
    }
  }
  iVar3 = 0;
  do {
    sVar11 = *(short *)(pfVar9 + 0xc);
    if ((sVar11 != 0) && (sVar11 < 0x80)) {
      *(ushort *)(pfVar9 + 0xc) = sVar11 + (ushort)DAT_803dc070;
      if ((sVar11 == 1) && (1 < *(short *)(pfVar9 + 0xc))) {
        FUN_80006824((uint)psVar2,SFXsk_toysq2_c);
      }
      if ((sVar11 < 0x1e) && (0x1d < *(short *)(pfVar9 + 0xc))) {
        FUN_80006824((uint)psVar2,SFXsk_trbark1);
      }
    }
    pfVar9 = (float *)((int)pfVar9 + 2);
    iVar3 = iVar3 + 1;
  } while (iVar3 < 3);
  *psVar2 = *psVar2 + (ushort)DAT_803dc070 * 0x2a;
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d16c
 * EN v1.0 Address: 0x8019D16C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8019E7BC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d16c(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d1a0
 * EN v1.0 Address: 0x8019D1A0
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019E7EC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d1a0(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d1c8
 * EN v1.0 Address: 0x8019D1C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019E820
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d1c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019d1cc
 * EN v1.0 Address: 0x8019D1CC
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x8019E8F4
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d1cc(undefined2 *param_1,int param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  if (*(char *)(param_2 + 0x19) == '\0') {
    *(undefined *)(iVar1 + 0x15c) = 0x28;
    *(undefined *)(iVar1 + 0x15d) = 0;
    *(undefined *)(iVar1 + 0x15e) = 0;
    *(undefined *)(iVar1 + 0x15f) = 0x46;
    *(undefined *)((int)param_1 + 0xad) = 1;
    *(undefined4 *)(iVar1 + 0x158) = 0;
  }
  ObjMsg_AllocQueue((int)param_1,2);
  return;
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
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if ((*(short *)(param_9 + 0xa0) != 5) && (*(short *)(param_9 + 0xa0) != 0xd)) {
    FUN_800305f8((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
  }
  if ((*(short *)(param_9 + 0xa0) == 5) && (lbl_803E4EC4 < *(float *)(param_9 + 0x28))) {
    FUN_800305f8((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
  }
  if ((*(short *)(param_9 + 0xa0) == 0xd) && (*(float *)(param_9 + 0x28) < lbl_803E4EB0)) {
    FUN_800305f8((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,5,0,param_12,param_13,param_14,param_15,param_16);
  }
  dVar2 = (double)((*(float *)(param_9 + 0x28) * lbl_803DCAB4 + lbl_803E4EC8) * lbl_803E4ECC);
  if (dVar2 < (double)lbl_803E4EB0) {
    dVar2 = (double)lbl_803E4EB0;
  }
  if ((double)lbl_803E4ECC < dVar2) {
    dVar2 = (double)lbl_803E4ECC;
  }
  if (*(short *)(param_9 + 0xa0) == 0xd) {
    if (*(float *)(param_9 + 0x98) <= lbl_803E4ECC) {
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
 * Function: FUN_8019d4d4
 * EN v1.0 Address: 0x8019D4D4
 * EN v1.0 Size: 572b
 * EN v1.1 Address: 0x8019EAE4
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d4d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10,int param_11,int param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  uVar3 = 0x28;
  uVar4 = 0;
  uVar5 = 3;
  FUN_8003add8(param_9,param_10,param_11 + 0x3c,0x28,0,3);
  iVar2 = Obj_GetYawDeltaToObject(param_9,param_10,(float *)0x0);
  sVar1 = (short)(iVar2 >> 3);
  *param_9 = *param_9 + sVar1;
  if (param_12 != 0) {
    if ((sVar1 < -199) || (199 < sVar1)) {
      if (*(int *)(param_11 + 0xc0) == 0) {
        *(undefined4 *)(param_11 + 0xc0) = 1;
        FUN_800305f8((double)lbl_803E4EB0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,9,0,uVar3,uVar4,uVar5,param_15,param_16);
      }
      else {
        iVar2 = (int)sVar1;
        if (iVar2 < 1) {
          sVar1 = (short)(-iVar2 >> 2);
        }
        else {
          sVar1 = (short)(iVar2 >> 2);
        }
        FUN_8002fc3c((double)((float)((double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000) -
                                     DOUBLE_803e4eb8) / lbl_803E4ED8),(double)lbl_803DC074);
      }
    }
    else if (*(int *)(param_11 + 0xc0) == 0) {
      FUN_8002fc3c((double)lbl_803E4ED4,(double)lbl_803DC074);
    }
    else {
      *(undefined4 *)(param_11 + 0xc0) = 0;
      FUN_800305f8((double)lbl_803E4EB0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0,0,uVar3,uVar4,uVar5,param_15,param_16);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d710
 * EN v1.0 Address: 0x8019D710
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x8019EC44
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d710(void)
{
  bool bVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  int iVar6;
  double dVar7;
  
  puVar2 = (undefined2 *)FUN_80286840();
  pfVar5 = *(float **)(puVar2 + 0x5c);
  iVar4 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_80017a98();
  iVar6 = *(int *)(puVar2 + 0x26);
  bVar1 = false;
  dVar7 = (double)FUN_8001771c((float *)(iVar3 + 0x18),(float *)(puVar2 + 0xc));
  if (((dVar7 < (double)(float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(iVar6 + 0x1a) ^ 0x80000000) -
                               DOUBLE_803e4eb8)) && (pfVar5[0x8c] == 4.2039e-45)) &&
     ((puVar2[0x58] & 0x1000) == 0)) {
    bVar1 = true;
  }
  if (bVar1) {
    FUN_8007f718(pfVar5,0x3c);
    *(undefined4 *)(puVar2 + 0x7a) = 1;
    *puVar2 = *(undefined2 *)(pfVar5 + 0x34);
    (**(code **)(*DAT_803dd6d4 + 0x48))(4,puVar2,0xffffffff);
    *pfVar5 = lbl_803E4EDC;
    FUN_80017688(0x901);
    pfVar5[0x31] = 1.68156e-44;
    FUN_80017698((int)*(short *)(iVar4 + 0x1e),1);
    *(undefined4 *)(puVar2 + 0x7a) = 0;
  }
  else {
    FUN_80039468(puVar2,pfVar5 + 0x1b,0x296,0x1000,0xffffffff,1);
    FUN_80006824((uint)puVar2,SFXsk_baptr9_c);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019d874
 * EN v1.0 Address: 0x8019D874
 * EN v1.0 Size: 984b
 * EN v1.1 Address: 0x8019ED98
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019d874(undefined4 param_1,undefined4 param_2,int param_3)
{
  float fVar1;
  float fVar2;
  bool bVar3;
  int iVar4;
  ushort *puVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  int iVar9;
  char cVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  bool bVar14;
  double dVar15;
  float local_48 [2];
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  puVar5 = (ushort *)FUN_80286830();
  iVar13 = *(int *)(puVar5 + 0x26);
  iVar12 = *(int *)(puVar5 + 0x5c);
  if (puVar5[0x5a] != 4) {
    *(undefined *)(param_3 + 0x56) = 0;
    iVar6 = FUN_80017a98();
    fVar1 = *(float *)(iVar6 + 0xc) - *(float *)(iVar13 + 8);
    fVar2 = *(float *)(iVar6 + 0x14) - *(float *)(iVar13 + 0x10);
    iVar4 = (int)*(short *)(iVar13 + 0x1a) / 2;
    uStack_3c = iVar4 * iVar4 ^ 0x80000000;
    local_40 = 0x43300000;
    bVar14 = fVar1 * fVar1 + fVar2 * fVar2 <
             (f32)(s32)uStack_3c;
    *(byte *)((int)puVar5 + 0xaf) = *(byte *)((int)puVar5 + 0xaf) & 0xf7;
    iVar9 = *(int *)(puVar5 + 0x5c);
    iVar4 = FUN_80017a98();
    iVar11 = *(int *)(puVar5 + 0x26);
    bVar3 = false;
    dVar15 = (double)FUN_8001771c((float *)(iVar4 + 0x18),(float *)(puVar5 + 0xc));
    uStack_34 = (int)*(short *)(iVar11 + 0x1a) ^ 0x80000000;
    local_38 = 0x43300000;
    if (((dVar15 < (double)(f32)(s32)uStack_34) &&
        (*(int *)(iVar9 + 0x230) == 3)) && ((puVar5[0x58] & 0x1000) == 0)) {
      bVar3 = true;
    }
    if (bVar3) {
      *(byte *)((int)puVar5 + 0xaf) = *(byte *)((int)puVar5 + 0xaf) & 0xef;
    }
    else {
      *(byte *)((int)puVar5 + 0xaf) = *(byte *)((int)puVar5 + 0xaf) | 0x10;
    }
    if ((!bVar14) && (*(int *)(iVar12 + 0x230) == 2)) {
      uStack_34 = (int)*(short *)(iVar13 + 0x18) ^ 0x80000000;
      local_38 = 0x43300000;
      local_48[0] = (f32)(s32)uStack_34;
      iVar4 = ObjGroup_FindNearestObject(3,puVar5,local_48);
      if (iVar4 != 0) {
        bVar14 = true;
      }
    }
    for (cVar10 = '\0'; (int)cVar10 < (int)(uint)*(byte *)(param_3 + 0x8b); cVar10 = cVar10 + '\x01'
        ) {
      if (*(char *)(param_3 + cVar10 + 0x81) == '\x01') {
        FUN_80006824(0,SFXsp_lf_mutter4);
      }
    }
    *(undefined4 *)(iVar12 + 0xc4) = 0;
    switch(*(undefined4 *)(iVar12 + 0xc4)) {
    case 0:
    case 8:
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & ~0x2;
      uVar7 = Obj_GetYawDeltaToObject(puVar5,iVar6,(float *)0x0);
      FUN_8003add8(puVar5,iVar6,iVar12 + 0x3c,0x28,0,3);
      *puVar5 = *puVar5 + ((short)uVar7 >> 3) + (ushort)((short)uVar7 < 0 && (uVar7 & 7) != 0);
      if (bVar14) {
        *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
      }
      else {
        *(undefined *)(param_3 + 0x90) = 8;
      }
      break;
    case 5:
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & ~0x2;
      iVar13 = FUN_80017a90();
      uVar7 = Obj_GetYawDeltaToObject(puVar5,iVar13,(float *)0x0);
      uVar8 = FUN_80017a90();
      FUN_8003add8(puVar5,uVar8,iVar12 + 0x3c,0x28,0,3);
      *puVar5 = *puVar5 + ((short)uVar7 >> 3) + (ushort)((short)uVar7 < 0 && (uVar7 & 7) != 0);
      break;
    case 10:
    case 0xb:
      if (*(int *)(iVar12 + 0x114) != 0) {
        *(float *)(iVar12 + 0xac) = *(float *)(iVar12 + 0xac) * lbl_803E4EE0;
        *(undefined4 *)(*(int *)(iVar12 + 0x114) + 8) = *(undefined4 *)(iVar12 + 0xac);
      }
      *(undefined4 *)(iVar12 + 0xc4) = 0xb;
      dVar15 = (double)FUN_8001771c((float *)(puVar5 + 0xc),(float *)(iVar6 + 0x18));
      uStack_34 = (int)*(short *)(iVar13 + 0x1a) ^ 0x80000000;
      local_38 = 0x43300000;
      if ((dVar15 < (double)(f32)(s32)uStack_34) &&
         ((*(byte *)((int)puVar5 + 0xaf) & 1) != 0)) {
        *(undefined4 *)(iVar12 + 0xc4) = 7;
        goto LAB_8019f118;
      }
    }
  }
LAB_8019f118:
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019dc4c
 * EN v1.0 Address: 0x8019DC4C
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x8019F140
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019dc4c(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x20);
  ObjGroup_RemoveObject(param_1,3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019dc88
 * EN v1.0 Address: 0x8019DC88
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019F17C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019dc88(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019dcb0
 * EN v1.0 Address: 0x8019DCB0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019F1B0
 * EN v1.1 Size: 1908b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019dcb0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019dcb4
 * EN v1.0 Address: 0x8019DCB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8019F924
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019dcb4(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019dcb8
 * EN v1.0 Address: 0x8019DCB8
 * EN v1.0 Size: 1136b
 * EN v1.1 Address: 0x8019FABC
 * EN v1.1 Size: 1020b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019dcb8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
  bool bVar1;
  byte bVar2;
  short sVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  uint local_38;
  uint uStack_34;
  uint auStack_30 [2];
  undefined4 local_28;
  uint uStack_24;
  
  uVar4 = FUN_80286834();
  iVar10 = *(int *)(uVar4 + 0xb8);
  local_38 = 0;
  iVar9 = *(int *)(uVar4 + 0x4c);
  bVar2 = *(byte *)(param_11 + 0x80);
  if (bVar2 == 5) {
    param_2 = (double)lbl_803E4EFC;
    uStack_24 = (uint)DAT_803dc070;
    local_28 = 0x43300000;
    *(float *)(iVar10 + 0x30) =
         (float)(param_2 * (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4f08)
                + (double)*(float *)(iVar10 + 0x30));
  }
  else if (bVar2 < 5) {
    if (3 < bVar2) {
      *(undefined *)(iVar10 + 0x37) = 6;
      goto LAB_8019fe8c;
    }
  }
  else if (bVar2 == 0x29) {
    *(float *)(iVar10 + 0x30) = lbl_803E4EF8;
  }
  if (*(short *)(uVar4 + 0xb4) < 0) goto LAB_8019fe8c;
  ObjHits_EnableObject(uVar4);
  uVar5 = FUN_80017690(0x50);
  uVar6 = FUN_80017690(0x48);
  if (((*(byte *)(iVar10 + 0x38) & 2) != 0) && (uVar7 = FUN_80017690(0x4d), uVar7 != 0)) {
    *(byte *)(iVar10 + 0x38) = *(byte *)(iVar10 + 0x38) & 0xfd;
    goto LAB_8019fe8c;
  }
  bVar1 = (char)uVar5 != '\0';
  if (bVar1) goto LAB_8019fe8c;
  if ((bVar1) || (*(char *)(iVar10 + 0x37) == '\x05')) {
    *(undefined *)(iVar10 + 0x37) = 5;
    goto LAB_8019fe8c;
  }
  bVar1 = false;
  iVar8 = FUN_80017a98();
  switch(*(undefined *)(iVar10 + 0x37)) {
  case 0:
    FUN_8003b1a4(uVar4,iVar10);
    dVar11 = (double)FUN_8001771c((float *)(uVar4 + 0x18),(float *)(iVar8 + 0x18));
    if ((char)uVar6 == '\0') {
      uStack_24 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
      local_28 = 0x43300000;
      param_2 = DOUBLE_803e4f10;
      if ((dVar11 < (double)(f32)(s32)uStack_24) ||
         (iVar9 = FUN_800810ac((double)lbl_803E4F00,(float *)(uVar4 + 0xc)), iVar9 != 0)) {
        iVar9 = FUN_80294d6c(iVar8);
        if (iVar9 == 0x40) {
          *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) | 8;
          *(undefined *)(iVar10 + 0x37) = 5;
          *(undefined2 *)(iVar10 + 0x34) = 0x14;
          (**(code **)(*DAT_803dd6d4 + 0x48))(2,uVar4,0xffffffff);
          goto LAB_8019fe8c;
        }
        bVar1 = true;
        *(undefined *)(iVar10 + 0x37) = 4;
      }
    }
    break;
  case 1:
    dVar11 = (double)FUN_8001771c((float *)(uVar4 + 0x18),(float *)(iVar8 + 0x18));
    if ((char)uVar6 == '\0') {
      uStack_24 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
      local_28 = 0x43300000;
      param_2 = DOUBLE_803e4f10;
      if (dVar11 < (double)(f32)(s32)uStack_24) {
        iVar9 = FUN_80294d6c(iVar8);
        if (iVar9 == 0x40) {
          *(undefined *)(iVar10 + 0x37) = 2;
        }
        else {
          bVar1 = true;
          *(undefined *)(iVar10 + 0x37) = 4;
        }
      }
    }
    break;
  case 2:
    sVar3 = *(short *)(iVar10 + 0x34) - (ushort)DAT_803dc070;
    *(short *)(iVar10 + 0x34) = sVar3;
    if (sVar3 < 1) {
      *(undefined *)(iVar10 + 0x37) = 1;
    }
    FUN_8003b1a4(uVar4,iVar10);
    break;
  case 3:
    sVar3 = *(short *)(iVar10 + 0x34) - (ushort)DAT_803dc070;
    *(short *)(iVar10 + 0x34) = sVar3;
    if (sVar3 < 1) {
      *(undefined *)(iVar10 + 0x37) = 0;
    }
    break;
  case 5:
    goto LAB_8019fe8c;
  case 6:
    goto LAB_8019fe8c;
  case 7:
    bVar1 = true;
    *(undefined *)(iVar10 + 0x37) = 4;
  }
  if ((*(short *)(uVar4 + 0xa0) == 0x103) || (*(short *)(uVar4 + 0xa0) == 0x2e)) {
    uVar12 = FUN_80006824(uVar4,SFXsk_doggydig11);
  }
  else {
    uVar12 = FUN_8000680c(uVar4,0x10);
  }
  if (!bVar1) {
    *(undefined *)(iVar10 + 0x36) = 0;
    *(undefined *)(param_11 + 0x56) = 0;
    do {
      iVar9 = ObjMsg_Pop(uVar4,&uStack_34,auStack_30,&local_38);
    } while (iVar9 != 0);
    if (*(char *)(param_11 + 0x80) == '\x01') {
      getLActions(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar4,uVar4,0x18,0
                   ,0,0,in_r9,in_r10);
      *(undefined *)(param_11 + 0x80) = 0;
    }
  }
LAB_8019fe8c:
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e128
 * EN v1.0 Address: 0x8019E128
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x8019FEB8
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e128(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (visible != 0) {
    FUN_8003b818(param_1);
    if (lbl_803E4EF8 < *(float *)(iVar1 + 0x30)) {
      *(float *)(iVar1 + 0x30) =
           lbl_803E4EFC *
           (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e4f08) +
           *(float *)(iVar1 + 0x30);
      if ((double)*(float *)(iVar1 + 0x30) < (double)lbl_803E4F1C) {
        FUN_8008111c((double)lbl_803E4F18,(double)*(float *)(iVar1 + 0x30),param_1,3,(int *)0x0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e1d0
 * EN v1.0 Address: 0x8019E1D0
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8019FF74
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e1d0(int param_1)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = ObjHits_GetPriorityHit(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar1 == 0x13) {
    *(undefined *)(iVar2 + 0x37) = 7;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e218
 * EN v1.0 Address: 0x8019E218
 * EN v1.0 Size: 412b
 * EN v1.1 Address: 0x8019FFBC
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e218(void)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  iVar1 = FUN_80286840();
  iVar5 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_80017a98();
  iVar4 = *(int *)(iVar1 + 0x4c);
  if ((char)*(byte *)(iVar5 + 0x39) < '\0') {
    *(byte *)(iVar5 + 0x39) = *(byte *)(iVar5 + 0x39) & 0x7f;
  }
  uVar3 = FUN_80017690((int)*(short *)(iVar4 + 0x1e));
  if (uVar3 == 0) {
    uVar3 = FUN_80017690(0x44);
    dVar6 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(iVar2 + 0x18));
    if (*(char *)(iVar5 + 0x38) == '\x01') {
      FUN_800810ac((double)lbl_803E4F00,(float *)(iVar1 + 0xc));
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
      *(undefined *)(iVar5 + 0x38) = 2;
    }
    if (((uVar3 == 0) &&
        (((*(char *)(iVar5 + 0x37) == '\x04' ||
          (dVar6 < (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(iVar4 + 0x1a) ^ 0x80000000) -
                                  DOUBLE_803e4f10))) ||
         (iVar4 = FUN_800810ac((double)lbl_803E4F00,(float *)(iVar1 + 0xc)), iVar4 != 0)))) &&
       (iVar2 = FUN_80294d6c(iVar2), iVar2 != 0x40)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar1,0xffffffff);
    }
  }
  else {
    *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
    *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
    ObjHits_DisableObject(iVar1);
    FUN_80017ad0(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e3b4
 * EN v1.0 Address: 0x8019E3B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A014C
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e3b4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019e3b8
 * EN v1.0 Address: 0x8019E3B8
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801A0200
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8019e3b8(int param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 0x74) == '\0') && (*(char *)(param_3 + 0x80) == '\x02'))
  {
    *(undefined *)(*(int *)(param_1 + 0xb8) + 0x74) = 1;
    iVar1 = FUN_80017a98();
    FUN_80294d40(iVar1,2);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e408
 * EN v1.0 Address: 0x8019E408
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x801A0270
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e408(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  
  iVar1 = FUN_80286838();
  piVar4 = *(int **)(iVar1 + 0xb8);
  uVar2 = FUN_80017690(0x50);
  if (uVar2 == 0) {
    uVar2 = FUN_80017690(0x4d);
    if ((uVar2 == 0) || (visible == '\0')) {
      if ((piVar4 != (int *)0x0) && (iVar3 = *piVar4, iVar3 != 0)) {
        if (*(char *)((int)piVar4 + 0x73) == '\0') {
          if (visible != '\0') {
            iVar3 = FUN_80057690(iVar3);
            if (iVar3 != 0) {
              FUN_8003b818(*piVar4);
              ObjPath_GetPointWorldPosition(*piVar4,0,(float *)(iVar1 + 0xc),(undefined4 *)(iVar1 + 0x10),
                           (float *)(iVar1 + 0x14),0);
            }
            FUN_8003b818(iVar1);
          }
        }
        else {
          iVar3 = FUN_80057690(iVar3);
          if (iVar3 != 0) {
            FUN_8003b818(*piVar4);
          }
          if (visible != '\0') {
            FUN_8003b818(iVar1);
          }
        }
      }
    }
    else {
      FUN_8003b818(iVar1);
      if ((*piVar4 != 0) && (iVar1 = FUN_80057690(*piVar4), iVar1 != 0)) {
        FUN_8003b818(*piVar4);
      }
    }
  }
  else if ((*piVar4 != 0) && (iVar1 = FUN_80057690(*piVar4), iVar1 != 0)) {
    FUN_8003b818(*piVar4);
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e54c
 * EN v1.0 Address: 0x8019E54C
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x801A0458
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e54c(uint param_1)
{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined2 *puVar4;
  int iVar5;
  int *piVar6;
  uint uStack_38;
  uint uStack_34;
  int local_30;
  int local_2c;
  uint auStack_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  piVar6 = *(int **)(param_1 + 0xb8);
  if ((piVar6 != (int *)0x0) && (uVar1 = FUN_80017690(0x50), uVar1 == 0)) {
    iVar2 = ObjMsg_Pop(param_1,&uStack_34,auStack_28,&uStack_38);
    if (iVar2 != 0) {
      *piVar6 = 0;
    }
    if (*piVar6 == 0) {
      iVar2 = FUN_80017b00(&local_2c,&local_30);
      for (; local_2c < local_30; local_2c = local_2c + 1) {
        iVar5 = *(int *)(iVar2 + local_2c * 4);
        if (*(short *)(iVar5 + 0x44) == 0x3d) {
          *piVar6 = iVar5;
          local_2c = local_30;
        }
      }
    }
    ObjTrigger_UpdateIdBlockFlag(param_1);
    uVar1 = FUN_80017690(0x4d);
    *(char *)((int)piVar6 + 0x73) = (char)uVar1;
    if (*(char *)((int)piVar6 + 0x73) == '\0') {
      uVar3 = FUN_80017a98();
      FUN_8003add8(param_1,uVar3,*(int *)(param_1 + 0xb8) + 4,0x41,0,3);
      uVar1 = randomGetRange(0,0x1e);
      if (uVar1 == 0) {
        FUN_800392ec(param_1,(undefined *)(piVar6 + 0xd),0x297);
      }
      iVar2 = ObjTrigger_IsSet(param_1);
      if (iVar2 == 0) {
        objAnimFn_80038f38(param_1,(char *)(piVar6 + 0xd));
        uStack_1c = (uint)DAT_803dc070;
        local_20 = 0x43300000;
        FUN_8002fc3c((double)lbl_803E4F24,
                     (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4f28));
      }
      else {
        FUN_8003add8(param_1,uVar3,*(int *)(param_1 + 0xb8) + 4,0x41,0,3);
        puVar4 = (undefined2 *)FUN_8003964c(param_1,1);
        *puVar4 = 0xf556;
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
      }
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      if (*(short *)(param_1 + 0xb4) == -1) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e764
 * EN v1.0 Address: 0x8019E764
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A0670
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e764(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019e768
 * EN v1.0 Address: 0x8019E768
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x801A06F0
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_8019e768(int param_1)
{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 8) >> 7;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e77c
 * EN v1.0 Address: 0x8019E77C
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801A0710
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e77c(int param_1)
{
  if (**(uint **)(param_1 + 0xb8) != 0) {
    FUN_80017520(*(uint **)(param_1 + 0xb8));
  }
  if (*(int *)(param_1 + 0xc4) != 0) {
    ObjLink_DetachChild(*(int *)(param_1 + 0xc4),param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e7cc
 * EN v1.0 Address: 0x8019E7CC
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x801A0764
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e7cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9)
{
  int iVar1;
  byte bVar2;
  int iVar3;
  int local_70;
  float local_6c;
  float local_68;
  undefined4 local_64;
  int aiStack_60 [22];
  
  iVar3 = param_9[0x2e];
  *(byte *)(iVar3 + 8) = *(byte *)(iVar3 + 8) & 0x7f;
  if (((param_9[0x31] != 0) &&
      (((iVar1 = ObjHits_GetPriorityHit((int)param_9,&local_70,(int *)0x0,(uint *)0x0), iVar1 != 0 ||
        (local_70 = *(int *)(param_9[0x15] + 0x50), local_70 != 0)) &&
       (iVar1 = FUN_80017a98(), local_70 == iVar1)))) &&
     (bVar2 = FUN_80294c20(local_70), bVar2 == 0)) {
    local_6c = *(float *)(local_70 + 0xc);
    local_68 = (float)((double)lbl_803E4F30 + (double)*(float *)(local_70 + 0x10));
    local_64 = *(undefined4 *)(local_70 + 0x14);
    iVar1 = FUN_8020a490((double)lbl_803E4F30,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,(float *)(param_9 + 3),&local_6c);
    if (iVar1 != 0) {
      if ((param_9[0x3d] == 0) &&
         (iVar1 = FUN_800620e8(param_9 + 3,&local_6c,(float *)0x0,aiStack_60,param_9,4,0xffffffff,0,
                               0), iVar1 != 0)) {
        return;
      }
      *(byte *)(iVar3 + 8) = *(byte *)(iVar3 + 8) & 0x7f | 0x80;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019e964
 * EN v1.0 Address: 0x8019E964
 * EN v1.0 Size: 600b
 * EN v1.1 Address: 0x801A088C
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019e964(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  double dVar5;
  byte local_58;
  byte local_57;
  byte local_56 [2];
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  longlong local_20;
  undefined4 local_18;
  uint uStack_14;
  longlong local_10;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  if (*piVar4 == 0) {
    iVar3 = FUN_80017524(param_9,0xfa,0xfa,0xfa,1);
    *piVar4 = iVar3;
    if (*piVar4 != 0) {
      param_2 = (double)(float)((double)lbl_803E4F38 + (double)lbl_803DCAC0);
      FUN_800175d0((double)lbl_803DCAC0,param_2,*piVar4);
    }
  }
  ObjHits_SetHitVolumeSlot((int)param_9,0x17,0,0);
  local_48 = DAT_80323888;
  local_44 = DAT_8032388c;
  local_40 = DAT_80323890;
  FUN_80017a40(param_9,&DAT_80323888,&local_48);
  FUN_8020a494((double)lbl_803DCAC4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               &local_54,(float *)(param_9 + 6),&local_48);
  dVar5 = FUN_802480e8((float *)(param_9 + 6),&local_54);
  FUN_80247edc(dVar5,&DAT_80323888,&local_54);
  FUN_80080f8c(0,local_56,&local_57,&local_58);
  if (*piVar4 != 0) {
    uStack_34 = (uint)local_56[0];
    local_38 = 0x43300000;
    iVar3 = (int)(lbl_803E4F3C * (f32)(s32)uStack_34
                 );
    local_30 = (longlong)iVar3;
    uStack_24 = (uint)local_57;
    local_28 = 0x43300000;
    iVar1 = (int)(lbl_803E4F3C * (f32)(s32)uStack_24
                 );
    local_20 = (longlong)iVar1;
    uStack_14 = (uint)local_58;
    local_18 = 0x43300000;
    iVar2 = (int)(lbl_803E4F3C * (f32)(s32)uStack_14
                 );
    local_10 = (longlong)iVar2;
    FUN_8001759c(*piVar4,(char)iVar3,(char)iVar1,(char)iVar2,0xff);
    FUN_800175ec((double)local_54,(double)local_50,(double)local_4c,(int *)*piVar4);
  }
  return;
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

  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  *puVar1 = 0;
  puVar1[1] = 0;
  ObjHits_EnableObject(param_1);
  *(undefined *)(param_1 + 0x36) = 0x80;
  return;
}

extern int babycloudrunner_SeqFn(int *obj, int p2, u8 *p3);
extern f32 lbl_803E422C;
extern f32 lbl_803E4244;
extern f32 lbl_803E4258;
extern u8 lbl_803DBE28;
extern u8 lbl_803DBE30;
extern void storeZeroToFloatParam(void* p);
extern uint GameBit_Get(int eventId);
extern int objRemoveFromListFn_8002ce88(int *obj);

typedef struct BabyCloudrunnerFlags {
    u8 resetLatch : 1;
    u8 flags : 7;
} BabyCloudrunnerFlags;

#pragma scheduling off
#pragma peephole off
void babycloudrunner_init(int *obj, u8 *def) {
    u8 *sub;

    ObjHits_EnableObject(obj);
    ObjMsg_AllocQueue(obj, 4);
    *(void**)((char*)obj + 0xbc) = (void*)&babycloudrunner_SeqFn;
    *(s16*)obj = (s16)(def[0x1d] << 8);
    ObjGroup_AddObject(obj, 3);
    sub = *(u8**)((char*)obj + 0xb8);
    *(int*)(sub + 0xb0) = 0;
    *(int*)(sub + 0xb4) = 0;
    *(int*)(sub + 0xb8) = 0;
    *(int*)(sub + 0xbc) = 0;
    *(int*)(sub + 0xc0) = 0;
    *(int*)(sub + 0xc4) = def[0x1c];
    *(int*)(sub + 0xcc) = 0;
    storeZeroToFloatParam(sub);
    *(int*)(sub + 0x114) = 0;
    *(s16*)(sub + 0xd0) = *(s16*)obj;
    sub[0x22c] = 0;
    *(f32*)(sub + 0xa8) = lbl_803E422C;
    *(int*)(sub + 0x230) = 0;
    if (GameBit_Get(*(s16*)(def + 0x22)) != 0) {
        ObjHits_DisableObject(obj);
        *(s16*)((char*)obj + 6) = (s16)(*(s16*)((char*)obj + 6) | 0x4000);
        sub[0x22c] = (u8)(sub[0x22c] & ~1);
        objRemoveFromListFn_8002ce88(obj);
        ObjGroup_RemoveObject(obj, 3);
    } else {
        *(int*)(sub + 0x234) = *(s16*)(def + 0x22) - 0x2fc;
        if (*(s16*)((char*)obj + 0x46) == 0x788) {
            *(int*)(sub + 0x234) = -1;
            *(f32*)(sub + 0x23c) = lbl_803E4244;
            *(void**)(sub + 0x240) = &lbl_803DBE30;
        } else {
            if (*(int*)(sub + 0x234) < 0 || *(int*)(sub + 0x234) > 4) {
                *(int*)(sub + 0x230) = 3;
            }
            *(f32*)(sub + 0x23c) = lbl_803E4258;
            *(void**)(sub + 0x240) = &lbl_803DBE28;
            ObjGroup_AddObject(obj, 0x20);
        }
        ((BabyCloudrunnerFlags *)(sub + 0x244))->resetLatch = 0;
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
 * Function: FUN_8019ec44
 * EN v1.0 Address: 0x8019EC44
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x801A0AC4
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019ec44(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  ObjMsg_SendToObjects(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3e,0,param_9,
               0x40001,0,in_r8,in_r9,in_r10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019ecf0
 * EN v1.0 Address: 0x8019ECF0
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x801A0B04
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019ecf0(int param_1)
{
  uint uVar1;
  
  if ((*(int *)(param_1 + 0xf4) != 0) && (uVar1 = FUN_80017690(0x50), uVar1 == 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
  }
  *(undefined4 *)(param_1 + 0xf4) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019ed60
 * EN v1.0 Address: 0x8019ED60
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x801A0B90
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8019ed60(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint local_28;
  uint uStack_24;
  uint local_20 [5];
  
  local_28 = 0;
  iVar3 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80017690((int)*(short *)(iVar3 + 0x18));
  if (uVar1 == 0) {
    if (*(short *)(param_1 + 0x46) != 0x127) {
      while (iVar2 = ObjMsg_Pop(param_1,local_20,&uStack_24,&local_28), iVar2 != 0) {
        if (local_20[0] == 0xa0005) {
          FUN_80017698((int)*(short *)(iVar3 + 0x18),1);
        }
      }
      uVar1 = FUN_80017690(0x44);
      if (uVar1 == 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
      }
      if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
         (iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x44), iVar3 != 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      }
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8019eeac
 * EN v1.0 Address: 0x8019EEAC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A0D28
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019eeac(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019eed4
 * EN v1.0 Address: 0x8019EED4
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801A0D58
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019eed4(int param_1)
{
  int iVar1;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 auStack_10 [4];
  
  iVar1 = ObjHits_GetPriorityHitWithPosition(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0,&uStack_18,&uStack_14,
                       auStack_10);
  if (iVar1 != 0) {
    FUN_800810e8(&uStack_18,8,200,0x80,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019ef2c
 * EN v1.0 Address: 0x8019EF2C
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x801A0DB0
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019ef2c(int param_1)
{
  short sVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0xf4) != 0) {
    sVar1 = *(short *)(param_1 + 0x46);
    if (((sVar1 == 0x128) || (0x127 < sVar1)) || (sVar1 < 0x127)) {
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
    (**(code **)(*DAT_803dd6d4 + 0x48))(uVar2,param_1,0xffffffff);
    *(undefined4 *)(param_1 + 0xf4) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019efac
 * EN v1.0 Address: 0x8019EFAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A0E30
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019efac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8019efb0
 * EN v1.0 Address: 0x8019EFB0
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801A0F20
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019efb0(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x4e);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019efd4
 * EN v1.0 Address: 0x8019EFD4
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801A0F44
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019efd4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if ((visible != 0) && (**(char **)(param_1 + 0xb8) != '\0')) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019f00c
 * EN v1.0 Address: 0x8019F00C
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801A0F8C
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019f00c(int param_1)
{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  
  pcVar3 = *(char **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*pcVar3 == '\0') {
    uVar1 = FUN_80017690((int)*(short *)(iVar2 + 0x1e));
    uVar1 = countLeadingZeros(uVar1);
    *pcVar3 = (char)(uVar1 >> 5);
    if ((uVar1 >> 5 & 0xff) != 0) {
      ObjGroup_AddObject(param_1,0x4e);
    }
    if (*(char *)(param_1 + 0x36) != '\0') {
      *(char *)(param_1 + 0x36) = *(char *)(param_1 + 0x36) + -1;
    }
  }
  else {
    FUN_80081110(param_1,5,0,0,(undefined4 *)0x0);
    uVar1 = FUN_80017690((int)*(short *)(iVar2 + 0x1e));
    uVar1 = countLeadingZeros(uVar1);
    *pcVar3 = (char)(uVar1 >> 5);
    if ((uVar1 >> 5 & 0xff) == 0) {
      ObjGroup_RemoveObject(param_1,0x4e);
    }
    if (*(char *)(param_1 + 0x36) != -1) {
      *(char *)(param_1 + 0x36) = *(char *)(param_1 + 0x36) + '\x01';
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019f0ec
 * EN v1.0 Address: 0x8019F0EC
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x801A1090
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_8019f0ec(int param_1)
{
  return *(byte *)(*(int *)(param_1 + 0xb8) + 0x4a) >> 5 & 1;
}

/*
 * --INFO--
 *
 * Function: FUN_8019f0fc
 * EN v1.0 Address: 0x8019F0FC
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x801A10A0
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8019f0fc(int param_1)
{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  if (((*(char *)(*(int *)(param_1 + 0xb8) + 0x15) == '\0') &&
      (*(float *)(*(int *)(param_1 + 0xb8) + 0x18) == lbl_803E4F58)) &&
     (iVar1 = (**(code **)(*DAT_803dd740 + 0x14))(), iVar1 == 0)) {
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_8019f16c
 * EN v1.0 Address: 0x8019F16C
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x801A110C
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019f16c(int param_1)
{
  float fVar1;
  int iVar2;
  
  fVar1 = lbl_803E4F58;
  iVar2 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar2 + 0x24) = lbl_803E4F58;
  *(float *)(iVar2 + 0x20) = fVar1;
  *(float *)(iVar2 + 0x28) = fVar1;
  *(byte *)(iVar2 + 0x49) = *(byte *)(iVar2 + 0x49) | 1;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  *(float *)(iVar2 + 0x38) = fVar1;
  *(byte *)(iVar2 + 0x4a) = *(byte *)(iVar2 + 0x4a) & 0xdf;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019f1ac
 * EN v1.0 Address: 0x8019F1AC
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801A1158
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019f1ac(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar1 + 0x4a) = *(byte *)(iVar1 + 0x4a) & 0xdf | 0x20;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *(byte *)(iVar1 + 0x49) = *(byte *)(iVar1 + 0x49) & 0xfd;
  return;
}

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
extern int cfguardian_SeqFn(int *obj, int p2, int *p3);
extern void dll_2E_func0A(int a, int *obj);
extern void dll_2E_func05(int *obj, u8 *sub, int c, int d, int e);
extern void dll_2E_func08(u8 *sub, int b, int c);
extern void dll_2E_func09(u8 *sub, void *a, void *b, int c);
extern void objSeqInitFn_80080078(u8 *p, int n);

#pragma scheduling off
#pragma peephole off
void cfguardian_init(int *obj, u8 *params) {
    u8 *sub;
    GuardianVec stk1;
    GuardianVec stk2;

    sub = *(u8**)((char*)obj + 0xb8);
    stk1 = lbl_802C22C0;
    stk2 = lbl_802C22CC;
    if (sub == NULL) return;
    ObjMsg_AllocQueue(obj, 4);
    sub[0xa80] = (u8)GameBit_Get(0x4b);
    *(int*)((char*)obj + 0xf4) = 1;
    *(void**)((char*)obj + 0xbc) = (void*)&cfguardian_SeqFn;
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    *(int*)(sub + 0xa94) = 0;
    *(f32*)(sub + 0x7fc) = lbl_803E4110;
    *(int*)(sub + 0xa90) = 6;
    sub[0xa9b] = 0;
    sub[0x611] = (u8)(sub[0x611] | 0x28);
    sub[0xa98] = 1;
    sub[0xa99] = 0;
    sub[0xa9a] = 0;
    if (GameBit_Get(0x57) != 0) {
        sub[0xa80] = 4;
        if ((s8)params[0x19] == 0) {
            *(s16*)((char*)obj + 6) = (s16)(*(s16*)((char*)obj + 6) | 0x4000);
            objRemoveFromListFn_8002ce88(obj);
        }
    } else if (GameBit_Get(0x60) != 0 && (s8)params[0x19] == 0) {
        sub[0xa80] = 4;
        dll_2E_func0A(8, obj);
    }
    ObjHits_EnableObject(obj);
    dll_2E_func05(obj, sub, -0x2000, 0x2800, 4);
    dll_2E_func08(sub, 0x12c, 0x64);
    dll_2E_func09(sub, &stk2, &stk1, 4);
    objSeqInitFn_80080078(lbl_8032284C, 0xf);
    sub[0x611] = (u8)(sub[0x611] | 0x2);
}
#pragma peephole reset
#pragma scheduling reset

typedef struct { int a, b, c, d; } GuardianMsg;
extern GuardianMsg lbl_802C22D8;
extern int  dll_2E_func07(int* obj, int* p3, u8* sub, int x, int y);
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
int cfguardian_SeqFn(int* obj, int p2, int* p3)
{
    int* sel;
    GuardianMsg stk;
    u8* sub = *(u8**)((char*)obj + 0xb8);
    stk = lbl_802C22D8;
    if (*(s16*)((char*)obj + 0xb4) < 0) {
        saveGame_saveObjectPos((int)obj);
        return 0;
    }
    if (sub[0xa80] != 6) {
        sel = &stk.a;
    } else {
        sel = &stk.c;
    }
    if (animatedObjGetSeqId(p3) != 0x283) {
        if (dll_2E_func07(obj, p3, sub, (s16)sel[0], (s16)sel[1]) != 0) {
            return 1;
        }
    }
    if (*(u8*)((char*)p3 + 0x80) == 2) {
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
        if (*(int*)((char*)c + 0xc0) != 0) {
            *(int*)((char*)c + 0xc0) = 0;
            ObjAnim_SetCurrentMove((int)a, 0, lbl_803E4218, 0);
        } else {
            ObjAnim_AdvanceCurrentMove(lbl_803E423C, timeDelta, (int)a, 0);
        }
    } else {
        if (*(int*)((char*)c + 0xc0) == 0) {
            *(int*)((char*)c + 0xc0) = 1;
            ObjAnim_SetCurrentMove((int)a, 9, lbl_803E4218, 0);
        } else {
            s16 t;
            if ((s16)shifted > 0) {
                t = (s16)shifted >> 2;
            } else {
                t = -(s16)shifted >> 2;
            }
            ObjAnim_AdvanceCurrentMove((f32)t / lbl_803E4240, timeDelta, (int)a, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int *gGameUIInterface;
extern int *gObjectTriggerInterface;

/* EN v1.0 0x801A0614  size: 368b  cfprisoncage_SeqFn: drain the object's message
 * queue (re-arming its gamebit on the keyed message), then sync the
 * lit/active state from gamebit 0x44 and notify on completion. */
#pragma scheduling off
#pragma peephole off
int cfprisoncage_SeqFn(int* obj, int p2, u8* p3)
{
    int msg;
    int v;
    int w = 0;
    u8* sub = *(u8**)((char*)obj + 0x4c);
    if (GameBit_Get(*(s16*)(sub + 0x18)) != 0) {
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x8);
        *(u8*)((char*)p3 + 0x90) = (u8)(*(u8*)((char*)p3 + 0x90) | 0x4);
        return 0;
    }
    if (*(s16*)((char*)obj + 0x46) == 0x127) {
        return 0;
    }
    while (ObjMsg_Pop(obj, &msg, &v, &w) != 0) {
        if (msg == 0xa0005) {
            GameBit_Set(*(s16*)(sub + 0x18), 1);
        }
    }
    if (GameBit_Get(0x44) != 0) {
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~0x10);
    } else {
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x10);
    }
    if ((*(u8*)((char*)obj + 0xaf) & 1) != 0) {
        if (((int (*)(int))((int *)*gGameUIInterface)[0x20 / 4])(0x44) != 0) {
            *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x8);
            ((void (*)(int, int *, int))((int *)*gObjectTriggerInterface)[0x48 / 4])(0, obj, -1);
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
extern f32  lbl_803E4244;

/* EN v1.0 0x8019E6C8  size: 316b  babycloudrunner_func0B: when the player
 * gets within the trigger radius and the runner is in state 3, fire its
 * burst (notify, bump the counter, set the gamebit); otherwise just play
 * the idle audio cue. */
#pragma scheduling off
#pragma peephole off
int babycloudrunner_func0B(int* obj)
{
    u8* sub = *(u8**)((char*)obj + 0xb8);
    u8* q = *(u8**)((char*)obj + 0x4c);
    int flag = 0;
    void* player = Obj_GetPlayerObject();
    u8* r = *(u8**)((char*)obj + 0x4c);
    if (Vec_distance((char*)player + 0x18, (char*)obj + 0x18) < (f32)(s16)*(s16*)(r + 0x1a)) {
        if (*(int*)(sub + 0x230) == 3) {
            if ((*(u16*)((char*)obj + 0xb0) & 0x1000) == 0) {
                flag = 1;
            }
        }
    }
    if (flag != 0) {
        s16toFloat((int)sub, 0x3c);
        *(int*)((char*)obj + 0xf4) = 1;
        *(s16*)obj = *(s16*)(sub + 0xd0);
        ((void (*)(int, int *, int))((int *)*gObjectTriggerInterface)[0x48 / 4])(4, obj, -1);
        *(f32*)(sub + 0) = lbl_803E4244;
        gameBitIncrement(0x901);
        *(int*)(sub + 0xc4) = 0xc;
        GameBit_Set(*(s16*)(q + 0x1e), 1);
        *(int*)((char*)obj + 0xf4) = 0;
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

extern int cfpowerbase_SeqFn(int p1, int unused, int p3);

/* EN v1.0 0x8019D8B4  size: 308b  cfpowerbase_init: seed header and the
 * sub's type from spawn params, map the type id (0x54..0x56) to a model
 * and gamebit, then gate the active/lit state bits on those gamebits. */
#pragma scheduling off
#pragma peephole off
void cfpowerbase_init(int* obj, u8* params) {
    u8* sub = *(u8**)((char*)obj + 0xb8);
    s16 type;
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    *(s16*)(sub + 0) = *(s16*)(params + 0x1e);
    type = *(s16*)(sub + 0);
    switch (type) {
    case 0x54:
        *(s16*)(sub + 2) = 0x51;
        sub[4] = 0;
        break;
    case 0x55:
        *(s16*)(sub + 2) = 0x52;
        sub[4] = 1;
        Obj_SetActiveModelIndex(obj, 2);
        break;
    case 0x56:
        *(s16*)(sub + 2) = 0x53;
        sub[4] = 2;
        Obj_SetActiveModelIndex(obj, 1);
        break;
    }
    *(void**)((char*)obj + 0xbc) = (void*)&cfpowerbase_SeqFn;
    ObjMsg_AllocQueue(obj, 2);
    if (GameBit_Get(*(s16*)(sub + 2)) != 0) {
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~0x10);
    } else {
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x10);
    }
    if (GameBit_Get(*(s16*)(sub + 0)) != 0) {
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x8);
        *(int*)((char*)obj + 0xf4) = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int *gGameUIInterface;
extern int *gObjectTriggerInterface;

/* EN v1.0 0x8019D77C  size: 312b  cfpowerbase_update: track its gamebit's
 * lit state, fire the queued state-change trigger, and when the base is
 * powered and its UI condition clears, mark it done and notify. */
#pragma scheduling off
#pragma peephole off
void cfpowerbase_update(int* obj) {
    u8* sub = *(u8**)((char*)obj + 0xb8);
    if (GameBit_Get(*(s16*)(sub + 2)) != 0) {
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~0x10);
    } else {
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x10);
    }
    if (*(int*)((char*)obj + 0xf4) != 0) {
        ((void (*)(int *, int))((int *)*gObjectTriggerInterface)[0x54 / 4])(obj, 0xfa);
        ((void (*)(int, int *, int))((int *)*gObjectTriggerInterface)[0x48 / 4])((*(s8*)(sub + 4)), obj, 3);
        *(int*)((char*)obj + 0xf4) = 0;
    }
    if ((*(u8*)((char*)obj + 0xaf) & 1) != 0) {
        if (((int (*)(int))((int *)*gGameUIInterface)[0x20 / 4])(*(s16*)(sub + 2)) != 0) {
            *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x8);
            GameBit_Set(*(s16*)(sub + 2), 0);
            GameBit_Set(0x973, 0);
            ((void (*)(int, int *, int))((int *)*gObjectTriggerInterface)[0x48 / 4])((*(s8*)(sub + 4)), obj, -1);
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

extern int cfprisonguard_SeqFn(int* obj, int p2, u8* p3);

typedef struct { u8 top : 1; u8 rest : 7; } Bit80;

/* EN v1.0 0x8019FBD0  size: 172b  cfprisonguard_init: set up the guard's
 * substate (update fn cfprisonguard_SeqFn, message queue), seed its header from
 * the spawn params, and apply the alarm-active gating bits. */
#pragma scheduling off
#pragma peephole off
void cfprisonguard_init(int* obj, u8* params) {
    u8* sub = *(u8**)((char*)obj + 0xb8);
    sub[0x38] = 1;
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    *(void**)((char*)obj + 0xbc) = (void*)&cfprisonguard_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    sub[0x36] = 1;
    if (GameBit_Get(0x4d) != 0) {
        sub[0x38] = (u8)(sub[0x38] | 4);
    }
    *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~0x10);
    ((Bit80*)(sub + 0x39))->top = 1;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E4268;
extern f32 Vec_distance(void *a, void *b);
extern int waterfx_consumePendingImpactNearPoint(f32 *vec, f32 r);
extern int objGetAnimState80A(void *obj);
extern int *gObjectTriggerInterface;
extern void *Obj_GetPlayerObject(void);

#pragma scheduling off
#pragma peephole off
void cfprisonguard_update(int *obj) {
    u8 *sub;
    int *player;
    u8 *def;
    int bit44;
    f32 dist;

    sub = *(u8**)((char*)obj + 0xb8);
    player = (int*)Obj_GetPlayerObject();
    def = *(u8**)((char*)obj + 0x4c);
    if (((u32)sub[0x39] >> 7) & 1u) {
        sub[0x39] = (u8)(sub[0x39] & ~0x80);
    }
    if (GameBit_Get(*(s16*)(def + 0x1e)) != 0) {
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x8);
        *(s16*)((char*)obj + 6) = (s16)(*(s16*)((char*)obj + 6) | 0x4000);
        ObjHits_DisableObject(obj);
        objRemoveFromListFn_8002ce88(obj);
        return;
    }
    bit44 = GameBit_Get(0x44);
    dist = Vec_distance((char*)obj + 0x18, (char*)player + 0x18);
    if (sub[0x38] == 1) {
        waterfx_consumePendingImpactNearPoint((f32 *)((char*)obj + 0xc), lbl_803E4268);
        ((void(*)(int, int*, int))((void**)*gObjectTriggerInterface)[18])(0, obj, -1);
        sub[0x38] = 2;
    }
    if (bit44 == 0) {
        if ((s8)sub[0x37] != 4) {
            if (dist >= (f32)(s32)*(s16*)(def + 0x1a)) {
                if (waterfx_consumePendingImpactNearPoint((f32 *)((char*)obj + 0xc), lbl_803E4268) == 0) return;
            }
        }
        if (objGetAnimState80A(player) != 0x40) {
            ((void(*)(int, int*, int))((void**)*gObjectTriggerInterface)[18])(1, obj, -1);
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
extern int *gObjectTriggerInterface;
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
    u8* sub = *(u8**)((char*)obj + 0xb8);
    void* player;
    int m2, objectIndex, objectCount, m1, m3;
    int* objects;
    int i;
    if (sub == NULL) return;
    if (GameBit_Get(0x50) != 0) return;
    if (ObjMsg_Pop(obj, &m1, &m2, &m3) != 0) {
        *(void**)(sub + 0) = NULL;
    }
    if (*(void**)(sub + 0) == NULL) {
        objects = ObjList_GetObjects(&objectIndex, &objectCount);
        for (i = objectIndex; i < objectCount; i++) {
            if (*(s16*)((char*)objects[i] + 0x44) == 0x3d) {
                *(int*)(sub + 0) = objects[i];
                i = objectCount;
            }
        }
    }
    ObjTrigger_UpdateIdBlockFlag((int)obj);
    *(s8*)(sub + 0x73) = (s8)GameBit_Get(0x4d);
    if (*(s8*)(sub + 0x73) == 0) {
        player = Obj_GetPlayerObject();
        fn_8003ADC4(obj, player, (char*)sub + 4, 0x41, 0, 3);
        if ((int)randomGetRange(0, 0x1e) == 0) {
            objAudioFn_80039270((int)obj, (char*)sub + 0x34, 0x297);
        }
        if (ObjTrigger_IsSet((int)obj) != 0) {
            fn_8003ADC4(obj, player, (char*)sub + 4, 0x41, 0, 3);
            *(s16*)objModelGetVecFn_800395d8((int)obj, 1) = -0xaaa;
            ((void (*)(int, int *, int))((int *)*gObjectTriggerInterface)[0x48 / 4])(1, obj, -1);
        } else {
            objAnimFn_80038f38((int)obj, (char*)sub + 0x34);
            ObjAnim_AdvanceCurrentMove(lbl_803E428C, (f32)(u32)framesThisStep, (int)obj, 0);
        }
    } else {
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 0x8);
        if (*(s16*)((char*)obj + 0xb4) == -1) {
            ((void (*)(int, int *, int))((int *)*gObjectTriggerInterface)[0x48 / 4])(0, obj, -1);
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
    u8* sub = *(u8**)((char*)obj + 0xb8);
    ((Bit80*)(sub + 8))->top = 0;
    if (*(void**)((char*)obj + 0xc4) == NULL) return;
    if (ObjHits_GetPriorityHit((int)obj, &hit, 0, 0) == 0) {
        hit = *(void**)((char*)*(void**)((char*)obj + 0x54) + 0x50);
        if (hit == NULL) return;
    }
    if (hit != Obj_GetPlayerObject()) return;
    if (playerIsDisguised(hit) != 0) return;
    vec[0] = *(f32*)((char*)hit + 0xc);
    vec[1] = lbl_803E4298 + *(f32*)((char*)hit + 0x10);
    vec[2] = *(f32*)((char*)hit + 0x14);
    if (voxmaps_traceWorldLine((void *)((int)obj + 0xc), vec) == 0) return;
    if (*(int*)((char*)obj + 0xf4) != 0 ||
        objBboxFn_800640cc((int)obj + 0xc, vec, 0, &out, (int)obj, 4, -1, 0, 0) == 0) {
        ((Bit80*)(sub + 8))->top = 1;
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
    extern int *gObjectTriggerInterface;
    int v;
    if (*(int*)((char*)obj + 0xf4) != 0) {
        switch (*(s16*)((char*)obj + 0x46)) {
        case 0x127: v = 0; break;
        case 0x128:
        default:    v = 1; break;
        }
        ((void(*)(int, int*, int))((void**)*(int*)gObjectTriggerInterface)[18])(v, obj, -1);
        *(int*)((char*)obj + 0xf4) = 0;
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
extern void objRenderFn_8003b8f4(f32);
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
extern u8    framesThisStep;
extern void  objParticleFn_80099d84(int obj, int a, f32 f, int b);

/* EN v1.0 0x8019F93C  size: 188b  cfprisonguard_render: render the guard
 * model when visible, ramp its alarm timer at sub->_30 each frame, and
 * once it crosses the threshold spawn a one-shot particle. */
#pragma scheduling off
#pragma peephole off
void cfprisonguard_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* sub = *(u8**)((char*)obj + 0xb8);
    if (visible != 0) {
        objRenderFn_8003b8f4(lbl_803E4280);
    }
    if (visible != 0) {
        f32 t = *(f32*)(sub + 0x30);
        if (t > lbl_803E4260) {
            *(f32*)(sub + 0x30) = lbl_803E4264 * (f32)(u32)framesThisStep + t;
            if (*(f32*)(sub + 0x30) < lbl_803E4284) {
                objParticleFn_80099d84((int)obj, 3, lbl_803E4280, 0);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void spiritdoorspirit_free(int x) { ObjGroup_RemoveObject(x, 0x4e); }
#pragma peephole reset
#pragma scheduling reset

/* if (o->_X == K) return A; else return B; */
#pragma peephole off
#pragma scheduling off
#pragma peephole off
int cfprisoncage_getObjectTypeId(int *obj) { if (*(s16*)((char*)obj + 0x46) == 0x128) return 0x8; return 0x0; }
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

/* chained byte bit-extract. */
u32 fn_801A0174(int *obj) { return (*((u8*)((int**)obj)[0xb8/4] + 0x8) >> 7) & 1; }
u32 gunpowderbarrel_isHeld(int *obj) { return (*((u8*)((int**)obj)[0xb8/4] + 0x4a) >> 5) & 1; }

typedef struct { u8 playerHeld : 1; u8 _pad0 : 1; u8 held : 1; u8 _pad1 : 5; } GpbHeldByte;
extern f32 lbl_803E42C0;

/* EN v1.0 0x801A0BDC  size: 56b  gunpowderbarrel_setHeldState: flag the
 * barrel as held, mark obj active, and clear its physics-sleep bit. */
#pragma scheduling off
#pragma peephole off
void gunpowderbarrel_setHeldState(int* obj) {
    u8* sub = *(u8**)((char*)obj + 0xb8);
    ((GpbHeldByte*)(sub + 0x4a))->held = 1;
    *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 8);
    *(u8*)(sub + 0x49) = (u8)(*(u8*)(sub + 0x49) & ~2);
}

/* EN v1.0 0x801A0B90  size: 76b  gunpowderbarrel_clearHeldState: zero the
 * barrel's velocity/throw vectors, mark it sleeping, clear obj-active and
 * the held flag. */
void gunpowderbarrel_clearHeldState(int* obj) {
    u8* sub = *(u8**)((char*)obj + 0xb8);
    f32 z = lbl_803E42C0;
    *(f32*)(sub + 0x24) = z;
    *(f32*)(sub + 0x20) = z;
    *(f32*)(sub + 0x28) = z;
    *(u8*)(sub + 0x49) = (u8)(*(u8*)(sub + 0x49) | 1);
    *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~8);
    *(f32*)(sub + 0x38) = z;
    ((GpbHeldByte*)(sub + 0x4a))->held = 0;
}

/* EN v1.0 0x801A0E04  size: 244b  gunpowderbarrel_setPlayerHeldState: when
 * grabbed by the player, copy the held-pose and enable hit reactions; when
 * released, restore the default pose and clear them. */
void gunpowderbarrel_setPlayerHeldState(int* obj, u8 heldByPlayer) {
    u8* sub = *(u8**)((char*)obj + 0xb8);
    u8* h = *(u8**)((char*)obj + 0x54);
    if (heldByPlayer != 0) {
        h[0x6a] = 1;
        h[0x6b] = 1;
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) | 8);
        ((GpbHeldByte*)(sub + 0x4a))->playerHeld = 1;
        *(u8*)(sub + 0x49) = (u8)(*(u8*)(sub + 0x49) & ~2);
        ObjHits_SetFlags((int)obj, 0x480);
        ObjHits_ClearSourceMask((int)obj, 1);
        ObjHits_EnableObject((int)obj);
        ObjHits_SyncObjectPositionIfDirty((int)obj);
    } else {
        h[0x6a] = (*(u8**)((char*)obj + 0x50))[0x63];
        h[0x6b] = (*(u8**)((char*)obj + 0x50))[0x64];
        ((GpbHeldByte*)(sub + 0x4a))->playerHeld = 0;
        *(u8*)((char*)obj + 0xaf) = (u8)(*(u8*)((char*)obj + 0xaf) & ~8);
        ObjHits_ClearFlags((int)obj, 0x400);
        *(u8*)(sub + 0x49) = (u8)(*(u8*)(sub + 0x49) | 1);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* state-transition: kicks player into mode 2 when sandworm not yet eaten. */
extern u32 GameBit_Get(int);
extern void* Obj_GetPlayerObject(void);
extern void playerAddRemoveMagic(void*, int);
#pragma peephole off
int fn_8019FC84(int *obj, int p2, void *p3) {
    char *p = *(char**)((char*)obj + 0xb8);
    if (*(s8*)(p + 0x74) != 0) return 0;
    if (*(u8*)((char*)p3 + 0x80) == 2) {
        *(u8*)(p + 0x74) = 1;
        playerAddRemoveMagic(Obj_GetPlayerObject(), 2);
    }
    return 0;
}
#pragma peephole reset

/* GameBit-gated byte write. */
#pragma scheduling off
int fn_801A04F4(int p1, int p2, void *p3) {
    if (GameBit_Get(0x4d) != 0) {
        *(u8*)((char*)p3 + 0x90) = 4;
    }
    return 0;
}
#pragma scheduling reset

/* plain forwarder. */
extern void waterSpellStone1Fn_8019b4c8(void);
void cfguardian_update(void) { waterSpellStone1Fn_8019b4c8(); }

/* Drift-recovery: add new fns with v1.0 names. */
extern int* gExpgfxInterface;
extern int fn_801A04F4(int p1, int p2, void* p3);
extern f32 lbl_803E42B8;
extern f32 lbl_803E42C0;
extern f32 lbl_803E4130;
extern f32 lbl_803E416C;
extern void fn_8001CB3C(int* p);
/* ObjLink_DetachChild already declared above as undefined4 ObjLink_DetachChild() */
extern void dll_2E_func06(int* a, int* b, int c);
extern void objfx_spawnHitEmitterAtPos(f32* p, int a, int b, int c, int d);
extern void* Obj_GetPlayerObject(void);
extern f32 fn_80296214(void* p);
/* ObjMsg_AllocQueue already declared as undefined */
extern int fn_8019FC84(int* obj, int p2, void* p3);
extern void Music_Trigger(int a, int b);
extern int ObjHits_GetPriorityHitWithPosition(int* obj, int a, int b, int c, f32* out_x, f32* out_y, f32* out_z);

#pragma scheduling off
#pragma peephole off

int babycloudrunner_getObjectTypeId(void) { return 0; }

void spiritdoorspirit_init(int* obj)
{
    int* state = *(int**)((char*)obj + 0xb8);
    *(s8*)state = 0;
    *(s8*)((char*)obj + 54) = 0;
}

extern f32 lbl_803DBE78;
extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);

#pragma scheduling off
#pragma peephole off
void spiritdoorspirit_update(int *obj) {
    u8 *sub;
    u8 *def;

    sub = *(u8**)((char*)obj + 0xb8);
    def = *(u8**)((char*)obj + 0x4c);
    if (sub[0] == 0) {
        sub[0] = (u8)(GameBit_Get(*(s16*)(def + 0x1e)) == 0);
        if (sub[0] != 0) {
            ObjGroup_AddObject(obj, 0x4e);
        }
        if (*(u8*)((char*)obj + 0x36) != 0) {
            *(u8*)((char*)obj + 0x36) = (u8)(*(u8*)((char*)obj + 0x36) - 1);
        }
    } else {
        fn_80098B18((int)obj, lbl_803DBE78, 5, 0, 0, 0);
        sub[0] = (u8)(GameBit_Get(*(s16*)(def + 0x1e)) == 0);
        if (sub[0] == 0) {
            ObjGroup_RemoveObject(obj, 0x4e);
        }
        if (*(u8*)((char*)obj + 0x36) < 0xff) {
            *(u8*)((char*)obj + 0x36) = (u8)(*(u8*)((char*)obj + 0x36) + 1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

int babycloudrunner_setScale(int* obj)
{
    int* state = *(int**)((char*)obj + 0xb8);
    return !(*(u8*)((char*)state + 556) & 1);
}

void cfperch_init(int* obj)
{
    *(int*)((char*)obj + 244) = 1;
    *(void**)((char*)obj + 188) = (void*)fn_801A04F4;
}

void cfmaincrystal_free(int* obj)
{
    ((void(*)(int*))((void**)*gExpgfxInterface)[5])(obj);
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
    int* state = *(int**)((char*)obj + 0xb8);
    state[0] = 0;
    state[1] = 0;
    ObjHits_EnableObject(obj);
    *(u8*)((char*)obj + 54) = 0x80;
}

extern f32 lbl_803E42A0;
extern f32 lbl_803E42A4;
extern f32 lbl_80322C38[];
extern f32 lbl_803DBE58;
extern f32 lbl_803DBE5C;
extern void *fn_8001CC9C(int a, int b, int c, int d);
extern void lightDistAttenFn_8001dc38(void *light, f32 a, f32 b);
extern void lightVecFn_8001dd88(void *light, f32 x, f32 y, f32 z);
extern void Obj_TransformLocalVectorByWorldMatrix(int *obj, void *out, void *in);
extern void voxmaps_traceScaledVectorEnd(f32 *dst, void *posA, f32 *dir, f32 factor);
extern f32 PSVECDistance(void *a, void *b);
extern void PSVECScale(void *in, void *out, f32 scale);
extern void getAmbientColor(int mode, u8 *r, u8 *g, u8 *b);
extern void modelLightStruct_setColorsA8AC(void *p, int r, int g, int b, int a);

#pragma scheduling off
#pragma peephole off
void gcrobotlightbea_update(int *obj) {
    void **sub;
    f32 vec[3];
    f32 vec2[3];
    u8 b_byte, g_byte, r_byte;

    sub = *(void***)((char*)obj + 0xb8);
    if (sub[0] == NULL) {
        sub[0] = fn_8001CC9C(0xfa, 0xfa, 0xfa, 1);
        if (sub[0] != NULL) {
            lightDistAttenFn_8001dc38(sub[0], lbl_803DBE58, lbl_803E42A0 + lbl_803DBE58);
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
    if (sub[0] != NULL) {
        modelLightStruct_setColorsA8AC(sub[0],
            (s32)(lbl_803E42A4 * (f32)(u32)r_byte),
            (s32)(lbl_803E42A4 * (f32)(u32)g_byte),
            (s32)(lbl_803E42A4 * (f32)(u32)b_byte),
            0xff);
        lightVecFn_8001dd88(sub[0], vec2[0], vec2[1], vec2[2]);
    }
}
#pragma peephole reset
#pragma scheduling reset

void spiritdoorspirit_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* state = *(int**)((char*)obj + 0xb8);
    if ((s32)visible != 0) {
        if (*(u8*)state != 0) {
            ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E42B8);
        }
    }
}

void cfprisonguard_hitDetect(int* obj)
{
    int* state = *(int**)((char*)obj + 0xb8);
    if (ObjHits_GetPriorityHit(obj, NULL, NULL, NULL) == 19) {
        *(s8*)((char*)state + 55) = 7;
    }
}

void gcrobotlightbea_free(int* obj)
{
    int* state = *(int**)((char*)obj + 0xb8);
    if (*(void**)state != NULL) {
        fn_8001CB3C(state);
    }
    if (*(int**)((char*)obj + 196) != NULL) {
        ObjLink_DetachChild(*(int**)((char*)obj + 196), obj);
    }
}

void cfguardian_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* state = *(int**)((char*)obj + 0xb8);
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

extern int cfprisoncage_SeqFn(int* obj, int p2, u8* p3);
extern int *gObjectTriggerInterface;
extern f32 lbl_803E42B4;
#pragma scheduling off
#pragma peephole off
void cfprisoncage_init(int *obj, u8 *def) {
    ObjMsg_AllocQueue(obj, 1);
    *(s16 *)obj = (s16)((s32)def[0x1a] << 8);
    *(int *)((char *)obj + 0xf4) = 1;
    *(int *)((char *)obj + 0xbc) = (int)cfprisoncage_SeqFn;
    if (*(s16 *)((char *)obj + 0x46) == 296) {
        if (GameBit_Get(*(s16 *)((char *)def + 0x18)) != 0) {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E42B4, 0);
        } else {
            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E42B4, 0);
        }
    } else {
        if (GameBit_Get(*(s16 *)((char *)def + 0x18)) != 0) {
            ((void (*)(int *, int))((int *)*gObjectTriggerInterface)[0x54/4])(obj, 60);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

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
    char* state = *(char**)((char*)obj + 0xb8);
    if (p2 == 0) {
        int i;
        for (i = 0; i < 6; i++) {
            int* sub = *(int**)(state + 1676);
            if (sub != NULL) {
                Obj_FreeObject(sub);
            }
            state += 4;
        }
    }
}

void gunpowderbarrel_setScale(int* obj, f32* params)
{
    int* state = *(int**)((char*)obj + 0xb8);
    if (*(u8*)((char*)state + 21) != 0) return;
    if (*(u8*)((char*)state + 23) != 0) return;
    *(f32*)((char*)state + 36) = *(f32*)((char*)state + 36) + params[1];
    *(f32*)((char*)state + 32) = *(f32*)((char*)state + 32) + params[0];
    *(f32*)((char*)state + 40) = *(f32*)((char*)state + 40) + params[2];
    *(u8*)((char*)state + 73) = (u8)(*(u8*)((char*)state + 73) | 1);
}

int gunpowderbarrel_canBeGrabbed(int* obj)
{
    int* state = *(int**)((char*)obj + 0xb8);
    int result = 0;
    if (*(u8*)((char*)state + 21) == 0 &&
        *(f32*)((char*)state + 24) == lbl_803E42C0 &&
        ((int(*)(int*))(*(*(void****)&lbl_803DCAC0))[5])(state) == 0) {
        result = 1;
    }
    return result;
}

void cfprisonuncle_init(int* obj)
{
    int* state;
    ObjMsg_AllocQueue(obj, 1);
    *(void**)((char*)obj + 188) = (void*)fn_8019FC84;
    state = *(int**)((char*)obj + 0xb8);
    *(int*)((char*)state + 100) = 464;
    *(int*)((char*)state + 104) = 465;
    *(s16*)((char*)state + 112) = 0;
    *(s8*)((char*)state + 116) = 0;
    if ((u32)GameBit_Get(77) != 0u) {
        GameBit_Set(80, 1);
    }
}

#pragma peephole reset
#pragma scheduling reset

/* copy 3 floats within same struct */
void cfguardian_hitDetect(int *obj) {
    *(f32*)((char*)obj + 0x80) = *(f32*)((char*)obj + 0xc);
    *(f32*)((char*)obj + 0x84) = *(f32*)((char*)obj + 0x10);
    *(f32*)((char*)obj + 0x88) = *(f32*)((char*)obj + 0x14);
}

extern int *gRomCurveInterface;
#pragma scheduling off
#pragma peephole off
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

    found = (*(int (***)(f32, f32, f32, int *, int, int))gRomCurveInterface)[5](
        *(f32 *)((char *)obj + 0xc),
        *(f32 *)((char *)obj + 0x10),
        *(f32 *)((char *)obj + 0x14),
        local, 2, p2);

    if (found > -1) {
        result = (int *)(*(int *(***)(void))gRomCurveInterface)[7]();
        if (outVec != NULL) {
            *(f32 *)((char *)outVec + 0) = *(f32 *)((char *)result + 8);
            *(f32 *)((char *)outVec + 4) = *(f32 *)((char *)result + 12);
            *(f32 *)((char *)outVec + 8) = *(f32 *)((char *)result + 16);
        }
    }
    return result;
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_8019D9F0(int *obj);
extern int *lbl_803DDB10;
extern u8 framesThisStep;
#pragma peephole off
#pragma scheduling off
void cfmaincrystal_update(int *obj) {
    uint payload;
    uint msgType;
    uint srcObjId;
    s8 t;
    t = ((s8 *)*(int *)((char *)obj + 0x4c))[0x19];
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
int cfpowerbase_SeqFn(int p1, int unused, int p3)
{
  extern int ObjMsg_Pop(int, int *, int *, int *);
  int sub = *(int *)(p1 + 0xb8);
  int msgArg;
  int msgType;
  int msgFlag = 0;
  int i;

  while (ObjMsg_Pop(p1, &msgType, &msgArg, &msgFlag) != 0) {
    switch (msgType) {
      case 0x110001:
        if (*(s16 *)(sub + 0) == 84 && *(s16 *)(p3 + 0x58) > 175) {
          ObjMsg_SendToObject((void *)msgArg, 0x110001, p1, 0);
        }
        break;
      case 0x110002:
        if (*(s16 *)(sub + 0) == 85 && *(s16 *)(p3 + 0x58) > 175) {
          ObjMsg_SendToObject((void *)msgArg, 0x110002, p1, 0);
        }
        break;
      case 0x110003:
        if (*(s16 *)(sub + 0) == 86 && *(s16 *)(p3 + 0x58) > 175) {
          ObjMsg_SendToObject((void *)msgArg, 0x110003, p1, 0);
        }
        break;
      case 0xA0005:
        GameBit_Set(*(s16 *)(sub + 0), 1);
        break;
    }
  }

  for (i = 0; i < (s32)*(u8 *)(p3 + 0x8b); i++) {
    if ((s32)*(u8 *)(p3 + 0x81 + i) == 1) {
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
    if (*(int *)((char *)obj + 0xf4) != 0) {
        if (GameBit_Get(0x50) == 0) {
            ((void (*)(int, int *, int))((int **)*gObjectTriggerInterface)[0x12])(0, obj, -1);
        }
    }
    *(int *)((char *)obj + 0xf4) = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cfmaincrystal_init(int *obj, u8 *def) {
    u8 *state = *(u8 **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s32)*(s8 *)((char *)def + 0x18) << 8);
    if (*(s8 *)((char *)def + 0x19) == 0) {
        state[0x15c] = 0x28;
        state[0x15d] = 0;
        state[0x15e] = 0;
        state[0x15f] = 0x46;
        *(u8 *)((char *)obj + 0xad) = 1;
        *(int *)((char *)state + 0x158) = 0;
    }
    ObjMsg_AllocQueue(obj, 2);
}
#pragma peephole reset
#pragma scheduling reset

extern void* Obj_GetPlayerObject(void);
extern void mathFn_80021ac8(s16* rotIn, f32* outVec);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void saveGame_saveObjectPos(int obj);
extern int barrelgener_getLinkId(int barrel);
extern f32 lbl_803E42C0;
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
 * via mathFn_80021ac8, sets thrown/inflight flags, plays sfx 0xd3. When
 * state[0x48] bit 0x40 is set, looks up the linked barrel by data[0x1a]
 * (or the nearest one if 0), temporarily moves obj to that barrel's
 * position so saveGame_saveObjectPos latches the target slot, then
 * restores. */
#pragma scheduling off
#pragma peephole off
void gunpowderbarrel_launchAtTarget(int obj, u8 flag) {
    u8* state = *(u8**)(obj + 0xb8);
    u8* playerState;
    s16 stk[8];
    f32 fz;
    int target;
    f32 sx, sy, sz;

    playerState = *(u8**)((u8*)Obj_GetPlayerObject() + 0xb8);
    *(f32*)(state + 0x20) = lbl_803E42C0;
    if (flag != 0) {
        *(f32*)(state + 0x24) = lbl_803E42C8 * *(f32*)(playerState + 0x298) + lbl_803E42C4;
        *(f32*)(state + 0x28) = lbl_803E42D0 * *(f32*)(playerState + 0x298) + lbl_803E42CC;
    } else {
        *(f32*)(state + 0x24) = lbl_803E42D4;
        *(f32*)(state + 0x28) = lbl_803E42D8;
    }
    fz = lbl_803E42C0;
    *(f32*)((u8*)stk + 0xc) = fz;
    *(f32*)((u8*)stk + 0x10) = fz;
    *(f32*)((u8*)stk + 0x14) = fz;
    *(f32*)((u8*)stk + 0x8) = lbl_803E42DC;
    stk[2] = 0;
    stk[1] = 0;
    stk[0] = *(s16*)(state + 0x50);
    mathFn_80021ac8(stk, (f32*)(state + 0x20));
    state[0x49] = (u8)(state[0x49] | 1);
    Sfx_PlayFromObject(obj, SFXsk_baptr6_c);
    state[0x49] = (u8)(state[0x49] | 2);
    if ((state[0x48] & 0x40) != 0) {
        u8* params = *(u8**)(obj + 0x4c);
        target = 0;
        if (*(s16*)(params + 0x1a) != 0) {
            int count;
            int* barrels = (int*)ObjGroup_GetObjects(0x3a, &count);
            int i;
            int* p = barrels;
            for (i = 0; i < count; i++) {
                if (*(s16*)(params + 0x1a) == barrelgener_getLinkId(*p)) {
                    target = barrels[i];
                    break;
                }
                p++;
            }
        } else {
            target = ObjGroup_FindNearestObject(0x3a, obj, (f32*)0);
        }
        if (target != 0) {
            sx = *(f32*)(obj + 0xc);
            sy = *(f32*)(obj + 0x10);
            sz = *(f32*)(obj + 0x14);
            *(f32*)(obj + 0xc) = *(f32*)(target + 0xc);
            *(f32*)(obj + 0x10) = *(f32*)(target + 0x10);
            *(f32*)(obj + 0x14) = *(f32*)(target + 0x14);
            saveGame_saveObjectPos(obj);
            *(f32*)(obj + 0xc) = sx;
            *(f32*)(obj + 0x10) = sy;
            *(f32*)(obj + 0x14) = sz;
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
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
int fn_8019E3F4(int* obj)
{
    f32 speed;
    u8* sub = *(u8**)((char*)obj + 0xb8);
    if (*(s16*)((char*)obj + 0xa0) != 5 && *(s16*)((char*)obj + 0xa0) != 0xd) {
        ObjAnim_SetCurrentMove((int)obj, 0xd, *(f32*)((char*)obj + 0x98), 0);
    }
    if (*(s16*)((char*)obj + 0xa0) == 5 && *(f32*)((char*)obj + 0x28) > lbl_803E422C) {
        ObjAnim_SetCurrentMove((int)obj, 0xd, *(f32*)((char*)obj + 0x98), 0);
    }
    if (*(s16*)((char*)obj + 0xa0) == 0xd && *(f32*)((char*)obj + 0x28) < lbl_803E4218) {
        ObjAnim_SetCurrentMove((int)obj, 5, *(f32*)((char*)obj + 0x98), 0);
    }
    speed = *(f32*)((char*)obj + 0x28) * lbl_803DBE4C + lbl_803E4230;
    speed *= lbl_803E4234;
    if (speed < lbl_803E4218) {
        speed = lbl_803E4218;
    }
    if (speed > lbl_803E4234) {
        speed = lbl_803E4234;
    }
    if (*(s16*)((char*)obj + 0xa0) == 0xd) {
        if (*(f32*)((char*)obj + 0x98) > lbl_803E4234) {
            if (!((WormSpitByte*)(sub + 0x244))->spitLatch) {
                Sfx_PlayFromObject((int)obj, SFXand_spitout);
                ((WormSpitByte*)(sub + 0x244))->spitLatch = 1;
            }
        } else {
            ((WormSpitByte*)(sub + 0x244))->spitLatch = 0;
        }
    }
    ((int(*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)((int)obj, speed, timeDelta, 0);
    return 1;
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

extern int objUpdateOpacity(int sub);
extern f32 lbl_803E4288;

/* EN v1.0 0x8019FCF4  size: 484b  cfprisonuncle_render: render the uncle and/or
 * his held model depending on the rescue gamebits, opacity and visibility;
 * when path-following, snap the held model to the path point first. */
#pragma scheduling off
#pragma peephole off
void cfprisonuncle_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* sub = *(int**)((char*)obj + 0xb8);
    if (GameBit_Get(0x50) != 0) {
        if (*(void**)sub != NULL && objUpdateOpacity(*sub) != 0) {
            ((void(*)(int,int,int,int,int,f32))objRenderFn_8003b8f4)(*sub, p2, p3, p4, p5, lbl_803E4288);
        }
    } else if (GameBit_Get(0x4d) != 0 && visible != 0) {
        ((void(*)(int*,int,int,int,int,f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4288);
        if (*(void**)sub != NULL && objUpdateOpacity(*sub) != 0) {
            ((void(*)(int,int,int,int,int,f32))objRenderFn_8003b8f4)(*sub, p2, p3, p4, p5, lbl_803E4288);
        }
    } else if (sub != NULL && *(void**)sub != NULL) {
        if (*(s8*)((char*)sub + 0x73) == 0) {
            if (visible != 0) {
                if (objUpdateOpacity(*sub) != 0) {
                    ((void(*)(int,int,int,int,int,f32))objRenderFn_8003b8f4)(*sub, p2, p3, p4, p5, lbl_803E4288);
                    ObjPath_GetPointWorldPosition(*sub, 0, (char*)obj + 0xc, (char*)obj + 0x10, (char*)obj + 0x14, 0);
                }
                ((void(*)(int*,int,int,int,int,f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4288);
            }
        } else {
            if (objUpdateOpacity(*sub) != 0) {
                ((void(*)(int,int,int,int,int,f32))objRenderFn_8003b8f4)(*sub, p2, p3, p4, p5, lbl_803E4288);
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
extern f32  lbl_803E4110;
extern f32  lbl_803E4124;
extern f32  lbl_803E4128;

/* EN v1.0 0x8019B1D8  size: 544b  fn_8019B1D8: steer the object toward the
 * target: scale its velocity along the normalized delta, blend the yaw by
 * speed over distance, move it and keep the chase move playing. Returns 1
 * when already within the closing threshold. */
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
    dx = *(f32*)((char*)target + 0xc) - *(f32*)((char*)obj + 0xc);
    dy = *(f32*)((char*)target + 0x10) - *(f32*)((char*)obj + 0x10);
    dz = *(f32*)((char*)target + 0x14) - *(f32*)((char*)obj + 0x14);
    dist = sqrtf(dz * dz + (dx * dx + dy * dy));
    if (dist < lbl_803E4124 * speed) {
        return 1;
    }
    normalize(&dx, &dy, &dz);
    *(f32*)((char*)obj + 0x24) = timeDelta * (dx * speed);
    *(f32*)((char*)obj + 0x28) = timeDelta * (dy * speed);
    *(f32*)((char*)obj + 0x2c) = timeDelta * (dz * speed);
    d = (*(s16*)target + 0x8000) - (u16)*(s16*)obj;
    if (d > 0x8000) {
        d = d - 0xffff;
    }
    if (d < -0x8000) {
        d = d + 0xffff;
    }
    *(s16*)obj = (f32)*(s16*)obj + ((lbl_803E4128 + (f32)d) * (speed * timeDelta)) / dist;
    objMove((int)obj, *(f32*)((char*)obj + 0x24), *(f32*)((char*)obj + 0x28), *(f32*)((char*)obj + 0x2c));
    if (*(s16*)((char*)obj + 0xa0) != 0x1a) {
        ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
    }
    ((int(*)(int*, f32, int))ObjAnim_SampleRootCurvePhase)(obj, speed, p4);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int seqStreamLookupFn_8007fff8(void *table, int count, int key);
extern u8  lbl_80322A48[];
extern u8  lbl_80322A68[];
extern f32 lbl_803E41C8;
extern f32 lbl_803E41CC;
extern f32 lbl_803E4168;
extern f32 lbl_803E416C;

typedef struct {
    int i0;
    f32 f4;
    f32 f8;
    f32 fc;
    u8  b10;
    u8  b11;
    u8  pad12[6];
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
    u8  _f0 : 1;
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
    WindLiftSub* sub = *(WindLiftSub**)((char*)obj + 0xb8);
    sub->seqId = *(s16*)(def + 0x1e);
    sub->duration = seqStreamLookupFn_8007fff8(lbl_80322A48, 4, sub->seqId);
    sub->gamebit = seqStreamLookupFn_8007fff8(lbl_80322A68, 3, sub->seqId);
    if (sub->gamebit == 0) {
        sub->gamebit = -1;
    }
    if (sub->duration == 0) {
        sub->duration = 100;
    }
    sub->delay = *(s16*)(def + 0x1c);
    sub->timer = 0;
    if (*(s8*)(def + 0x19) != 0) {
        sub->liftHeight = lbl_803E41C8 * (f32)*(s8*)(def + 0x19);
    } else {
        sub->liftHeight = lbl_803E41CC;
    }
    *(f32*)((char*)obj + 8) = (*(f32*)(*(char**)((char*)obj + 0x50) + 4) * sub->liftHeight) / lbl_803E41CC;
    if (GameBit_Get(0x57) != 0 || sub->duration >= 0xa) {
        sub->timer = 0x3c;
    }
    sub->active = 1;
    if (sub->gamebit != -1) {
        if (GameBit_Get(sub->gamebit) != 0) {
            sub->timer = 0x3c;
        } else {
            sub->active = 0;
            *(u8*)((char*)obj + 0x36) = 0;
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

extern f32 lbl_803E42C0;
extern f32 lbl_803E42DC;
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
    dx = *(f32*)(near + 0xc) - *(f32*)((char*)obj + 0xc);
    dy2 = *(f32*)(near + 0x10) - *(f32*)((char*)obj + 0x10);
    scale = 0.0f;
    if (dy2 > scale) {
        return;
    }
    dz = *(f32*)(near + 0x14) - *(f32*)((char*)obj + 0x14);
    rate = (dy2 != scale) ? *(f32*)((char*)obj + 0x28) / dy2 : scale;
    if (rate >= lbl_803E42DC) {
        Sfx_PlayFromObject((int)obj, 0xd2);
        rate = lbl_803E42DC;
        *(f32*)((char*)obj + 0x28) = dy2;
        *(f32*)(near + 0xc) += lbl_803E42E8;
        *(f32*)(near + 0x2c) += lbl_803E42E8;
        if (*(f32*)(near + 0x2c) > lbl_803E42EC) {
            *(f32*)(near + 0xc) -= *(f32*)(near + 0x2c);
            *(f32*)(near + 0x2c) = 0.0f;
        }
        *(s16*)((char*)obj + 2) = 0;
        *(s16*)((char*)obj + 4) = 0;
        a = 0;
        b = 0;
    }
    *(f32*)((char*)obj + 0x24) = dx * rate;
    *(f32*)((char*)obj + 0x2c) = dz * rate;
    v = a;
    if (v != 0) {
        f32 t;
        if (v == 1) {
            t = (lbl_803E42F0 - (f32)(u16)*(s16*)((char*)obj + 2)) * rate;
        } else {
            t = (f32)(u16)*(s16*)((char*)obj + 2) * (rate * (f32)v);
        }
        *(s16*)((char*)obj + 2) = (f32)*(s16*)((char*)obj + 2) + t;
    }
    w = b;
    if (w != 0) {
        f32 t;
        if (w == 1) {
            t = 0.0f;
        } else {
            t = (f32)(u16)*(s16*)((char*)obj + 4) * (rate * (f32)w);
        }
        *(s16*)((char*)obj + 4) = (f32)*(s16*)((char*)obj + 4) + t;
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
int babycloudrunner_SeqFn(int* obj, int p2, u8* p3)
{
    s8 inRange;
    s8 i;
    int yaw;
    char* player;
    f32 dx;
    f32 dz;
    f32 distSq;
    u8* def = *(u8**)((char*)obj + 0x4c);
    u8* sub = *(u8**)((char*)obj + 0xb8);
    if (*(s16*)((char*)obj + 0xb4) == 4) {
        return 0;
    }
    p3[0x56] = 0;
    player = (char*)Obj_GetPlayerObject();
    dx = *(f32*)(player + 0xc) - *(f32*)(def + 8);
    dz = *(f32*)(player + 0x14) - *(f32*)(def + 0x10);
    distSq = dx * dx + dz * dz;
    if (distSq < (f32)((*(s16*)(def + 0x1a) / 2) * (*(s16*)(def + 0x1a) / 2))) {
        inRange = 1;
    } else {
        inRange = 0;
    }
    *(u8*)((char*)obj + 0xaf) &= ~0x8;
    {
        u8* sub2 = *(u8**)((char*)obj + 0xb8);
        char* pp = (char*)Obj_GetPlayerObject();
        u8* def2 = *(u8**)((char*)obj + 0x4c);
        int found = 0;
        if (Vec_distance(pp + 0x18, (char*)obj + 0x18) < (f32)*(s16*)(def2 + 0x1a)
            && *(int*)(sub2 + 0x230) == 3
            && (*(u16*)((char*)obj + 0xb0) & 0x1000) == 0) {
            found = 1;
        }
        if (found != 0) {
            *(u8*)((char*)obj + 0xaf) &= ~0x10;
        } else {
            *(u8*)((char*)obj + 0xaf) |= 0x10;
        }
    }
    if (inRange == 0 && *(int*)(sub + 0x230) == 2) {
        f32 radius = (f32)*(s16*)(def + 0x18);
        if ((void*)ObjGroup_FindNearestObject(3, obj, &radius) != NULL) {
            inRange = 1;
        }
    }
    for (i = 0; i < *(u8*)(p3 + 0x8b); i++) {
        int idx = i + 0x81;
        if (p3[idx] == 1) {
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
        }
    }
    *(int*)(sub + 0xc4) = 0;
    switch (*(int*)(sub + 0xc4)) {
    case 10:
    case 11:
        if (*(void**)(sub + 0x114) != NULL) {
            *(f32*)(sub + 0xac) *= lbl_803E4248;
            *(f32*)(*(char**)(sub + 0x114) + 8) = *(f32*)(sub + 0xac);
        }
        *(int*)(sub + 0xc4) = 0xb;
        if (Vec_distance((char*)obj + 0x18, player + 0x18) < (f32)*(s16*)(def + 0x1a)
            && (*(u8*)((char*)obj + 0xaf) & 1) != 0) {
            *(int*)(sub + 0xc4) = 7;
            return 4;
        }
        break;
    case 0:
    case 8:
        *(s16*)(p3 + 0x6e) &= ~0x2;
        yaw = Obj_GetYawDeltaToObject((int)obj, (int)player, 0);
        fn_8003ADC4(obj, (int*)player, (char*)sub + 0x3c, 0x28, 0, 3);
        *(s16*)obj += (s16)yaw / 8;
        if (inRange != 0) {
            *(u8*)(p3 + 0x90) |= 4;
        } else {
            *(u8*)(p3 + 0x90) = 8;
        }
        break;
    case 5:
        *(s16*)(p3 + 0x6e) &= ~0x2;
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
int cfprisonguard_SeqFn(int* obj, int p2, u8* p3)
{
    char* player;
    u8* sub = *(u8**)((char*)obj + 0xb8);
    s8 gb50;
    s8 gb48;
    s8 moved;
    f32 dist;
    int msgB;
    int msgA;
    int payload = 0;
    u8* def = *(u8**)((char*)obj + 0x4c);
    switch (p3[0x80]) {
    case 0x29:
        *(f32*)(sub + 0x30) = lbl_803E4260;
        break;
    case 4:
        *(s8*)(sub + 0x37) = 6;
        return 0;
    case 5:
        *(f32*)(sub + 0x30) = lbl_803E4264 * (f32)framesThisStep + *(f32*)(sub + 0x30);
        break;
    }
    if (*(s16*)((char*)obj + 0xb4) < 0) {
        return 0;
    }
    ObjHits_EnableObject(obj);
    gb50 = GameBit_Get(0x50);
    gb48 = GameBit_Get(0x48);
    if ((*(u8*)(sub + 0x38) & 2) != 0 && GameBit_Get(0x4d) != 0) {
        *(u8*)(sub + 0x38) &= ~0x2;
        return 4;
    }
    if (gb50 != 0) {
        return 4;
    }
    if (gb50 != 0 || *(s8*)(sub + 0x37) == 5) {
        *(s8*)(sub + 0x37) = 5;
        return 0;
    }
    moved = 0;
    player = (char*)Obj_GetPlayerObject();
    switch (*(s8*)(sub + 0x37)) {
    case 0:
        fn_8003B228(obj, sub);
        dist = Vec_distance((char*)obj + 0x18, player + 0x18);
        if (gb48 == 0) {
            if (dist < (f32)*(s16*)(def + 0x1a)
                || waterfx_consumePendingImpactNearPoint((f32*)((char*)obj + 0xc), lbl_803E4268) != 0) {
                if (objGetAnimState80A(player) != 0x40) {
                    moved = 1;
                    *(s8*)(sub + 0x37) = 4;
                } else {
                    *(u8*)((char*)obj + 0xaf) |= 8;
                    *(s8*)(sub + 0x37) = 5;
                    *(s16*)(sub + 0x34) = 0x14;
                    ((void (*)(int, int*, int))((int*)*gObjectTriggerInterface)[0x48 / 4])(2, obj, -1);
                    return 4;
                }
            }
        }
        break;
    case 2:
        if ((*(s16*)(sub + 0x34) -= framesThisStep) <= 0) {
            *(s8*)(sub + 0x37) = 1;
        }
        fn_8003B228(obj, sub);
        break;
    case 1:
        dist = Vec_distance((char*)obj + 0x18, player + 0x18);
        if (gb48 == 0) {
            if (dist < (f32)*(s16*)(def + 0x1a)) {
                if (objGetAnimState80A(player) != 0x40) {
                    moved = 1;
                    *(s8*)(sub + 0x37) = 4;
                } else {
                    *(s8*)(sub + 0x37) = 2;
                }
            }
        }
        break;
    case 3:
        if ((*(s16*)(sub + 0x34) -= framesThisStep) <= 0) {
            *(s8*)(sub + 0x37) = 0;
        }
        break;
    case 5:
        return 0;
    case 6:
        return 0;
    case 7:
        moved = 1;
        *(s8*)(sub + 0x37) = 4;
        break;
    }
    if (*(s16*)((char*)obj + 0xa0) == 0x103 || *(s16*)((char*)obj + 0xa0) == 0x2e) {
        Sfx_PlayFromObject((int)obj, SFXsk_doggydig11);
    } else {
        Sfx_StopObjectChannel((int)obj, 0x10);
    }
    if (gb50 != 0 && *(s8*)(sub + 0x36) == 0) {
        moved = 1;
    }
    if (moved != 0) {
        return 4;
    }
    *(s8*)(sub + 0x36) = gb50;
    p3[0x56] = 0;
    while (ObjMsg_Pop(obj, &msgA, &msgB, &payload) != 0) {
    }
    if (p3[0x80] == 1) {
        getLActions(obj, obj, 0x18, 0, 0, 0);
        p3[0x80] = 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
