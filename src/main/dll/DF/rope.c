#include "ghidra_import.h"
#include "main/dll/DF/rope.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006920();
extern int FUN_80006a10();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017544();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017580();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017594();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern uint FUN_80017690();
extern uint FUN_80017720();
extern uint FUN_80017730();
extern uint FUN_80017760();
extern undefined4 FUN_80017954();
extern undefined4 FUN_80017958();
extern int FUN_80017a54();
extern undefined4 FUN_80017a88();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 FUN_80035b84();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjMsg_Pop();
extern undefined4 FUN_8003b818();
extern int FUN_8005b398();
extern undefined4 FUN_8005fe14();
extern int FUN_800632f4();
extern undefined4 dimbosstonsil_render();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de810;
extern undefined4 DAT_803de814;
extern f64 DOUBLE_803e5990;
extern f64 DOUBLE_803e59f0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de818;
extern f32 FLOAT_803de81c;
extern f32 FLOAT_803de820;
extern f32 FLOAT_803de824;
extern f32 FLOAT_803e5928;
extern f32 FLOAT_803e5934;
extern f32 FLOAT_803e5938;
extern f32 FLOAT_803e5964;
extern f32 FLOAT_803e5968;
extern f32 FLOAT_803e596c;
extern f32 FLOAT_803e5970;
extern f32 FLOAT_803e5974;
extern f32 FLOAT_803e5978;
extern f32 FLOAT_803e5984;
extern f32 FLOAT_803e5988;
extern f32 FLOAT_803e5998;
extern f32 FLOAT_803e599c;
extern f32 FLOAT_803e59a0;
extern f32 FLOAT_803e59a4;
extern f32 FLOAT_803e59a8;
extern f32 FLOAT_803e59ac;
extern f32 FLOAT_803e59b0;
extern f32 FLOAT_803e59b4;
extern f32 FLOAT_803e59b8;
extern f32 FLOAT_803e59bc;
extern f32 FLOAT_803e59c0;
extern f32 FLOAT_803e59c4;
extern f32 FLOAT_803e59c8;
extern f32 FLOAT_803e59d0;
extern f32 FLOAT_803e59d4;
extern f32 FLOAT_803e59d8;
extern f32 FLOAT_803e59dc;
extern f32 FLOAT_803e59e0;
extern f32 FLOAT_803e59e4;
extern f32 FLOAT_803e59e8;
extern f32 FLOAT_803e59f8;
extern f32 FLOAT_803e59fc;
extern f32 FLOAT_803e5a00;
extern f32 FLOAT_803e5a04;
extern f32 FLOAT_803e5a08;
extern f32 FLOAT_803e5a0c;
extern f32 FLOAT_803e5a10;
extern f32 FLOAT_803e5a14;
extern f32 FLOAT_803e5a18;

/*
 * --INFO--
 *
 * Function: FUN_801bf048
 * EN v1.0 Address: 0x801BF048
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801BF224
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bf048(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801bf04c
 * EN v1.0 Address: 0x801BF04C
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x801BF454
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bf04c(int param_1,int param_2)
{
  short sVar1;
  uint uVar2;
  float *pfVar3;
  double dVar4;
  
  pfVar3 = *(float **)(param_2 + 0x40c);
  dVar4 = (double)(pfVar3[3] - *(float *)(param_1 + 0x10));
  *(short *)(pfVar3 + 5) = *(short *)(pfVar3 + 5) + 0x400;
  uVar2 = FUN_80017720();
  *pfVar3 = FLOAT_803dc074 *
            ((float)(dVar4 + (double)((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                             DOUBLE_803e5990) / FLOAT_803e5998)) / FLOAT_803e599c -
            pfVar3[2]) + *pfVar3;
  *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + *pfVar3;
  *(short *)(param_1 + 2) = (short)(int)(FLOAT_803e59a0 * *pfVar3);
  dVar4 = DOUBLE_803e5990;
  sVar1 = -*(short *)(param_1 + 4);
  if (0x8000 < sVar1) {
    sVar1 = sVar1 + 1;
  }
  if (sVar1 < -0x8000) {
    sVar1 = sVar1 + -1;
  }
  uVar2 = (uint)sVar1;
  pfVar3[1] = pfVar3[1] +
              (float)((double)CONCAT44(0x43300000,
                                       (((int)uVar2 >> 4) +
                                       (uint)((int)uVar2 < 0 && (uVar2 & 0xf) != 0)) *
                                       (uint)DAT_803dc070 ^ 0x80000000) - DOUBLE_803e5990);
  *(short *)(param_1 + 4) =
       (short)(int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 4) ^ 0x80000000) -
                           dVar4) + pfVar3[1]);
  *pfVar3 = *pfVar3 / FLOAT_803e59a4;
  pfVar3[1] = pfVar3[1] / FLOAT_803e59a8;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bf1f4
 * EN v1.0 Address: 0x801BF1F4
 * EN v1.0 Size: 660b
 * EN v1.1 Address: 0x801BF5FC
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bf1f4(ushort *param_1,int param_2)
{
  float fVar1;
  ushort uVar3;
  short sVar4;
  uint uVar2;
  int iVar5;
  char cVar6;
  float *pfVar7;
  int iVar8;
  
  iVar8 = *(int *)(param_2 + 0x40c);
  pfVar7 = *(float **)(param_2 + 0x3dc);
  if ((*(ushort *)(param_2 + 0x400) & 8) == 0) {
    FUN_80017a98();
    uVar2 = FUN_80017730();
    iVar8 = (uVar2 & 0xffff) - (uint)*param_1;
    if (0x8000 < iVar8) {
      iVar8 = iVar8 + -0xffff;
    }
    if (iVar8 < -0x8000) {
      iVar8 = iVar8 + 0xffff;
    }
    iVar8 = iVar8 * (uint)DAT_803dc070;
    *param_1 = *param_1 +
               ((short)((ulonglong)((longlong)iVar8 * 0x55555556) >> 0x20) -
               ((short)((short)(iVar8 / 0x30000) + (short)(iVar8 >> 0x1f)) >> 0xf));
  }
  else {
    iVar5 = FUN_80006a10((double)*(float *)(iVar8 + 0x10),pfVar7);
    if (((iVar5 != 0) || (pfVar7[4] != 0.0)) &&
       (cVar6 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar7), cVar6 != '\0')) {
      *(ushort *)(param_2 + 0x400) = *(ushort *)(param_2 + 0x400) & 0xfff7;
    }
    iVar5 = FUN_80017730();
    uVar3 = (short)iVar5 + 0x8000;
    sVar4 = uVar3 - *param_1;
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    *param_1 = uVar3;
    iVar5 = (int)sVar4;
    *(float *)(iVar8 + 4) =
         *(float *)(iVar8 + 4) +
         (float)((double)CONCAT44(0x43300000,iVar5 >> 4 ^ 0x80000000) - DOUBLE_803e5990);
    if (*(float *)(iVar8 + 0x10) < FLOAT_803e59ac) {
      *(float *)(iVar8 + 0x10) = *(float *)(iVar8 + 0x10) + FLOAT_803e59b0;
    }
    iVar5 = iVar5 / 0xb6 + (iVar5 >> 0x1f);
    uVar2 = iVar5 - (iVar5 >> 0x1f);
    if ((int)uVar2 < 0) {
      uVar2 = -uVar2;
    }
    fVar1 = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5990) *
            FLOAT_803e596c;
    if (FLOAT_803e5988 < fVar1) {
      *(float *)(iVar8 + 0x10) = *(float *)(iVar8 + 0x10) / fVar1;
      *(float *)(iVar8 + 8) = *(float *)(iVar8 + 8) + FLOAT_803e59b4;
    }
    if (FLOAT_803e5970 < *(float *)(iVar8 + 8)) {
      *(float *)(iVar8 + 8) = *(float *)(iVar8 + 8) / FLOAT_803e59a8;
    }
    *(float *)(param_1 + 6) = pfVar7[0x1a];
    *(float *)(param_1 + 10) = pfVar7[0x1c];
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bf488
 * EN v1.0 Address: 0x801BF488
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x801BF8A4
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bf488(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  uVar1 = *(uint *)(*(int *)(iVar2 + 0x40c) + 0x18);
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
  }
  uVar3 = ObjGroup_RemoveObject(param_9,3);
  if (*(int *)(param_9 + 200) != 0) {
    FUN_80017ac8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
    *(undefined4 *)(param_9 + 200) = 0;
  }
  (**(code **)(*DAT_803dd738 + 0x40))(param_9,iVar2,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bf58c
 * EN v1.0 Address: 0x801BF58C
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x801BF930
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bf58c(int param_1)
{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
    iVar1 = *(int *)(*(int *)(iVar1 + 0x40c) + 0x18);
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_8005fe14(iVar1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bf5ec
 * EN v1.0 Address: 0x801BF5EC
 * EN v1.0 Size: 876b
 * EN v1.1 Address: 0x801BF99C
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bf5ec(ushort *param_1)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  float *pfVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  uint local_68;
  uint uStack_64;
  uint uStack_60;
  undefined auStack_5c [8];
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  iVar5 = *(int *)(param_1 + 0x5c);
  if ((*(int *)(param_1 + 0x7a) == 0) &&
     ((*(int *)(param_1 + 0x18) != 0 ||
      (iVar1 = FUN_8005b398((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8)),
      -1 < iVar1)))) {
    local_68 = 0;
    do {
      iVar1 = ObjMsg_Pop((int)param_1,&uStack_64,&uStack_60,&local_68);
    } while (iVar1 != 0);
    pfVar4 = *(float **)(iVar5 + 0x40c);
    if ((*pfVar4 < FLOAT_803e5968) && (pfVar4[4] < FLOAT_803e596c)) {
      dVar8 = (double)(pfVar4[3] - *(float *)(param_1 + 8));
      if (dVar8 < (double)FLOAT_803e5970) {
        dVar8 = -dVar8;
      }
      if ((dVar8 < (double)FLOAT_803e5974) &&
         (local_4c = pfVar4[3], uVar2 = FUN_80017760(0x1e,0x3c),
         (int)uVar2 < (int)(uint)*(ushort *)((int)pfVar4 + 0x16))) {
        dVar7 = (double)(FLOAT_803e5978 * pfVar4[4]);
        uStack_3c = (int)(short)*param_1 ^ 0x80000000;
        local_40 = 0x43300000;
        dVar6 = (double)FUN_80293f90();
        local_50 = -(float)(dVar7 * dVar6 - (double)*(float *)(param_1 + 6));
        uStack_34 = (int)(short)*param_1 ^ 0x80000000;
        local_38 = 0x43300000;
        dVar6 = (double)FUN_80294964();
        local_48 = -(float)(dVar7 * dVar6 - (double)*(float *)(param_1 + 10));
        local_54 = FLOAT_803e5984 * (FLOAT_803e5988 - (float)(dVar8 / (double)FLOAT_803e5974));
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x32b,auStack_5c,1,0xffffffff,0);
        *(undefined2 *)((int)pfVar4 + 0x16) = 0;
      }
    }
    *(ushort *)((int)pfVar4 + 0x16) = *(short *)((int)pfVar4 + 0x16) + (ushort)DAT_803dc070;
    FUN_801bf04c((int)param_1,iVar5);
    FUN_801bf1f4(param_1,iVar5);
    FUN_8002fc3c((double)FLOAT_803e59b8,(double)FLOAT_803dc074);
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6e) = 9;
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6f) = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_1);
    iVar1 = *(int *)(iVar5 + 0x40c);
    iVar5 = *(int *)(iVar1 + 0x18);
    if (((iVar5 != 0) && (*(char *)(iVar5 + 0x2f8) != '\0')) && (*(char *)(iVar5 + 0x4c) != '\0')) {
      uVar2 = (uint)*(byte *)(iVar5 + 0x2f9) + (int)*(char *)(iVar5 + 0x2fa) & 0xffff;
      if (0xc < uVar2) {
        uVar3 = FUN_80017760(0xfffffff4,0xc);
        uVar2 = uVar2 + uVar3 & 0xffff;
        if (0xff < uVar2) {
          uVar2 = 0xff;
          *(undefined *)(*(int *)(iVar1 + 0x18) + 0x2fa) = 0;
        }
      }
      *(char *)(*(int *)(iVar1 + 0x18) + 0x2f9) = (char)uVar2;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bf958
 * EN v1.0 Address: 0x801BF958
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801BFC68
 * EN v1.1 Size: 548b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bf958(int param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801bf95c
 * EN v1.0 Address: 0x801BF95C
 * EN v1.0 Size: 824b
 * EN v1.1 Address: 0x801BFE8C
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bf95c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  uint uVar1;
  int iVar2;
  short *psVar3;
  double dVar4;
  int local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  undefined8 local_18;
  
  psVar3 = *(short **)(param_9 + 0x5c);
  dVar4 = (double)*(float *)(param_9 + 4);
  *(float *)(param_9 + 4) = (float)(dVar4 + (double)FLOAT_803e59d0);
  *param_9 = *param_9 + 0xaaa;
  param_9[2] = param_9[2] + 0x38e;
  param_9[1] = param_9[1] + 0x38e;
  if (*psVar3 == 1) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x340,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x12);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x4bb,0,1,0xffffffff,0);
    FUN_80006824((uint)param_9,0x17e);
    FUN_80006824((uint)param_9,0x186);
    FUN_80006920((double)FLOAT_803e59d4);
    dVar4 = (double)FUN_80006b94((double)FLOAT_803e59d8);
    if (*(int *)(psVar3 + 2) != 0) {
      dVar4 = (double)FUN_800175cc((double)FLOAT_803e59dc,*(int *)(psVar3 + 2),'\0');
    }
  }
  *psVar3 = *psVar3 + (ushort)DAT_803dc070;
  uVar1 = (uint)*psVar3;
  if ((int)uVar1 < 0x201) {
    uStack_1c = uVar1 ^ 0x80000000;
    local_20 = 0x43300000;
    iVar2 = (int)(FLOAT_803e59e0 *
                 (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e59f0) * FLOAT_803e59e4)
    ;
    local_18 = (double)(longlong)iVar2;
    iVar2 = 0xff - iVar2;
    local_28[0] = 0x94 - ((int)uVar1 >> 2);
    if (iVar2 < 0) {
      if (*(uint *)(psVar3 + 2) != 0) {
        FUN_80017620(*(uint *)(psVar3 + 2));
        psVar3[2] = 0;
        psVar3[3] = 0;
      }
      *(undefined *)(param_9 + 0x1b) = 0;
      local_18 = (double)CONCAT44(0x43300000,local_28[0] + -0x40 >> 1 ^ 0x80000000);
      if (FLOAT_803e59e8 < (float)(local_18 - DOUBLE_803e59f0)) {
        ObjHits_SetHitVolumeSlot((int)param_9,9,1,0);
        FUN_80035b84((int)param_9,(short)(local_28[0] + -0x40 >> 1));
      }
    }
    else {
      ObjHits_SetHitVolumeSlot((int)param_9,5,2,0);
      FUN_80035b84((int)param_9,(short)(local_28[0] + -0x40 >> 1));
      *(char *)(param_9 + 0x1b) = (char)iVar2;
    }
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x4bc,0,1,0xffffffff,local_28);
  }
  else if (0x22a < (int)uVar1) {
    FUN_80017ac8(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bfc94
 * EN v1.0 Address: 0x801BFC94
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801C0124
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bfc94(int param_1)
{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 4);
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bfcec
 * EN v1.0 Address: 0x801BFCEC
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801C0178
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bfcec(int param_1)
{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
    iVar1 = *(int *)(iVar1 + 4);
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_8005fe14(iVar1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bfd48
 * EN v1.0 Address: 0x801BFD48
 * EN v1.0 Size: 772b
 * EN v1.1 Address: 0x801C01E0
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bfd48(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  double dVar1;
  float fVar2;
  short sVar3;
  uint uVar4;
  int iVar5;
  short *psVar6;
  
  psVar6 = *(short **)(param_9 + 0x5c);
  if (*psVar6 == 0) {
    *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) - (uint)DAT_803dc070;
    if (*(int *)(param_9 + 0x7a) < 0) {
      FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      return;
    }
    ObjHits_SetHitVolumeSlot((int)param_9,5,4,0);
    FUN_80035b84((int)param_9,10);
    *(float *)(param_9 + 0x14) = -(FLOAT_803e59f8 * FLOAT_803dc074 - *(float *)(param_9 + 0x14));
    *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * FLOAT_803e59fc;
    dVar1 = DOUBLE_803e59f0;
    *param_9 = (short)(int)(FLOAT_803e5a00 * FLOAT_803dc074 +
                           (float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000) -
                                  DOUBLE_803e59f0));
    fVar2 = FLOAT_803e5a04;
    param_9[2] = (short)(int)(FLOAT_803e5a04 * FLOAT_803dc074 +
                             (float)((double)CONCAT44(0x43300000,(int)param_9[2] ^ 0x80000000) -
                                    dVar1));
    param_9[1] = (short)(int)(fVar2 * FLOAT_803dc074 +
                             (float)((double)CONCAT44(0x43300000,(int)param_9[1] ^ 0x80000000) -
                                    dVar1));
    FUN_80017a88((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x4ba,0,1,0xffffffff,0);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 3);
    if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') {
      *(undefined4 *)(param_9 + 6) = *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x3c);
      *(float *)(param_9 + 8) = *(float *)(*(int *)(param_9 + 0x2a) + 0x40) - FLOAT_803e59e8;
      *(undefined4 *)(param_9 + 10) = *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x44);
      *psVar6 = 1;
    }
  }
  else {
    FUN_801bf95c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  iVar5 = *(int *)(psVar6 + 2);
  if (((iVar5 != 0) && (*(char *)(iVar5 + 0x2f8) != '\0')) && (*(char *)(iVar5 + 0x4c) != '\0')) {
    sVar3 = (ushort)*(byte *)(iVar5 + 0x2f9) + (short)*(char *)(iVar5 + 0x2fa);
    if (sVar3 < 0) {
      sVar3 = 0;
      *(undefined *)(iVar5 + 0x2fa) = 0;
    }
    else if (0xc < sVar3) {
      uVar4 = FUN_80017760(0xfffffff4,0xc);
      sVar3 = sVar3 + (short)uVar4;
      if (0xff < sVar3) {
        sVar3 = 0xff;
        *(undefined *)(*(int *)(psVar6 + 2) + 0x2fa) = 0;
      }
    }
    *(char *)(*(int *)(psVar6 + 2) + 0x2f9) = (char)sVar3;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c004c
 * EN v1.0 Address: 0x801C004C
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x801C0468
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c004c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int *piVar1;
  int iVar2;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 *puVar3;
  double dVar4;
  
  puVar3 = *(undefined2 **)(param_9 + 0xb8);
  piVar1 = FUN_80017624(param_9,'\x01');
  *(int **)(puVar3 + 2) = piVar1;
  if (*(int *)(puVar3 + 2) != 0) {
    FUN_800175b0(*(int *)(puVar3 + 2),2);
    FUN_8001759c(*(int *)(puVar3 + 2),0,0xff,0,0);
    FUN_80017588(*(int *)(puVar3 + 2),0,0xff,0,0);
    dVar4 = (double)FLOAT_803e5a0c;
    FUN_800175d0((double)FLOAT_803e5a08,dVar4,*(int *)(puVar3 + 2));
    FUN_800175bc(*(int *)(puVar3 + 2),1);
    FUN_800175cc((double)FLOAT_803e5a10,*(int *)(puVar3 + 2),'\x01');
    FUN_800175d8(*(int *)(puVar3 + 2),1);
    FUN_8001754c((double)FLOAT_803e5a14,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(undefined4 *)(puVar3 + 2),0,0,0xff,0,0x7f,in_r9,in_r10);
    FUN_80017544((double)FLOAT_803e5a18,*(int *)(puVar3 + 2));
  }
  *(undefined4 *)(param_9 + 0xf4) = 0xb4;
  ObjHits_SetHitVolumeSlot(param_9,0,0,0);
  FUN_80035b84(param_9,0);
  *puVar3 = 0;
  puVar3[1] = 0;
  ObjHits_EnableObject(param_9);
  iVar2 = FUN_80017a54(param_9);
  FUN_80017958(iVar2,FUN_80017954);
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void dimbossgut2_func11(void) {}
void dimbossgut2_hitDetect(void) {}
void dimbossgut2_release(void) {}
void dimbossgut2_initialise(void) {}
void dimbossspit_hitDetect(void) {}
void dimbossspit_release(void) {}
void dimbossspit_initialise(void) {}
void magicmaker_free(void) {}
void magicmaker_hitDetect(void) {}
void magicmaker_init(void) {}
void magicmaker_release(void) {}
void magicmaker_initialise(void) {}
void dimbosscrackpar_hitDetect(void) {}
void dimbosscrackpar_release(void) {}
void dimbosscrackpar_initialise(void) {}
void dimbossfire_hitDetect(void) {}
