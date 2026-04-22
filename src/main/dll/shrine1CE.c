#include "ghidra_import.h"
#include "main/dll/shrine1CE.h"

extern undefined4 FUN_800066e0();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_800217c8();
extern uint FUN_8002bac4();
extern void* FUN_8002becc();
extern undefined4 FUN_8002e088();
extern uint FUN_8002e144();
extern int FUN_80036f50();
extern int FUN_800375e4();
extern undefined4 FUN_80037a5c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80137cd0();
extern undefined4 FUN_801cc04c();
extern int FUN_80286834();
extern undefined4 FUN_80286880();
extern undefined4 FUN_802972d8();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f0;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern f64 DOUBLE_803e5e40;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5e24;
extern f32 FLOAT_803e5e28;
extern f32 FLOAT_803e5e2c;
extern f32 FLOAT_803e5e30;
extern f32 FLOAT_803e5e34;
extern f32 FLOAT_803e5e38;
extern f32 FLOAT_803e5e4c;

/*
 * --INFO--
 *
 * Function: FUN_801cc33c
 * EN v1.0 Address: 0x801CC33C
 * EN v1.0 Size: 2032b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cc33c(void)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  short sVar5;
  uint uVar6;
  int iVar7;
  short *psVar8;
  double in_f31;
  double dVar9;
  double in_ps31_1;
  uint uStack_68;
  uint local_64 [2];
  float local_5c [2];
  uint uStack_54;
  longlong local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined8 local_40;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar1 = FUN_80286834();
  psVar8 = *(short **)(iVar1 + 0xb8);
  uVar2 = FUN_8002bac4();
  local_5c[0] = FLOAT_803e5e24;
  iVar7 = *(int *)(iVar1 + 0xb8);
  local_64[1] = 0;
  while (iVar3 = FUN_800375e4(iVar1,local_64,&uStack_68,local_64 + 1), iVar3 != 0) {
    if (local_64[0] == 0x30006) {
      *(undefined2 *)(iVar7 + 6) = 0x10;
    }
    else if (((int)local_64[0] < 0x30006) && (0x30004 < (int)local_64[0])) {
      *(undefined2 *)(iVar7 + 6) = 0xfffd;
    }
  }
  FUN_800201ac(0x127,1);
  if (psVar8[3] != 0) {
    psVar8[2] = psVar8[2] + psVar8[3];
    if (psVar8[2] < 0xd) {
      psVar8[2] = 0xc;
      psVar8[3] = 0;
    }
    else if (0x45 < psVar8[2]) {
      psVar8[2] = 0x46;
      psVar8[3] = 0;
    }
    (**(code **)(*DAT_803dd6f0 + 0x38))(2,psVar8[2] & 0xff);
  }
  if (psVar8[5] != 0) {
    psVar8[4] = psVar8[4] + psVar8[5];
    if ((psVar8[4] < 2) && (psVar8[5] < 1)) {
      psVar8[4] = 1;
      psVar8[5] = 0;
    }
    else if ((0x45 < psVar8[4]) && (-1 < psVar8[5])) {
      psVar8[4] = 0x46;
      psVar8[5] = 0;
    }
    (**(code **)(*DAT_803dd6f0 + 0x38))(3,psVar8[4] & 0xff);
  }
  if (psVar8[1] < 1) {
    iVar7 = FUN_80036f50(0xe,uVar2,local_5c);
    if (((iVar7 != 0) && (local_5c[0] < FLOAT_803e5e28)) && (FLOAT_803e5e2c < local_5c[0])) {
      dVar9 = (double)(*(float *)(iVar7 + 0x14) - *(float *)(uVar2 + 0x14));
      if (dVar9 <= (double)FLOAT_803e5e30) {
        if (dVar9 < (double)FLOAT_803e5e30) {
          dVar9 = (double)(float)(dVar9 * (double)FLOAT_803e5e34);
        }
        if (psVar8[4] != 0x1e) {
          psVar8[4] = 0x1e;
        }
        uStack_54 = (int)psVar8[4] ^ 0x80000000;
        local_5c[1] = 176.0;
        uVar6 = (uint)((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e5e40) *
                      ((float)(dVar9 - (double)FLOAT_803e5e2c) / FLOAT_803e5e38));
        local_50 = (longlong)(int)uVar6;
        if ((short)uVar6 < 1) {
          uVar6 = 1;
        }
        (**(code **)(*DAT_803dd6f0 + 0x38))(3,uVar6 & 0xff);
        uStack_44 = (int)psVar8[2] ^ 0x80000000;
        local_48 = 0x43300000;
        uVar6 = (uint)((float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e5e40) *
                      ((FLOAT_803e5e38 - (float)(dVar9 - (double)FLOAT_803e5e2c)) / FLOAT_803e5e38))
        ;
        local_40 = (double)(longlong)(int)uVar6;
        if ((short)uVar6 < 1) {
          uVar6 = 1;
        }
        (**(code **)(*DAT_803dd6f0 + 0x38))(2,uVar6 & 0xff);
      }
    }
    switch(*(undefined *)((int)psVar8 + 0x13)) {
    case 0:
      dVar9 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(uVar2 + 0x18));
      local_40 = (double)CONCAT44(0x43300000,(int)*psVar8 ^ 0x80000000);
      if (dVar9 < (double)(float)(local_40 - DOUBLE_803e5e40)) {
        *(undefined *)((int)psVar8 + 0x13) = 1;
        FUN_800201ac(0x129,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
        piVar4 = (int *)FUN_80013ee8(0x83);
        (**(code **)(*piVar4 + 4))(iVar1,1,0,1,0xffffffff,0);
        FUN_80013e4c((undefined *)piVar4);
        piVar4 = (int *)FUN_80013ee8(0x84);
        (**(code **)(*piVar4 + 4))(iVar1,0,0,1,0xffffffff,0);
        FUN_80013e4c((undefined *)piVar4);
        FUN_800201ac(0x126,0);
        (**(code **)(*DAT_803dd6fc + 0x20))(psVar8 + 6);
      }
      break;
    case 1:
      if (*(char *)(psVar8 + 10) == '\x01') {
        *(undefined *)((int)psVar8 + 0x13) = 2;
        psVar8[1] = 0xa0;
      }
      break;
    case 2:
      if ((*(char *)(psVar8 + 9) == '\0') && (uVar2 = FUN_80020078(0x1d3), uVar2 == 0)) {
        FUN_800201ac(0x1d3,1);
      }
      uVar2 = FUN_80020078(0x1d8);
      if (uVar2 != 0) {
        *(char *)(psVar8 + 9) = *(char *)(psVar8 + 9) + '\x01';
        FUN_800201ac(0x1d8,0);
      }
      local_40 = (double)(longlong)(int)FLOAT_803dc074;
      psVar8[7] = psVar8[7] - (short)(int)FLOAT_803dc074;
      FUN_80137cd0();
      if (psVar8[7] < 1) {
        FUN_800201ac(0x1d4,1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,iVar1,0xffffffff);
        psVar8[1] = 10;
        *(undefined *)((int)psVar8 + 0x13) = 6;
        (**(code **)(*DAT_803dd6f0 + 0x18))(3,0x35,0x50,psVar8[4] & 0xff,0);
        psVar8[5] = 1;
        FUN_800201ac(0x1d3,0);
      }
      else if (*(char *)(psVar8 + 9) == '\x01') {
        *(undefined *)((int)psVar8 + 0x13) = 3;
        psVar8[1] = 200;
        psVar8[5] = -3;
      }
      break;
    case 3:
      uVar6 = FUN_80020078(0x1d1);
      if (uVar6 == 0) {
        FUN_802972d8(uVar2,-1);
        FUN_800201ac(0x126,0);
        (**(code **)(*DAT_803dd6f0 + 0x18))(3,0x2a,0x50,psVar8[4] & 0xff,0);
        psVar8[5] = 1;
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar1,0xffffffff);
        *(undefined *)((int)psVar8 + 0x13) = 4;
      }
      else {
        psVar8[4] = 1;
        (**(code **)(*DAT_803dd6f0 + 0x18))(3,0x2c,0x50,psVar8[4] & 0xff,0);
        psVar8[5] = 1;
        FUN_800201ac(0x129,1);
        *(undefined *)((int)psVar8 + 0x13) = 5;
      }
      break;
    case 4:
      uVar2 = FUN_80020078(0xfd);
      if (uVar2 == 0) {
        FUN_800201ac(0xfd,1);
      }
      FUN_800201ac(0x1d2,0);
      FUN_800201ac(0x127,0);
      *(undefined *)((int)psVar8 + 0x13) = 5;
      (**(code **)(*DAT_803dd6f0 + 0x18))(3,0x2c,0x50,psVar8[4] & 0xff,0);
      break;
    case 6:
      *(undefined *)((int)psVar8 + 0x13) = 0;
      *(undefined *)(psVar8 + 10) = 0;
      psVar8[1] = 400;
      FUN_800201ac(0x129,1);
      FUN_800201ac(0x126,1);
      FUN_800201ac(0x127,1);
      piVar4 = (int *)FUN_80013ee8(0x6a);
      sVar5 = (**(code **)(*piVar4 + 4))(iVar1,2,0,0x402,0xffffffff,0);
      psVar8[6] = sVar5;
      FUN_80013e4c((undefined *)piVar4);
      FUN_800201ac(0x1d8,0);
      *(undefined *)(psVar8 + 9) = 0;
      psVar8[7] = 4000;
      FUN_800201ac(0x1d4,0);
    }
  }
  else {
    psVar8[1] = psVar8[1] - (ushort)DAT_803dc070;
    if ((psVar8[1] < 1) && (psVar8[1] = 0, *(char *)(psVar8 + 0xb) == '\0')) {
      (**(code **)(*DAT_803dd6f0 + 0x18))(3,0x2c,0x50,(int)psVar8[4],0);
      *(undefined *)(psVar8 + 0xb) = 1;
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ccb2c
 * EN v1.0 Address: 0x801CCB2C
 * EN v1.0 Size: 456b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ccb2c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801cccf4
 * EN v1.0 Address: 0x801CCCF4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cccf4(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ccd28
 * EN v1.0 Address: 0x801CCD28
 * EN v1.0 Size: 564b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ccd28(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  int *piVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar4;
  int iVar5;
  double dVar6;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  iVar4 = *(int *)(param_9 + 0xb8);
  if ((*(int *)(param_9 + 0xf8) != 0) && (uVar1 = FUN_80020078(0x1d4), uVar1 != 0)) {
    *(undefined4 *)(param_9 + 0xf8) = 0;
  }
  if ((*(int *)(param_9 + 0xf8) == 0) && (uVar1 = FUN_80020078(0x1d3), uVar1 != 0)) {
    piVar2 = (int *)FUN_80013ee8(0x82);
    (**(code **)(*piVar2 + 4))(param_9,0,0,1,0xffffffff,0);
    in_r8 = 0;
    in_r9 = *piVar2;
    (**(code **)(in_r9 + 4))(param_9,1,0,1,0xffffffff);
    FUN_8000bb38(0,0xaf);
    FUN_80013e4c((undefined *)piVar2);
    *(undefined2 *)(iVar4 + 6) = 1;
    *(undefined4 *)(param_9 + 0xf8) = 1;
  }
  if (*(short *)(iVar4 + 6) != 0) {
    *(ushort *)(iVar4 + 4) = *(short *)(iVar4 + 4) - *(short *)(iVar4 + 6) * (ushort)DAT_803dc070;
  }
  if (((*(short *)(iVar4 + 4) < 1) && (*(char *)(iVar5 + 0x1f) == '\0')) &&
     (uVar1 = FUN_8002e144(), (uVar1 & 0xff) != 0)) {
    puVar3 = FUN_8002becc(0x18,0x248);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar5 + 8);
    dVar6 = (double)FLOAT_803e5e4c;
    *(float *)(puVar3 + 6) = (float)(dVar6 + (double)*(float *)(iVar5 + 0xc));
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar5 + 0x10);
    *puVar3 = 0x248;
    *(undefined4 *)(puVar3 + 10) = 0xffffffff;
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
    *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
    *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar5 + 7);
    FUN_8002e088(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                 *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,in_r9,
                 in_r10);
    *(undefined2 *)(iVar4 + 4) = 100;
    *(undefined2 *)(iVar4 + 6) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ccf5c
 * EN v1.0 Address: 0x801CCF5C
 * EN v1.0 Size: 132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ccf5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if ((*(byte *)(iVar1 + 0x36) & 2) == 0) {
    FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,1,0
                 ,0,0,in_r9,in_r10);
    *(byte *)(iVar1 + 0x36) = *(byte *)(iVar1 + 0x36) | 2;
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_9);
  return;
}
