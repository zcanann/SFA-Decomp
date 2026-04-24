#include "ghidra_import.h"
#include "main/dll/laser19F.h"

extern undefined8 FUN_80013ee8();
extern char FUN_80014cec();
extern undefined4 FUN_8001dc30();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_80021754();
extern uint FUN_80021884();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern undefined4 FUN_8002fb40();
extern undefined4 FUN_80037a5c();
extern int FUN_80054ed0();
extern undefined4 FUN_8011f9b8();
extern undefined4 FUN_8011f9c4();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80296c78();

extern undefined4* DAT_803dd72c;
extern void* DAT_803de838;
extern f64 DOUBLE_803e5bd0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5b58;
extern f32 FLOAT_803e5ba0;
extern f32 FLOAT_803e5ba4;
extern f32 FLOAT_803e5ba8;
extern f32 FLOAT_803e5bac;
extern f32 FLOAT_803e5bb8;
extern f32 FLOAT_803e5bbc;
extern f32 FLOAT_803e5bc0;
extern f32 FLOAT_803e5bc4;
extern f32 FLOAT_803e5bc8;
extern f32 FLOAT_803e5bd8;
extern f32 FLOAT_803e5bdc;
extern f32 FLOAT_803e5be0;
extern f32 FLOAT_803e5be4;
extern f32 FLOAT_803e5be8;
extern f32 FLOAT_803e5bec;
extern f32 FLOAT_803e5bf0;
extern f32 FLOAT_803e5bf4;
extern f32 FLOAT_803e5bf8;

/*
 * --INFO--
 *
 * Function: FUN_801c4b54
 * EN v1.0 Address: 0x801C4B10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C4B54
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c4b54(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c4c18
 * EN v1.0 Address: 0x801C4B14
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801C4C18
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c4c18(ushort *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 local_30;
  
  iVar4 = *(int *)(param_1 + 0x26);
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_8002bac4();
  if ((param_1[3] & 0x4000) == 0) {
    *(short *)(iVar3 + 0x1e) =
         *(short *)(iVar3 + 0x1e) + (short)(int)(FLOAT_803e5ba0 * FLOAT_803dc074);
    *(short *)(iVar3 + 0x20) =
         *(short *)(iVar3 + 0x20) + (short)(int)(FLOAT_803e5ba4 * FLOAT_803dc074);
    *(short *)(iVar3 + 0x22) =
         *(short *)(iVar3 + 0x22) + (short)(int)(FLOAT_803e5ba8 * FLOAT_803dc074);
    dVar5 = (double)FUN_802945e0();
    *(float *)(param_1 + 8) = FLOAT_803e5bac + (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
    dVar5 = (double)FUN_802945e0();
    dVar6 = (double)FUN_802945e0();
    param_1[2] = (ushort)(int)(FLOAT_803e5bb8 * (float)(dVar6 + dVar5));
    dVar5 = (double)FUN_802945e0();
    dVar6 = (double)FUN_802945e0();
    param_1[1] = (ushort)(int)(FLOAT_803e5bb8 * (float)(dVar6 + dVar5));
    FUN_8002fb40((double)FLOAT_803e5bbc,(double)FLOAT_803dc074);
    if (iVar1 != 0) {
      uVar2 = FUN_80021884();
      uVar2 = (uVar2 & 0xffff) - (uint)*param_1;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *param_1 = *param_1 +
                 (short)(int)(((float)(local_30 - DOUBLE_803e5bd0) * FLOAT_803dc074) /
                             FLOAT_803e5bc0);
      dVar5 = (double)FUN_80021754((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      if ((double)FLOAT_803e5bc4 < dVar5) {
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      else {
        *(char *)(param_1 + 0x1b) =
             (char)(int)(FLOAT_803e5bc8 * (float)(dVar5 / (double)FLOAT_803e5bc4));
      }
    }
  }
  else {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c4f6c
 * EN v1.0 Address: 0x801C4DE0
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x801C4F6C
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801c4f6c(int param_1)
{
  float fVar1;
  float fVar2;
  char cVar4;
  undefined4 uVar3;
  int iVar5;
  undefined8 local_18;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if ((*(uint *)(iVar5 + 0x18) & 0x20) == 0) {
    FUN_8011f9b8(1);
    *(uint *)(iVar5 + 0x18) = *(uint *)(iVar5 + 0x18) | 0x20;
    fVar1 = FLOAT_803e5bd8;
    *(float *)(iVar5 + 4) = FLOAT_803e5bd8;
    *(float *)(iVar5 + 8) = fVar1;
    *(float *)(iVar5 + 0xc) = fVar1;
  }
  cVar4 = FUN_80014cec(0);
  fVar2 = FLOAT_803e5be0;
  local_18 = (double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000);
  *(float *)(iVar5 + 8) =
       ((float)(local_18 - DOUBLE_803e5bd0) / FLOAT_803e5bdc) * FLOAT_803e5be0 * FLOAT_803dc074 +
       *(float *)(iVar5 + 8);
  fVar1 = *(float *)(iVar5 + 0x10);
  if ((FLOAT_803e5bd8 <= fVar1) || (*(float *)(iVar5 + 0xc) <= fVar1)) {
    if ((FLOAT_803e5bd8 < fVar1) && (*(float *)(iVar5 + 0xc) < fVar1)) {
      *(float *)(iVar5 + 0xc) = FLOAT_803e5be0 * FLOAT_803dc074 + *(float *)(iVar5 + 0xc);
    }
  }
  else {
    *(float *)(iVar5 + 0xc) = -(fVar2 * FLOAT_803dc074 - *(float *)(iVar5 + 0xc));
  }
  *(float *)(iVar5 + 4) =
       FLOAT_803dc074 * (*(float *)(iVar5 + 8) + *(float *)(iVar5 + 0xc)) + *(float *)(iVar5 + 4);
  iVar5 = (int)(FLOAT_803e5be4 * *(float *)(iVar5 + 4));
  FUN_8011f9c4(0x60,0x39,(short)iVar5);
  if ((iVar5 < 0x3a) && (-0x3a < iVar5)) {
    uVar3 = 0;
  }
  else {
    uVar3 = 1;
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_801c50c4
 * EN v1.0 Address: 0x801C4F4C
 * EN v1.0 Size: 1092b
 * EN v1.1 Address: 0x801C50C4
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c50c4(undefined4 param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  
  iVar1 = FUN_8028683c();
  piVar5 = *(int **)(iVar1 + 0xb8);
  iVar2 = FUN_8002bac4();
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    switch(*(undefined *)(param_3 + iVar4 + 0x81)) {
    case 1:
      piVar5[6] = piVar5[6] | 2;
      break;
    case 2:
      piVar5[6] = piVar5[6] & 0xfffffffd;
      if ((piVar5[6] & 0x20U) != 0) {
        FUN_8011f9b8(0);
        piVar5[6] = piVar5[6] & 0xffffffdf;
      }
      break;
    case 3:
      piVar5[4] = (int)FLOAT_803e5bec;
      break;
    case 4:
      piVar5[4] = (int)FLOAT_803e5bf0;
      break;
    case 5:
      piVar5[4] = (int)-(float)piVar5[4];
      piVar5[3] = (int)-(float)piVar5[4];
      break;
    case 6:
      piVar5[4] = (int)((float)piVar5[4] * FLOAT_803e5bf4);
      break;
    case 7:
      FUN_80296c78(iVar2,4,1);
      FUN_800201ac(0x12a,1);
      FUN_800201ac(0xff,1);
      (**(code **)(*DAT_803dd72c + 0x44))(0xb,3);
      break;
    case 8:
      piVar5[4] = (int)((float)piVar5[4] * FLOAT_803e5bf8);
      break;
    case 0xe:
      *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
      if (*piVar5 != 0) {
        FUN_8001dc30((double)FLOAT_803e5be8,*piVar5,'\0');
      }
      break;
    case 0xf:
      *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) & 0xbfff;
      if (*piVar5 != 0) {
        FUN_8001dc30((double)FLOAT_803e5be8,*piVar5,'\0');
      }
    }
    *(undefined *)(param_3 + iVar4 + 0x81) = 0;
  }
  if (((piVar5[6] & 2U) == 0) || (uVar3 = FUN_801c4f6c(iVar1), (uVar3 & 0xff) == 0)) {
    piVar5[6] = piVar5[6] | 1;
  }
  else {
    FUN_8011f9b8(0);
    piVar5[6] = piVar5[6] & 0xffffffdd;
    *(undefined *)(piVar5 + 9) = 3;
    FUN_800201ac(0xe82,0);
    FUN_800201ac(0xe83,0);
    FUN_800201ac(0xe84,0);
    FUN_800201ac(0xe85,0);
  }
  FUN_80286888();
  return;
}
