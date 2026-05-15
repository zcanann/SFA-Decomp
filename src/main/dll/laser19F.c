#include "ghidra_import.h"
#include "main/dll/laser19F.h"

extern undefined8 FUN_80006b14();
extern char FUN_80006bd0();
extern undefined4 FUN_800175cc();
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017710();
extern uint FUN_80017730();
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjMsg_AllocQueue();
extern int FUN_8005398c();
extern undefined4 FUN_8011eb10();
extern undefined4 FUN_8011eb1c();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294ccc();

extern undefined4* DAT_803dd72c;
extern void* DAT_803de838;
extern f64 DOUBLE_803e5bd0;
extern f32 lbl_803DC074;
extern f32 lbl_803E5B58;
extern f32 lbl_803E5BA0;
extern f32 lbl_803E5BA4;
extern f32 lbl_803E5BA8;
extern f32 lbl_803E5BAC;
extern f32 lbl_803E5BB8;
extern f32 lbl_803E5BBC;
extern f32 lbl_803E5BC0;
extern f32 lbl_803E5BC4;
extern f32 lbl_803E5BC8;
extern f32 lbl_803E5BD8;
extern f32 lbl_803E5BDC;
extern f32 lbl_803E5BE0;
extern f32 lbl_803E5BE4;
extern f32 lbl_803E5BE8;
extern f32 lbl_803E5BEC;
extern f32 lbl_803E5BF0;
extern f32 lbl_803E5BF4;
extern f32 lbl_803E5BF8;

/*
 * --INFO--
 *
 * Function: FUN_801c4b10
 * EN v1.0 Address: 0x801C4B10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C4B54
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c4b10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c4b14
 * EN v1.0 Address: 0x801C4B14
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801C4C18
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c4b14(ushort *param_1)
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
  iVar1 = FUN_80017a98();
  if ((param_1[3] & 0x4000) == 0) {
    *(short *)(iVar3 + 0x1e) =
         *(short *)(iVar3 + 0x1e) + (short)(int)(lbl_803E5BA0 * lbl_803DC074);
    *(short *)(iVar3 + 0x20) =
         *(short *)(iVar3 + 0x20) + (short)(int)(lbl_803E5BA4 * lbl_803DC074);
    *(short *)(iVar3 + 0x22) =
         *(short *)(iVar3 + 0x22) + (short)(int)(lbl_803E5BA8 * lbl_803DC074);
    dVar5 = (double)FUN_80293f90();
    *(float *)(param_1 + 8) = lbl_803E5BAC + (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
    dVar5 = (double)FUN_80293f90();
    dVar6 = (double)FUN_80293f90();
    param_1[2] = (ushort)(int)(lbl_803E5BB8 * (float)(dVar6 + dVar5));
    dVar5 = (double)FUN_80293f90();
    dVar6 = (double)FUN_80293f90();
    param_1[1] = (ushort)(int)(lbl_803E5BB8 * (float)(dVar6 + dVar5));
    FUN_8002fc3c((double)lbl_803E5BBC,(double)lbl_803DC074);
    if (iVar1 != 0) {
      uVar2 = FUN_80017730();
      uVar2 = (uVar2 & 0xffff) - (uint)*param_1;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *param_1 = *param_1 +
                 (short)(int)(((float)(local_30 - DOUBLE_803e5bd0) * lbl_803DC074) /
                             lbl_803E5BC0);
      dVar5 = (double)FUN_80017710((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      if ((double)lbl_803E5BC4 < dVar5) {
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      else {
        *(char *)(param_1 + 0x1b) =
             (char)(int)(lbl_803E5BC8 * (float)(dVar5 / (double)lbl_803E5BC4));
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
 * Function: FUN_801c4de0
 * EN v1.0 Address: 0x801C4DE0
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x801C4F6C
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801c4de0(int param_1)
{
  float fVar1;
  float fVar2;
  char cVar4;
  undefined4 uVar3;
  int iVar5;
  undefined8 local_18;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if ((*(uint *)(iVar5 + 0x18) & 0x20) == 0) {
    FUN_8011eb10(1);
    *(uint *)(iVar5 + 0x18) = *(uint *)(iVar5 + 0x18) | 0x20;
    fVar1 = lbl_803E5BD8;
    *(float *)(iVar5 + 4) = lbl_803E5BD8;
    *(float *)(iVar5 + 8) = fVar1;
    *(float *)(iVar5 + 0xc) = fVar1;
  }
  cVar4 = FUN_80006bd0(0);
  fVar2 = lbl_803E5BE0;
  local_18 = (double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000);
  *(float *)(iVar5 + 8) =
       ((float)(local_18 - DOUBLE_803e5bd0) / lbl_803E5BDC) * lbl_803E5BE0 * lbl_803DC074 +
       *(float *)(iVar5 + 8);
  fVar1 = *(float *)(iVar5 + 0x10);
  if ((lbl_803E5BD8 <= fVar1) || (*(float *)(iVar5 + 0xc) <= fVar1)) {
    if ((lbl_803E5BD8 < fVar1) && (*(float *)(iVar5 + 0xc) < fVar1)) {
      *(float *)(iVar5 + 0xc) = lbl_803E5BE0 * lbl_803DC074 + *(float *)(iVar5 + 0xc);
    }
  }
  else {
    *(float *)(iVar5 + 0xc) = -(fVar2 * lbl_803DC074 - *(float *)(iVar5 + 0xc));
  }
  *(float *)(iVar5 + 4) =
       lbl_803DC074 * (*(float *)(iVar5 + 8) + *(float *)(iVar5 + 0xc)) + *(float *)(iVar5 + 4);
  iVar5 = (int)(lbl_803E5BE4 * *(float *)(iVar5 + 4));
  FUN_8011eb1c(0x60,0x39,(short)iVar5);
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
 * Function: FUN_801c4f4c
 * EN v1.0 Address: 0x801C4F4C
 * EN v1.0 Size: 1092b
 * EN v1.1 Address: 0x801C50C4
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c4f4c(undefined4 param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  
  iVar1 = FUN_8028683c();
  piVar5 = *(int **)(iVar1 + 0xb8);
  iVar2 = FUN_80017a98();
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
        FUN_8011eb10(0);
        piVar5[6] = piVar5[6] & 0xffffffdf;
      }
      break;
    case 3:
      piVar5[4] = (int)lbl_803E5BEC;
      break;
    case 4:
      piVar5[4] = (int)lbl_803E5BF0;
      break;
    case 5:
      piVar5[4] = (int)-(float)piVar5[4];
      piVar5[3] = (int)-(float)piVar5[4];
      break;
    case 6:
      piVar5[4] = (int)((float)piVar5[4] * lbl_803E5BF4);
      break;
    case 7:
      FUN_80294ccc(iVar2,4,1);
      GameBit_Set(0x12a,1);
      GameBit_Set(0xff,1);
      (**(code **)(*DAT_803dd72c + 0x44))(0xb,3);
      break;
    case 8:
      piVar5[4] = (int)((float)piVar5[4] * lbl_803E5BF8);
      break;
    case 0xe:
      *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
      if (*piVar5 != 0) {
        FUN_800175cc((double)lbl_803E5BE8,*piVar5,'\0');
      }
      break;
    case 0xf:
      *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) & 0xbfff;
      if (*piVar5 != 0) {
        FUN_800175cc((double)lbl_803E5BE8,*piVar5,'\0');
      }
    }
    *(undefined *)(param_3 + iVar4 + 0x81) = 0;
  }
  if (((piVar5[6] & 2U) == 0) || (uVar3 = FUN_801c4de0(iVar1), (uVar3 & 0xff) == 0)) {
    piVar5[6] = piVar5[6] | 1;
  }
  else {
    FUN_8011eb10(0);
    piVar5[6] = piVar5[6] & 0xffffffdd;
    *(undefined *)(piVar5 + 9) = 3;
    GameBit_Set(0xe82,0);
    GameBit_Set(0xe83,0);
    GameBit_Set(0xe84,0);
    GameBit_Set(0xe85,0);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: mmsh_shrine_getExtraSize
 * EN v1.0 Address: 0x801C4D78
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int mmsh_shrine_getExtraSize(void)
{
  return 0x28;
}

/*
 * --INFO--
 *
 * Function: mmsh_shrine_func08
 * EN v1.0 Address: 0x801C4D80
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int mmsh_shrine_func08(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: mmsh_shrine_hitDetect
 * EN v1.0 Address: 0x801C4F1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void mmsh_shrine_hitDetect(void)
{
}
