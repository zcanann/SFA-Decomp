#include "ghidra_import.h"
#include "main/dll/DIM/DIMlavasmash.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017544();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017594();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175ec();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern int FUN_80017a90();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80035fe8();
extern undefined4 FUN_800360d4();
extern undefined4 FUN_80037180();
extern undefined4 FUN_8003735c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8005fe14();
extern undefined4 FUN_80081110();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();

extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e54b0;
extern f64 DOUBLE_803e54d8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e54ac;
extern f32 FLOAT_803e54b8;
extern f32 FLOAT_803e54bc;
extern f32 FLOAT_803e54c0;
extern f32 FLOAT_803e54c4;
extern f32 FLOAT_803e54c8;
extern f32 FLOAT_803e54cc;
extern f32 FLOAT_803e54d0;
extern f32 FLOAT_803e54d4;

/*
 * --INFO--
 *
 * Function: FUN_801b0924
 * EN v1.0 Address: 0x801B0924
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801B0B58
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0924(short *param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  *param_1 = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  iVar2 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar2 + 0x10) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x18) ^ 0x80000000) -
              DOUBLE_803e54b0);
  *(float *)(iVar2 + 0xc) = FLOAT_803e54ac;
  *(ushort *)(iVar2 + 0x14) = (ushort)*(byte *)(param_2 + 0x1d);
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x22));
  *(char *)(iVar2 + 0x18) = (char)uVar1;
  if ((*(short *)(param_2 + 0x24) == -1) && (*(char *)(iVar2 + 0x18) == '\0')) {
    *(undefined *)(iVar2 + 0x1b) = 1;
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b09dc
 * EN v1.0 Address: 0x801B09DC
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801B0C24
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801b09dc(uint param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar2 + 0x1a) == '\x01') {
    FUN_80006824(param_1,0x72);
  }
  else {
    FUN_8000680c(param_1,0x40);
  }
  bVar1 = *(byte *)(param_3 + 0x80);
  if (bVar1 == 2) {
    FUN_80017698(0x2e,1);
  }
  else if (bVar1 < 2) {
    if (bVar1 != 0) {
      *(byte *)(iVar2 + 0x1b) = *(byte *)(iVar2 + 0x1b) ^ 1;
    }
  }
  else if (bVar1 < 4) {
    *(undefined *)(iVar2 + 0x1a) = 4;
  }
  if (*(char *)(iVar2 + 0x1b) == '\0') {
    FUN_8000680c(param_1,1);
  }
  else {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0xd7,0,0,0xffffffff,0);
    FUN_8000680c(param_1,5);
  }
  *(undefined *)(param_3 + 0x80) = 0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801b0ae8
 * EN v1.0 Address: 0x801B0AE8
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x801B0D74
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0ae8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  uint uVar1;
  uint *puVar2;
  undefined8 uVar3;
  
  puVar2 = *(uint **)(param_9 + 0xb8);
  uVar3 = (**(code **)(*DAT_803dd6f8 + 0x18))();
  uVar1 = puVar2[1];
  if ((uVar1 != 0) && (param_10 == 0)) {
    FUN_80017ac8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1);
  }
  FUN_80037180(param_9,0x31);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b0be8
 * EN v1.0 Address: 0x801B0BE8
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x801B0DFC
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0be8(void)
{
  int iVar1;
  char in_r8;
  int iVar2;
  int *piVar3;
  
  iVar1 = FUN_8028683c();
  if (in_r8 != '\0') {
    piVar3 = *(int **)(iVar1 + 0xb8);
    iVar2 = piVar3[1];
    if (iVar2 != 0) {
      iVar2 = *(int *)(*(int *)(iVar2 + 0x7c) + *(char *)(iVar2 + 0xad) * 4);
      *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
      *(undefined *)(piVar3[1] + 0x37) = *(undefined *)(iVar1 + 0x37);
      FUN_8003b818(piVar3[1]);
    }
    FUN_8003b818(iVar1);
    iVar1 = *piVar3;
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_8005fe14(iVar1);
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b0c9c
 * EN v1.0 Address: 0x801B0C9C
 * EN v1.0 Size: 824b
 * EN v1.1 Address: 0x801B0ED8
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0c9c(uint param_1)
{
  bool bVar1;
  byte bVar2;
  float fVar3;
  short sVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  float local_28;
  float local_24;
  float local_20;
  
  piVar7 = *(int **)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  bVar2 = *(byte *)((int)piVar7 + 0x1a);
  if (bVar2 != 3) {
    if (bVar2 < 3) {
      if (bVar2 == 1) {
        if (*piVar7 != 0) {
          FUN_800175cc((double)FLOAT_803e54bc,*piVar7,'\x01');
        }
        FUN_80006824(param_1,0x72);
        piVar7[4] = (int)((float)piVar7[4] - FLOAT_803dc074);
        if (FLOAT_803e54c0 < (float)piVar7[4]) {
          uVar5 = 0;
        }
        else {
          uVar5 = 7;
          piVar7[4] = (int)((float)piVar7[4] + FLOAT_803e54c4);
        }
        piVar7[5] = (int)((float)piVar7[5] - FLOAT_803dc074);
        fVar3 = (float)piVar7[5];
        bVar1 = fVar3 <= FLOAT_803e54c0;
        if (bVar1) {
          piVar7[5] = (int)(fVar3 + FLOAT_803e54b8);
        }
        local_28 = FLOAT_803e54c0;
        local_24 = FLOAT_803e54c4;
        local_20 = FLOAT_803e54c0;
        FUN_80081110(param_1,2,uVar5,(uint)bVar1,&local_28);
        FUN_80035fe8(param_1,0x1f,1,0);
        goto LAB_801b10e4;
      }
      if (bVar2 != 0) {
        if (*piVar7 != 0) {
          FUN_800175cc((double)FLOAT_803e54bc,*piVar7,'\0');
        }
        if (*(char *)(piVar7 + 7) < '\x01') {
          FUN_800360d4(param_1);
          *(undefined *)((int)piVar7 + 0x1a) = 1;
          *(undefined *)((int)piVar7 + 0x1d) = 1;
          FUN_80017698((int)*(short *)(iVar6 + 0x1e),1);
        }
        iVar6 = FUN_80017a90();
        if (iVar6 != 0) {
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            (**(code **)(**(int **)(iVar6 + 0x68) + 0x28))(iVar6,param_1,1,4);
          }
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        }
        FUN_80035fe8(param_1,0,0,0);
        goto LAB_801b10e4;
      }
    }
    else if (bVar2 < 5) goto LAB_801b10e4;
  }
  if (*(char *)(piVar7 + 6) == '\0') {
    *(undefined *)((int)piVar7 + 0x1a) = 1;
    *(undefined *)((int)piVar7 + 0x1d) = 1;
  }
  else {
    *(undefined *)((int)piVar7 + 0x1a) = 2;
  }
LAB_801b10e4:
  if (*(char *)((int)piVar7 + 0x1d) != '\0') {
    *(undefined *)((int)piVar7 + 0x1d) = 0;
  }
  iVar6 = *piVar7;
  if (((iVar6 != 0) && (*(char *)(iVar6 + 0x2f8) != '\0')) && (*(char *)(iVar6 + 0x4c) != '\0')) {
    uVar5 = FUN_80017760(0xffffffe7,0x19);
    iVar6 = *piVar7;
    sVar4 = (ushort)*(byte *)(iVar6 + 0x2f9) + (short)*(char *)(iVar6 + 0x2fa) + (short)uVar5;
    if (sVar4 < 0) {
      sVar4 = 0;
      *(undefined *)(iVar6 + 0x2fa) = 0;
    }
    else if (0xff < sVar4) {
      sVar4 = 0xff;
      *(undefined *)(iVar6 + 0x2fa) = 0;
    }
    *(char *)(*piVar7 + 0x2f9) = (char)sVar4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b0fd4
 * EN v1.0 Address: 0x801B0FD4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B119C
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b0fd4(int param_1,int param_2)
{
}
