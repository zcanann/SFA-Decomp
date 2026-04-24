#include "ghidra_import.h"
#include "main/dll/LGT/LGTpointlight.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000dbb0();
extern undefined4 FUN_8000dcdc();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern undefined4 FUN_8001f448();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern int FUN_80036974();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80060630();
extern undefined4 FUN_80098da4();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();

extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e6a98;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e6a84;
extern f32 FLOAT_803e6a88;
extern f32 FLOAT_803e6a8c;
extern f32 FLOAT_803e6a90;
extern f32 FLOAT_803e6aa0;
extern f32 FLOAT_803e6aa4;
extern f32 FLOAT_803e6aa8;
extern f32 FLOAT_803e6aac;
extern f32 FLOAT_803e6ab4;

/*
 * --INFO--
 *
 * Function: FUN_801f3824
 * EN v1.0 Address: 0x801F37CC
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801F3824
 * EN v1.1 Size: 472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f3824(int param_1,int param_2)
{
  int iVar1;
  int *piVar2;
  undefined auStack_28 [16];
  float local_18;
  undefined4 local_10;
  uint uStack_c;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((int)*(short *)(param_2 + 0x1a) == 0) {
    *(float *)(iVar1 + 4) = FLOAT_803e6a84;
  }
  else {
    uStack_c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
    local_10 = 0x43300000;
    *(float *)(iVar1 + 4) = (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e6a98);
  }
  if (*(short *)(param_2 + 0x1c) == 0) {
    *(undefined2 *)(iVar1 + 10) = 0x8c;
  }
  else {
    *(short *)(iVar1 + 10) = *(short *)(param_2 + 0x1c);
  }
  *(undefined *)(iVar1 + 0xc) = *(undefined *)(param_2 + 0x19);
  local_18 = FLOAT_803e6a88;
  if (*(char *)(iVar1 + 0xc) == '\0') {
    piVar2 = (int *)FUN_80013ee8(0x69);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e6a8c;
    (**(code **)(*piVar2 + 4))(param_1,1,auStack_28,0x10004,0xffffffff,0);
  }
  else if (*(char *)(iVar1 + 0xc) == '\x7f') {
    piVar2 = (int *)FUN_80013ee8(0x69);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e6a8c;
    (**(code **)(*piVar2 + 4))(param_1,2,auStack_28,0x10004,0xffffffff,0);
  }
  else {
    piVar2 = (int *)FUN_80013ee8(99);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e6a8c;
    (**(code **)(*piVar2 + 4))(param_1,2,auStack_28,0x10004,0xffffffff,0);
  }
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e6a90;
  FUN_80013e4c((undefined *)piVar2);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f39fc
 * EN v1.0 Address: 0x801F398C
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x801F39FC
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f39fc(int param_1)
{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  if (*puVar1 != 0) {
    FUN_8001f448(*puVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f3a48
 * EN v1.0 Address: 0x801F39DC
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x801F3A48
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f3a48(void)
{
  int iVar1;
  int iVar2;
  char in_r8;
  
  iVar1 = FUN_8028683c();
  iVar2 = **(int **)(iVar1 + 0xb8);
  if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0')) {
    FUN_80060630(iVar2);
  }
  if (in_r8 != '\0') {
    FUN_8003b9ec(iVar1);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f3ae4
 * EN v1.0 Address: 0x801F3A50
 * EN v1.0 Size: 908b
 * EN v1.1 Address: 0x801F3AE4
 * EN v1.1 Size: 800b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f3ae4(uint param_1)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  float local_38;
  float local_34;
  float local_30;
  undefined auStack_2c [8];
  float local_24;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  if (*(char *)(piVar4 + 5) == '\x01') {
    *(undefined *)(piVar4 + 6) = *(undefined *)((int)piVar4 + 0x17);
    iVar2 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if (iVar2 != 0) {
      *(char *)((int)piVar4 + 0x17) = '\x01' - *(char *)((int)piVar4 + 0x17);
    }
    if (*(char *)((int)piVar4 + 0x17) != *(char *)(piVar4 + 6)) {
      if (*(char *)((int)piVar4 + 0x17) == '\0') {
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
        if ((piVar4[4] != 0xffffffff) && (uVar3 = FUN_80020078(piVar4[4]), uVar3 != 0)) {
          FUN_800201ac(piVar4[4],0);
        }
      }
      else {
        if ((piVar4[4] != 0xffffffff) && (uVar3 = FUN_80020078(piVar4[4]), uVar3 == 0)) {
          FUN_800201ac(piVar4[4],1);
        }
        FUN_8000bb38(param_1,0x80);
      }
    }
  }
  if ((*(char *)((int)piVar4 + 0x17) != '\0') && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    piVar4[1] = (int)((float)piVar4[1] - FLOAT_803dc074);
    if (FLOAT_803e6aa4 < (float)piVar4[1]) {
      uVar3 = 0;
    }
    else {
      uVar3 = (uint)*(byte *)((int)piVar4 + 0x16);
      piVar4[1] = (int)((float)piVar4[1] + FLOAT_803e6aa8);
    }
    if ((*(char *)((int)piVar4 + 0x15) != '\0') || (*(char *)((int)piVar4 + 0x16) != '\0')) {
      local_38 = FLOAT_803e6aa4;
      if (*(short *)(param_1 + 0x46) == 0x717) {
        local_34 = FLOAT_803e6aa4;
      }
      else {
        local_34 = FLOAT_803e6aac;
      }
      local_30 = FLOAT_803e6aa4;
      FUN_80098da4(param_1,(uint)*(byte *)((int)piVar4 + 0x15),uVar3,0,&local_38);
    }
    if ((*(char *)((int)piVar4 + 0x19) != '\0') &&
       (piVar4[3] = (int)((float)piVar4[3] - FLOAT_803dc074), (float)piVar4[3] <= FLOAT_803e6aa4)) {
      local_24 = FLOAT_803e6aa0;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7cb,auStack_2c,2,0xffffffff,0);
      piVar4[3] = (int)((float)piVar4[3] + FLOAT_803e6ab4);
    }
  }
  iVar2 = *piVar4;
  if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0')) {
    sVar1 = (ushort)*(byte *)(iVar2 + 0x2f9) + (short)*(char *)(iVar2 + 0x2fa);
    if (sVar1 < 0) {
      sVar1 = 0;
      *(undefined *)(iVar2 + 0x2fa) = 0;
    }
    else if (0xff < sVar1) {
      sVar1 = 0xff;
      *(undefined *)(iVar2 + 0x2fa) = 0;
    }
    *(char *)(*piVar4 + 0x2f9) = (char)sVar1;
  }
  if ((*(short *)(param_1 + 0x46) != 0x705) && (*(short *)(param_1 + 0x46) != 0x712)) {
    if (*(char *)((int)piVar4 + 0x17) == '\0') {
      if (*(char *)((int)piVar4 + 0x1a) < '\0') {
        FUN_8000dbb0();
        *(byte *)((int)piVar4 + 0x1a) = *(byte *)((int)piVar4 + 0x1a) & 0x7f;
      }
    }
    else if (-1 < *(char *)((int)piVar4 + 0x1a)) {
      FUN_8000dcdc(param_1,0x72);
      *(byte *)((int)piVar4 + 0x1a) = *(byte *)((int)piVar4 + 0x1a) & 0x7f | 0x80;
    }
  }
  return;
}
