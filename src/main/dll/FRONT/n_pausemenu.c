#include "ghidra_import.h"
#include "main/dll/FRONT/n_pausemenu.h"

extern int FUN_800284e8();
extern undefined4 FUN_8004c928();
extern undefined4 FUN_80117910();
extern ushort FUN_8024df24();
extern int FUN_8024e064();
extern undefined8 FUN_80286990();

extern undefined4 DAT_803a6a0c;
extern undefined4 DAT_803a6a40;
extern undefined4 DAT_803a6a44;
extern undefined4 DAT_803a6a5e;
extern undefined4 DAT_803a6a80;
extern undefined4 DAT_803a6a84;
extern undefined4 DAT_803a6a88;
extern undefined4 DAT_803a6a8c;
extern undefined4* DAT_803a6aac;
extern undefined4 DAT_803de288;
extern f32 FLOAT_803e29d0;

/*
 * --INFO--
 *
 * Function: FUN_801184e8
 * EN v1.0 Address: 0x8011846C
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801184E8
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801184e8(void)
{
  if (DAT_803de288 == 2) {
    FUN_8004c928(*DAT_803a6aac,DAT_803a6aac[1],DAT_803a6aac[2],(int)(short)DAT_803a6a40,
                 (int)(short)DAT_803a6a44);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011853c
 * EN v1.0 Address: 0x801184B8
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x8011853C
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8011853c(undefined4 param_1,int *param_2,int param_3)
{
  int iVar1;
  undefined4 uVar2;
  
  if (param_2 == (int *)0x0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_800284e8(*param_2,param_3);
  }
  if (((iVar1 == 0) || (*(char *)(iVar1 + 0x29) == '\x01')) && (DAT_803de288 == 2)) {
    FUN_80117910(*DAT_803a6aac,DAT_803a6aac[1],DAT_803a6aac[2],(int)(short)DAT_803a6a40,
                 (int)(short)DAT_803a6a44);
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801185cc
 * EN v1.0 Address: 0x80118540
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x801185CC
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801185cc(void)
{
  uint uVar1;
  ushort uVar3;
  int iVar2;
  undefined8 uVar4;
  
  if ((DAT_803a6a5e & 2) == 0) {
    if ((DAT_803a6a5e & 4) == 0) {
      uVar1 = (uint)(FLOAT_803e29d0 * DAT_803a6a0c);
      iVar2 = FUN_8024e064();
      if (iVar2 == 1) {
        uVar4 = FUN_80286990((int)((ulonglong)DAT_803a6a84 * (ulonglong)uVar1 >> 0x20) +
                             DAT_803a6a80 * uVar1 + DAT_803a6a84 * ((int)uVar1 >> 0x1f),
                             DAT_803a6a84 * uVar1,0,5000);
        DAT_803a6a8c = (int)uVar4;
      }
      else {
        uVar4 = FUN_80286990((int)((ulonglong)DAT_803a6a84 * (ulonglong)uVar1 >> 0x20) +
                             DAT_803a6a80 * uVar1 + DAT_803a6a84 * ((int)uVar1 >> 0x1f),
                             DAT_803a6a84 * uVar1,0,0x176a);
        DAT_803a6a8c = (int)uVar4;
      }
      if (DAT_803a6a88 != DAT_803a6a8c) {
        DAT_803a6a88 = DAT_803a6a8c;
        return 1;
      }
    }
    else {
      uVar3 = FUN_8024df24();
      if (uVar3 == 1) {
        return 1;
      }
    }
  }
  else {
    uVar3 = FUN_8024df24();
    if (uVar3 == 0) {
      return 1;
    }
  }
  return 0;
}
