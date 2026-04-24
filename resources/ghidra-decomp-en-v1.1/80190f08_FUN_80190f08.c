// Function: FUN_80190f08
// Entry: 80190f08
// Size: 584 bytes

void FUN_80190f08(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  uVar1 = (uint)*(short *)(iVar3 + 0x20);
  if (uVar1 != 0xffffffff) {
    uVar1 = FUN_80020078(uVar1);
    if (uVar1 == 0) {
      *(byte *)(iVar4 + 0xe) = *(byte *)(iVar4 + 0xe) | 0x80;
    }
    else {
      *(byte *)(iVar4 + 0xe) = *(byte *)(iVar4 + 0xe) & 0x7f;
    }
  }
  if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
    FUN_8011f6d0(0x1b);
    uVar1 = FUN_80020078(0x912);
    if (uVar1 == 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_1,0xffffffff);
      FUN_800201ac(0x912,1);
      return;
    }
  }
  iVar2 = FUN_8002bac4();
  if (iVar2 == 0) {
    return;
  }
  if (((*(char *)(iVar4 + 0xd) == '\0') && (*(char *)(iVar4 + 0xc) == '\0')) &&
     ((*(ushort *)(param_1 + 0xb0) & 0x1000) == 0)) {
    if (-1 < DAT_803ddb38) {
      iVar2 = FUN_8002bac4();
      dVar5 = (double)FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
      if (dVar5 < (double)FLOAT_803e4b78) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
        *(int *)(param_1 + 0xf4) = (int)*(short *)(iVar4 + 8);
        *(undefined *)(iVar4 + 0xd) = 0;
        *(undefined *)(iVar4 + 0xc) = 1;
        DAT_803dda60 = 2;
        goto LAB_801910d0;
      }
    }
    uVar1 = (uint)*(short *)(iVar3 + 0x20);
    if (((uVar1 == 0xffffffff) ||
        ((uVar1 = FUN_80020078(uVar1), uVar1 != 0 && ((*(byte *)(param_1 + 0xaf) & 4) != 0)))) &&
       (iVar3 = FUN_8003811c(param_1), iVar3 != 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      *(int *)(param_1 + 0xf4) = (int)*(short *)(iVar4 + 8);
      *(undefined *)(iVar4 + 0xd) = 1;
      *(undefined *)(iVar4 + 0xc) = 1;
    }
  }
LAB_801910d0:
  if (*(char *)(iVar4 + 0xc) != '\0') {
    if (*(int *)(param_1 + 0xf4) < 1) {
      *(undefined4 *)(param_1 + 0xf4) = 0;
      *(undefined *)(iVar4 + 0xc) = 0;
    }
    else {
      *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803dc070;
    }
  }
  *(float *)(iVar4 + 4) = *(float *)(iVar4 + 4) - FLOAT_803dc074;
  if (*(float *)(iVar4 + 4) <= FLOAT_803e4b30) {
    *(float *)(iVar4 + 4) = FLOAT_803e4b30;
    *(undefined2 *)(iVar4 + 10) = 0xffff;
  }
  return;
}

