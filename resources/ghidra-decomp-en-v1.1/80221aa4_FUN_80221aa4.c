// Function: FUN_80221aa4
// Entry: 80221aa4
// Size: 492 bytes

void FUN_80221aa4(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  float local_28;
  undefined auStack_24 [12];
  float local_18;
  float local_14;
  float local_10;
  
  iVar1 = FUN_8002bac4();
  local_28 = FLOAT_803e78a0;
  iVar2 = FUN_80297a08(iVar1);
  if (iVar2 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    if ('\0' < *(char *)(*(int *)(param_1 + 0x58) + 0x10f)) {
      iVar2 = 0;
      for (iVar3 = 0; iVar3 < *(char *)(*(int *)(param_1 + 0x58) + 0x10f); iVar3 = iVar3 + 1) {
        if (*(int *)(*(int *)(param_1 + 0x58) + iVar2 + 0x100) == iVar1) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        }
        iVar2 = iVar2 + 4;
      }
    }
    iVar1 = FUN_80036f50(10,param_1,&local_28);
    if (iVar1 == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
    if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
      FUN_8011f6d0(0x14);
    }
    iVar1 = FUN_8003811c(param_1);
    if (iVar1 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_1,0xffffffff);
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xe7;
    if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
      FUN_8011f6d0(0x15);
    }
    iVar1 = FUN_8003811c(param_1);
    if (iVar1 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    }
  }
  if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
    local_18 = FLOAT_803e78a4;
    local_14 = FLOAT_803e78a8;
    local_10 = FLOAT_803e78a4;
    FUN_800979c0((double)FLOAT_803e78ac,(double)FLOAT_803e78b0,(double)FLOAT_803e78b0,
                 (double)FLOAT_803e78b4,param_1,5,2,2,0xf,(int)auStack_24,0);
  }
  return;
}

