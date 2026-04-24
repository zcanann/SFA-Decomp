// Function: FUN_8017ce10
// Entry: 8017ce10
// Size: 596 bytes

void FUN_8017ce10(int param_1)

{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if ((*pbVar3 & 1) == 0) {
    if ((*pbVar3 & 2) == 0) {
      if ((((int)*(short *)(iVar2 + 0x1a) == 0xffffffff) ||
          (uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1a)), uVar1 != 0)) &&
         (((int)*(short *)(iVar2 + 0x18) == 0xffffffff ||
          (uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x18)), uVar1 == 0)))) {
        if ((*(byte *)(iVar2 + 0x1d) & 4) != 0) {
          FUN_800201ac((int)*(short *)(iVar2 + 0x1a),0);
          FUN_8007d858();
        }
        if ((*(byte *)(iVar2 + 0x1d) & 0x20) != 0) {
          FUN_800201ac((int)*(short *)(iVar2 + 0x18),1);
          FUN_8007d858();
        }
        FUN_8007d858();
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar2 + 0x1e),param_1,0xffffffff);
      }
    }
    else {
      if ((*(byte *)(iVar2 + 0x1d) & 2) != 0) {
        FUN_800201ac((int)*(short *)(iVar2 + 0x1a),0);
        FUN_8007d858();
      }
      if ((*(byte *)(iVar2 + 0x1d) & 0x10) != 0) {
        FUN_800201ac((int)*(short *)(iVar2 + 0x18),1);
        FUN_8007d858();
      }
      *pbVar3 = *pbVar3 & 0xfd;
    }
  }
  else {
    if ((*(byte *)(iVar2 + 0x1d) & 1) != 0) {
      FUN_800201ac((int)*(short *)(iVar2 + 0x1a),0);
      FUN_8007d858();
    }
    if ((*(byte *)(iVar2 + 0x1d) & 8) != 0) {
      FUN_800201ac((int)*(short *)(iVar2 + 0x18),1);
      FUN_8007d858();
    }
    FUN_8007d858();
    (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,(int)*(short *)(iVar2 + 0x20));
    (**(code **)(*DAT_803dd6d4 + 0x48))
              ((int)*(char *)(iVar2 + 0x1e),param_1,*(undefined2 *)(iVar2 + 0x22));
    *pbVar3 = *pbVar3 & 0xfe;
  }
  return;
}

