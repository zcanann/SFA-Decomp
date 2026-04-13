// Function: FUN_8017d62c
// Entry: 8017d62c
// Size: 420 bytes

void FUN_8017d62c(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((pbVar4[1] & 1) != 0) {
    uVar1 = (uint)*(short *)(iVar3 + (uint)*pbVar4 * 2 + 0x18);
    if (uVar1 != 0xffffffff) {
      FUN_800201ac(uVar1,1);
    }
    pbVar4[1] = pbVar4[1] & 0xfe;
    *pbVar4 = *pbVar4 + 1;
  }
  uVar1 = (uint)*pbVar4;
  if (uVar1 == 9) {
    (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,(int)*(short *)(iVar3 + 0x3c));
    (**(code **)(*DAT_803dd6d4 + 0x48))
              (*(undefined *)(iVar3 + 0x3a),param_1,*(undefined *)(iVar3 + 0x3b));
  }
  else {
    if (uVar1 < 9) {
      if (7 < uVar1) goto LAB_8017d768;
    }
    else if (uVar1 < 0xb) goto LAB_8017d768;
    uVar1 = (uint)*(short *)(iVar3 + uVar1 * 2 + 0x28);
    if (uVar1 == 0xffffffff) {
      *pbVar4 = 8;
    }
    else {
      uVar1 = FUN_80020078(uVar1);
      if ((uVar1 != 0) && (iVar2 = (int)*(char *)(iVar3 + (uint)*pbVar4 + 0x40), iVar2 != -1)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(iVar2,param_1,0xffffffff);
      }
    }
  }
LAB_8017d768:
  iVar2 = *pbVar4 - 1;
  iVar3 = iVar3 + iVar2 * 2;
  while (((-1 < iVar2 && ((int)*(short *)(iVar3 + 0x18) != 0xffffffff)) &&
         (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x18)), uVar1 == 0))) {
    *pbVar4 = *pbVar4 - 1;
    iVar3 = iVar3 + -2;
    iVar2 = iVar2 + -1;
  }
  return;
}

