// Function: FUN_8017d280
// Entry: 8017d280
// Size: 376 bytes

void FUN_8017d280(int param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  
  pbVar6 = *(byte **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  if ((pbVar6[1] & 1) != 0) {
    uVar1 = countLeadingZeros((int)(uint)*(byte *)(iVar5 + 0x30) >> (*pbVar6 + 4 & 0x3f) & 1);
    FUN_800201ac((int)*(short *)(iVar5 + (uint)*pbVar6 * 2 + 0x18),uVar1 >> 5);
    pbVar6[1] = pbVar6[1] & 0xfe;
    *pbVar6 = *pbVar6 + 1;
  }
  if (*pbVar6 != 4) {
    uVar1 = (uint)*(short *)(iVar5 + (uint)*pbVar6 * 2 + 0x20);
    if (uVar1 == 0xffffffff) {
      *pbVar6 = 4;
    }
    else {
      uVar2 = FUN_80020078(uVar1);
      uVar1 = countLeadingZeros((int)(uint)*(byte *)(iVar5 + 0x30) >> (*pbVar6 & 0x3f) & 1);
      if ((uVar1 >> 5 == uVar2) &&
         (iVar3 = (int)*(char *)(iVar5 + (uint)*pbVar6 + 0x2c), iVar3 != -1)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(iVar3,param_1,0xffffffff);
      }
    }
  }
  iVar3 = *pbVar6 - 1;
  iVar4 = iVar5 + iVar3 * 2;
  while (((-1 < iVar3 && ((int)*(short *)(iVar4 + 0x18) != 0xffffffff)) &&
         (uVar1 = FUN_80020078((int)*(short *)(iVar4 + 0x18)),
         ((int)(uint)*(byte *)(iVar5 + 0x30) >> (iVar3 + 4U & 0x3f) & 1U) == uVar1))) {
    *pbVar6 = *pbVar6 - 1;
    iVar4 = iVar4 + -2;
    iVar3 = iVar3 + -1;
  }
  return;
}

