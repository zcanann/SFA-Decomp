// Function: FUN_8017d0d4
// Entry: 8017d0d4
// Size: 420 bytes

void FUN_8017d0d4(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  byte *pbVar5;
  
  pbVar5 = *(byte **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((pbVar5[1] & 1) != 0) {
    iVar2 = (int)*(short *)(iVar4 + (uint)*pbVar5 * 2 + 0x18);
    if (iVar2 != -1) {
      FUN_800200e8(iVar2,1);
    }
    pbVar5[1] = pbVar5[1] & 0xfe;
    *pbVar5 = *pbVar5 + 1;
  }
  uVar1 = (uint)*pbVar5;
  if (uVar1 == 9) {
    (**(code **)(*DAT_803dca54 + 0x54))(param_1,(int)*(short *)(iVar4 + 0x3c));
    (**(code **)(*DAT_803dca54 + 0x48))
              (*(undefined *)(iVar4 + 0x3a),param_1,*(undefined *)(iVar4 + 0x3b));
  }
  else {
    if (uVar1 < 9) {
      if (7 < uVar1) goto LAB_8017d210;
    }
    else if (uVar1 < 0xb) goto LAB_8017d210;
    if (*(short *)(iVar4 + uVar1 * 2 + 0x28) == -1) {
      *pbVar5 = 8;
    }
    else {
      iVar2 = FUN_8001ffb4();
      if ((iVar2 != 0) && (iVar2 = (int)*(char *)(iVar4 + (uint)*pbVar5 + 0x40), iVar2 != -1)) {
        (**(code **)(*DAT_803dca54 + 0x48))(iVar2,param_1,0xffffffff);
      }
    }
  }
LAB_8017d210:
  iVar2 = *pbVar5 - 1;
  iVar4 = iVar4 + iVar2 * 2;
  while (((-1 < iVar2 && (*(short *)(iVar4 + 0x18) != -1)) && (iVar3 = FUN_8001ffb4(), iVar3 == 0)))
  {
    *pbVar5 = *pbVar5 - 1;
    iVar4 = iVar4 + -2;
    iVar2 = iVar2 + -1;
  }
  return;
}

