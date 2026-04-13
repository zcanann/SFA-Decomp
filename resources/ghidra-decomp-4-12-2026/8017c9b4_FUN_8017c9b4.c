// Function: FUN_8017c9b4
// Entry: 8017c9b4
// Size: 592 bytes

void FUN_8017c9b4(int param_1)

{
  uint uVar1;
  byte bVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if ((*pbVar4 & 4) != 0) {
    bVar2 = *(byte *)(iVar3 + 0x1d);
    if ((bVar2 & 1) == 0) {
      if ((bVar2 & 8) != 0) {
        FUN_800201ac((int)*(short *)(iVar3 + 0x18),1);
      }
      *pbVar4 = *pbVar4 | 1;
    }
    else if ((bVar2 & 4) == 0) {
      FUN_800201ac((int)*(short *)(iVar3 + 0x1a),0);
    }
    *pbVar4 = *pbVar4 & 0xfb;
  }
  if ((*pbVar4 & 1) == 0) {
    uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x18));
    if (uVar1 != 0) {
      *pbVar4 = *pbVar4 | 1;
    }
    uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x1a));
    bVar2 = (byte)uVar1;
    if ((bVar2 != pbVar4[1]) && (pbVar4[1] = bVar2, bVar2 != 0)) {
      if (*(char *)(iVar3 + 0x1e) != -1) {
        (**(code **)(*DAT_803dd6d4 + 0x84))(param_1,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 0x1e),param_1,0xffffffff);
      }
      if (((*(byte *)(iVar3 + 0x1d) & 1) == 0) && ((*(byte *)(iVar3 + 0x1d) & 10) == 0)) {
        FUN_800201ac((int)*(short *)(iVar3 + 0x18),1);
      }
    }
  }
  else if ((*pbVar4 & 2) == 0) {
    if (((*(byte *)(iVar3 + 0x1d) & 1) != 0) &&
       (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x18)), uVar1 == 0)) {
      *pbVar4 = *pbVar4 & 0xfe;
    }
  }
  else {
    (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,(int)*(short *)(iVar3 + 0x20));
    if ((*(byte *)(iVar3 + 0x1d) & 0x10) == 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 0x1e),param_1,1);
    }
    else {
      (**(code **)(*DAT_803dd6d4 + 0x48))
                ((int)*(char *)(iVar3 + 0x1e),param_1,*(undefined2 *)(iVar3 + 0x22));
    }
    *pbVar4 = *pbVar4 & 0xfd;
  }
  return;
}

