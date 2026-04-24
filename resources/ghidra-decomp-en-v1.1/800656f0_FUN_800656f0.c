// Function: FUN_800656f0
// Entry: 800656f0
// Size: 144 bytes

void FUN_800656f0(int param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  if (param_2 == 0) {
    uVar1 = (uint)DAT_803ddbde;
    iVar2 = DAT_803ddbb4;
  }
  else {
    uVar1 = (uint)*(byte *)(*(int *)(param_2 + 0x50) + 0x5c);
    iVar2 = *(int *)(*(int *)(param_2 + 0x50) + 0x34);
  }
  if (param_3 != 0) {
    if ((int)uVar1 < 1) {
      return;
    }
    do {
      if (*(short *)(iVar2 + 0xc) == param_1) {
        *(byte *)(iVar2 + 3) = *(byte *)(iVar2 + 3) & 0xbf;
      }
      iVar2 = iVar2 + 0x10;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
    return;
  }
  if ((int)uVar1 < 1) {
    return;
  }
  do {
    if (*(short *)(iVar2 + 0xc) == param_1) {
      *(byte *)(iVar2 + 3) = *(byte *)(iVar2 + 3) | 0x40;
    }
    iVar2 = iVar2 + 0x10;
    uVar1 = uVar1 - 1;
  } while (uVar1 != 0);
  return;
}

