// Function: FUN_8021f5ac
// Entry: 8021f5ac
// Size: 424 bytes

void FUN_8021f5ac(int param_1)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if (((*(byte *)(iVar4 + 0x19b) >> 3 & 1) == 0) && (iVar2 = FUN_8001ffb4(0x9b9), iVar2 != 0)) {
    *(byte *)(iVar4 + 0x19b) = *(byte *)(iVar4 + 0x19b) & 0xf7 | 8;
  }
  if ((*(byte *)(iVar4 + 0x19b) >> 3 & 1) == 0) {
    if (((*(byte *)(iVar4 + 0x19b) >> 4 & 1) == 0) &&
       (iVar2 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x20)), iVar2 == 0)) {
      if (*(short *)(param_1 + 0x46) != 0x72e) {
        (**(code **)(*DAT_803dca54 + 0x48))(4,param_1,0xffffffff);
      }
      *(byte *)(iVar4 + 0x19b) = *(byte *)(iVar4 + 0x19b) & 0xef | 0x10;
      *(byte *)(iVar4 + 0x19b) = *(byte *)(iVar4 + 0x19b) & 0x7f;
      FUN_80035f00(param_1);
      return;
    }
    if (((*(byte *)(iVar4 + 0x19b) >> 4 & 1) != 0) &&
       (iVar3 = FUN_8001ffb4((int)*(short *)(iVar3 + 0x20)), iVar3 != 0)) {
      if (*(short *)(param_1 + 0x46) != 0x72e) {
        (**(code **)(*DAT_803dca54 + 0x48))(3,param_1,0xffffffff);
      }
      *(byte *)(iVar4 + 0x19b) = *(byte *)(iVar4 + 0x19b) & 0xef;
      FUN_80035f20(param_1);
      return;
    }
  }
  if (*(char *)(iVar4 + 0x19b) < '\0') {
    iVar3 = 1;
    do {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x690,0,1,0xffffffff,0);
      bVar1 = iVar3 != 0;
      iVar3 = iVar3 + -1;
    } while (bVar1);
  }
  return;
}

