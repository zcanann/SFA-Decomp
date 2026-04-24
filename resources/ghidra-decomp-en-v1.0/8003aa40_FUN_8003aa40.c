// Function: FUN_8003aa40
// Entry: 8003aa40
// Size: 160 bytes

void FUN_8003aa40(int param_1)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  
  uVar6 = 0;
  do {
    puVar2 = (undefined2 *)0x0;
    iVar3 = *(int *)(param_1 + 0x50);
    if (iVar3 != 0) {
      iVar4 = 0;
      iVar5 = 0;
      for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
        if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)(param_1 + 0xad) + iVar4 + 1) != -1) &&
           (uVar6 == *(byte *)(*(int *)(iVar3 + 0x10) + iVar4))) {
          puVar2 = (undefined2 *)(*(int *)(param_1 + 0x6c) + iVar5);
        }
        iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
        iVar5 = iVar5 + 0x12;
      }
    }
    if (puVar2 != (undefined2 *)0x0) {
      *puVar2 = 0;
      puVar2[1] = 0;
      puVar2[2] = 0;
    }
    uVar6 = uVar6 + 1;
  } while ((int)uVar6 < 0x16);
  return;
}

