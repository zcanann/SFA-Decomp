// Function: FUN_8003adf4
// Entry: 8003adf4
// Size: 200 bytes

void FUN_8003adf4(int param_1,uint *param_2,int param_3,int param_4)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
    puVar2 = (undefined2 *)0x0;
    iVar3 = *(int *)(param_1 + 0x50);
    if (iVar3 != 0) {
      iVar4 = 0;
      iVar5 = 0;
      for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
        if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)(param_1 + 0xad) + iVar4 + 1) != -1) &&
           (*param_2 == (uint)*(byte *)(*(int *)(iVar3 + 0x10) + iVar4))) {
          puVar2 = (undefined2 *)(*(int *)(param_1 + 0x6c) + iVar5);
        }
        iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
        iVar5 = iVar5 + 0x12;
      }
    }
    if (puVar2 != (undefined2 *)0x0) {
      *(undefined2 *)(param_4 + 0x16) = puVar2[1];
      *(undefined2 *)(param_4 + 0x46) = *puVar2;
    }
    param_2 = param_2 + 1;
    param_4 = param_4 + 0x60;
  }
  return;
}

