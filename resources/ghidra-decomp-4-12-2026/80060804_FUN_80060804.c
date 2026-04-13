// Function: FUN_80060804
// Entry: 80060804
// Size: 84 bytes

int FUN_80060804(int param_1,uint param_2)

{
  uint uVar1;
  ushort *puVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 0;
  iVar3 = 0;
  for (uVar1 = (uint)*(ushort *)(param_1 + 0x9a); uVar1 != 0; uVar1 = uVar1 - 1) {
    puVar2 = (ushort *)(*(int *)(param_1 + 0x50) + iVar3);
    if (param_2 == *(uint *)(puVar2 + 8) >> 0x18) {
      iVar4 = iVar4 + ((uint)puVar2[10] - (uint)*puVar2);
    }
    iVar3 = iVar3 + 0x14;
  }
  return iVar4;
}

