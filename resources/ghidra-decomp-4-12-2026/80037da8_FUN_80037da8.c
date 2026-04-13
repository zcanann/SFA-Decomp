// Function: FUN_80037da8
// Entry: 80037da8
// Size: 124 bytes

void FUN_80037da8(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 0;
  uVar1 = (uint)*(byte *)(param_1 + 0xeb);
  for (iVar3 = param_1; (uVar1 != 0 && (*(int *)(iVar3 + 200) != param_2)); iVar3 = iVar3 + 4) {
    iVar4 = iVar4 + 1;
    uVar1 = uVar1 - 1;
  }
  iVar3 = param_1 + iVar4 * 4;
  for (; iVar2 = *(byte *)(param_1 + 0xeb) - 1, iVar4 < iVar2; iVar4 = iVar4 + 1) {
    *(undefined4 *)(iVar3 + 200) = *(undefined4 *)(iVar3 + 0xcc);
    iVar3 = iVar3 + 4;
  }
  *(char *)(param_1 + 0xeb) = (char)iVar2;
  *(undefined4 *)(param_1 + (uint)*(byte *)(param_1 + 0xeb) * 4 + 200) = 0;
  *(undefined4 *)(param_2 + 0xc4) = 0;
  return;
}

