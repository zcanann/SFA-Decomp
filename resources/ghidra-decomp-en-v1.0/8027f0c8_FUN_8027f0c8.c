// Function: FUN_8027f0c8
// Entry: 8027f0c8
// Size: 132 bytes

undefined4 FUN_8027f0c8(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = (uint)*(byte *)(param_1 + 0x52);
  iVar3 = 0;
  iVar2 = param_1;
  while( true ) {
    if (uVar1 == 0) {
      return 0;
    }
    if (*(int *)(iVar2 + 0x60) == param_2) break;
    iVar2 = iVar2 + 0xc;
    iVar3 = iVar3 + 1;
    uVar1 = uVar1 - 1;
  }
  iVar2 = param_1 + iVar3 * 0xc;
  for (; iVar3 <= (int)(*(byte *)(param_1 + 0x52) - 2); iVar3 = iVar3 + 1) {
    *(undefined4 *)(iVar2 + 0x58) = *(undefined4 *)(iVar2 + 100);
    *(undefined4 *)(iVar2 + 0x5c) = *(undefined4 *)(iVar2 + 0x68);
    *(undefined4 *)(iVar2 + 0x60) = *(undefined4 *)(iVar2 + 0x6c);
    iVar2 = iVar2 + 0xc;
  }
  *(byte *)(param_1 + 0x52) = *(byte *)(param_1 + 0x52) - 1;
  return 1;
}

