// Function: FUN_801b82d0
// Entry: 801b82d0
// Size: 164 bytes

void FUN_801b82d0(undefined2 *param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined4 *)(iVar3 + 0xa0) = *(undefined4 *)(param_2 + 0x14);
  *(byte *)(iVar3 + 0xac) = *(byte *)(iVar3 + 0xac) | 4;
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined *)(param_1 + 0x1b) = 0;
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0xa10;
  }
  uVar2 = FUN_8002e0b4(*(undefined4 *)(iVar3 + 0xa0));
  *(undefined4 *)(iVar3 + 0x9c) = uVar2;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

