// Function: FUN_801b8884
// Entry: 801b8884
// Size: 164 bytes

void FUN_801b8884(undefined2 *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined4 *)(iVar2 + 0xa0) = *(undefined4 *)(param_2 + 0x14);
  *(byte *)(iVar2 + 0xac) = *(byte *)(iVar2 + 0xac) | 4;
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined *)(param_1 + 0x1b) = 0;
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0xa10;
  }
  iVar1 = FUN_8002e1ac(*(int *)(iVar2 + 0xa0));
  *(int *)(iVar2 + 0x9c) = iVar1;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

