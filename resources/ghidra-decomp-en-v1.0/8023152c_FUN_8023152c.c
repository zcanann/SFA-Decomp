// Function: FUN_8023152c
// Entry: 8023152c
// Size: 184 bytes

void FUN_8023152c(undefined2 *param_1)

{
  undefined2 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  uVar1 = FUN_800221a0(0,0xffff);
  *param_1 = uVar1;
  uVar1 = FUN_800221a0(0,0xffff);
  param_1[1] = uVar1;
  uVar1 = FUN_800221a0(0,0xffff);
  param_1[2] = uVar1;
  uVar1 = FUN_800221a0(0xffffffec,0x14);
  *(undefined2 *)(iVar2 + 4) = uVar1;
  uVar1 = FUN_800221a0(0xffffffec,0x14);
  *(undefined2 *)(iVar2 + 6) = uVar1;
  uVar1 = FUN_800221a0(0xffffffec,0x14);
  *(undefined2 *)(iVar2 + 8) = uVar1;
  return;
}

