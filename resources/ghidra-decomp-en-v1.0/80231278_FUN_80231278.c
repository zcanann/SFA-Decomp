// Function: FUN_80231278
// Entry: 80231278
// Size: 204 bytes

void FUN_80231278(undefined2 *param_1)

{
  undefined2 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined *)(param_1 + 0x1b) = 0;
  uVar1 = FUN_800221a0(0,0xffff);
  *param_1 = uVar1;
  uVar1 = FUN_800221a0(0,0xffff);
  param_1[1] = uVar1;
  uVar1 = FUN_800221a0(0,0xffff);
  param_1[2] = uVar1;
  uVar1 = FUN_800221a0(0xffffffce,0x32);
  *(undefined2 *)(iVar2 + 4) = uVar1;
  uVar1 = FUN_800221a0(0xffffffce,0x32);
  *(undefined2 *)(iVar2 + 6) = uVar1;
  uVar1 = FUN_800221a0(0xffffffce,0x32);
  *(undefined2 *)(iVar2 + 8) = uVar1;
  DAT_803ddd90 = DAT_803ddd90 + 1;
  return;
}

