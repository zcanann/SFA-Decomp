// Function: FUN_80231bf0
// Entry: 80231bf0
// Size: 184 bytes

void FUN_80231bf0(undefined2 *param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  uVar1 = FUN_80022264(0,0xffff);
  *param_1 = (short)uVar1;
  uVar1 = FUN_80022264(0,0xffff);
  param_1[1] = (short)uVar1;
  uVar1 = FUN_80022264(0,0xffff);
  param_1[2] = (short)uVar1;
  uVar1 = FUN_80022264(0xffffffec,0x14);
  *(short *)(iVar2 + 4) = (short)uVar1;
  uVar1 = FUN_80022264(0xffffffec,0x14);
  *(short *)(iVar2 + 6) = (short)uVar1;
  uVar1 = FUN_80022264(0xffffffec,0x14);
  *(short *)(iVar2 + 8) = (short)uVar1;
  return;
}

