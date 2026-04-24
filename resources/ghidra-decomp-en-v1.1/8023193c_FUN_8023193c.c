// Function: FUN_8023193c
// Entry: 8023193c
// Size: 204 bytes

void FUN_8023193c(undefined2 *param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined *)(param_1 + 0x1b) = 0;
  uVar1 = FUN_80022264(0,0xffff);
  *param_1 = (short)uVar1;
  uVar1 = FUN_80022264(0,0xffff);
  param_1[1] = (short)uVar1;
  uVar1 = FUN_80022264(0,0xffff);
  param_1[2] = (short)uVar1;
  uVar1 = FUN_80022264(0xffffffce,0x32);
  *(short *)(iVar2 + 4) = (short)uVar1;
  uVar1 = FUN_80022264(0xffffffce,0x32);
  *(short *)(iVar2 + 6) = (short)uVar1;
  uVar1 = FUN_80022264(0xffffffce,0x32);
  *(short *)(iVar2 + 8) = (short)uVar1;
  DAT_803dea10 = DAT_803dea10 + 1;
  return;
}

