// Function: FUN_80003374
// Entry: 80003374
// Size: 52 bytes

void FUN_80003374(uint param_1,int param_2)

{
  uint uVar1;
  
  uVar1 = param_1 & 0xfffffff1;
  param_2 = param_2 + (param_1 - uVar1);
  do {
    dataCacheBlockStore(uVar1);
    sync(0);
    instructionCacheBlockInvalidate(uVar1);
    uVar1 = uVar1 + 8;
    param_2 = param_2 + -8;
  } while (-1 < param_2);
  instructionSynchronize();
  return;
}

