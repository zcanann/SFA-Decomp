// Function: FUN_80003374
// Entry: 80003374
// Size: 52 bytes

void FUN_80003374(uint param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  
  uVar2 = param_1 & 0xfffffff1;
  iVar1 = param_2 + (param_1 - uVar2);
  do {
    dataCacheBlockStore(uVar2);
    sync(0);
    instructionCacheBlockInvalidate(uVar2);
    uVar2 = uVar2 + 8;
    iVar1 = iVar1 + -8;
  } while (-1 < iVar1);
  instructionSynchronize();
  return;
}

