// Function: FUN_80013ce8
// Entry: 80013ce8
// Size: 140 bytes

void FUN_80013ce8(short **param_1,short param_2,undefined4 param_3)

{
  short *psVar1;
  
  for (psVar1 = *param_1; (psVar1 < param_1[1] && (*psVar1 != -1));
      psVar1 = psVar1 + *(byte *)((int)param_1 + 0xd)) {
  }
  *psVar1 = param_2;
  FUN_80003494(psVar1 + 1,param_3,*(undefined *)(param_1 + 3));
  if (psVar1 == param_1[1]) {
    param_1[1] = param_1[1] + *(byte *)((int)param_1 + 0xd);
  }
  return;
}

