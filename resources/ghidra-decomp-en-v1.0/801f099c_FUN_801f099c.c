// Function: FUN_801f099c
// Entry: 801f099c
// Size: 164 bytes

void FUN_801f099c(int param_1)

{
  int iVar1;
  
  if ((((*(byte *)(param_1 + 0xaf) & 1) != 0) && (*(short *)(*(int *)(param_1 + 0xb8) + 6) == 2)) &&
     (iVar1 = FUN_8001ffb4(0x9ad), iVar1 == 0)) {
    (**(code **)(*DAT_803dca54 + 0x48))(4,param_1,0xffffffff);
    FUN_80014b3c(0,0x100);
    FUN_800200e8(0x9ad,1);
  }
  FUN_8002fa48((double)FLOAT_803e5d04,(double)FLOAT_803db414,param_1,0);
  return;
}

