// Function: FUN_80155cf8
// Entry: 80155cf8
// Size: 280 bytes

void FUN_80155cf8(undefined4 param_1,int param_2)

{
  bool bVar1;
  float local_18 [4];
  
  (**(code **)(*DAT_803dca58 + 0x14))(local_18);
  if ((local_18[0] < FLOAT_803e2a70) || (FLOAT_803e2a74 < local_18[0])) {
    bVar1 = false;
  }
  else {
    bVar1 = true;
  }
  if ((bVar1) && (*(char *)(param_2 + 0x33a) == '\0')) {
    *(undefined *)(param_2 + 0x33a) = 1;
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x10000;
    FUN_8014d08c((double)FLOAT_803e2a78,param_1,param_2,1,0,0);
  }
  else if ((!bVar1) && (*(char *)(param_2 + 0x33a) == '\x02')) {
    *(undefined *)(param_2 + 0x33a) = 1;
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x10000;
    FUN_8014d08c((double)FLOAT_803e2a78,param_1,param_2,3,0,0);
  }
  return;
}

