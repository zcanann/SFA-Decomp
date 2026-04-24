// Function: FUN_8023852c
// Entry: 8023852c
// Size: 156 bytes

void FUN_8023852c(int param_1,uint param_2)

{
  int iVar1;
  float *pfVar2;
  double local_18;
  
  pfVar2 = *(float **)(param_1 + 0xb8);
  iVar1 = FUN_80080150(pfVar2);
  if (iVar1 != 0) {
    local_18 = (double)CONCAT44(0x43300000,param_2 ^ 0x80000000);
    *pfVar2 = *pfVar2 + (float)(local_18 - DOUBLE_803e7410);
    if (*(char *)(pfVar2 + 3) == '\x01') {
      FUN_800146bc(0x1d,(int)(*pfVar2 / FLOAT_803e7408));
      FUN_8001469c();
    }
  }
  return;
}

