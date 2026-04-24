// Function: FUN_80238bf0
// Entry: 80238bf0
// Size: 156 bytes

void FUN_80238bf0(int param_1,uint param_2)

{
  uint uVar1;
  float *pfVar2;
  undefined8 local_18;
  
  pfVar2 = *(float **)(param_1 + 0xb8);
  uVar1 = FUN_800803dc(pfVar2);
  if (uVar1 != 0) {
    local_18 = (double)CONCAT44(0x43300000,param_2 ^ 0x80000000);
    *pfVar2 = *pfVar2 + (float)(local_18 - DOUBLE_803e80a8);
    if (*(char *)(pfVar2 + 3) == '\x01') {
      FUN_800146e8(0x1d,(int)(*pfVar2 / FLOAT_803e80a0));
      FUN_800146c8();
    }
  }
  return;
}

