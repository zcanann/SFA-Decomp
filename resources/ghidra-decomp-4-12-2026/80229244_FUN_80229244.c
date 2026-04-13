// Function: FUN_80229244
// Entry: 80229244
// Size: 200 bytes

void FUN_80229244(int param_1)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0xb8);
  *pfVar1 = *pfVar1 - FLOAT_803dc074;
  if (*pfVar1 < FLOAT_803e7abc) {
    *pfVar1 = FLOAT_803e7abc;
  }
  if (*(char *)(pfVar1 + 1) == '\0') {
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      *(undefined *)(pfVar1 + 1) = 1;
    }
  }
  else if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    *(undefined *)(pfVar1 + 1) = 0;
  }
  return;
}

