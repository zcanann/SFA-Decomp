// Function: FUN_80228b80
// Entry: 80228b80
// Size: 200 bytes

void FUN_80228b80(int param_1)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0xb8);
  *pfVar1 = *pfVar1 - FLOAT_803db414;
  if (*pfVar1 < FLOAT_803e6e24) {
    *pfVar1 = FLOAT_803e6e24;
  }
  if (*(char *)(pfVar1 + 1) == '\0') {
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      *(undefined *)(pfVar1 + 1) = 1;
    }
  }
  else if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
    *(undefined *)(pfVar1 + 1) = 0;
  }
  return;
}

