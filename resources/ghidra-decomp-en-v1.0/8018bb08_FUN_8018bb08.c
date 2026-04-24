// Function: FUN_8018bb08
// Entry: 8018bb08
// Size: 252 bytes

void FUN_8018bb08(int param_1)

{
  int iVar1;
  char cVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  FUN_8002b9ec();
  if (*(char *)(pfVar3 + 1) == '\0') {
    iVar1 = FUN_80295cd4();
    if (iVar1 != 0) {
      *(undefined *)(pfVar3 + 1) = 1;
    }
  }
  else {
    iVar1 = FUN_80295cd4();
    if (iVar1 == 0) {
      *(undefined *)(pfVar3 + 1) = 0;
    }
  }
  FUN_8002b660(param_1,*(undefined *)(pfVar3 + 1));
  FUN_8002b884(param_1,*(undefined *)(pfVar3 + 1));
  iVar1 = FUN_80038024(param_1);
  if ((iVar1 != 0) && (cVar2 = FUN_801334e0(), cVar2 == '\0')) {
    *pfVar3 = FLOAT_803e3c88;
  }
  if (FLOAT_803e3c8c < *pfVar3) {
    if ((*(byte *)(param_1 + 0xaf) & 4) == 0) {
      *pfVar3 = FLOAT_803e3c8c;
    }
    else {
      *pfVar3 = *pfVar3 - FLOAT_803db414;
      FUN_8012ef30((int)*(short *)(*(int *)(param_1 + 0x50) + (uint)*(byte *)(pfVar3 + 1) * 2 + 0x7c
                                  ));
    }
  }
  return;
}

