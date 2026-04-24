// Function: FUN_801b7154
// Entry: 801b7154
// Size: 348 bytes

void FUN_801b7154(int param_1,undefined4 param_2,float *param_3,float *param_4)

{
  int iVar1;
  float *pfVar2;
  
  pfVar2 = *(float **)(param_1 + 0xb8);
  if (pfVar2[4] == 0.0) {
    FUN_8000a518(0xdf,1);
  }
  pfVar2[4] = 2.802597e-44;
  iVar1 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if (iVar1 == 0x49b23) {
    iVar1 = FUN_8001ffb4(0xc5c);
    if ((iVar1 != 0) && (iVar1 = FUN_8001ffb4(0xc5b), iVar1 == 0)) {
      *param_3 = *pfVar2;
      *param_4 = pfVar2[1];
    }
    iVar1 = FUN_8001ffb4(0xc5b);
    if ((iVar1 != 0) && (iVar1 = FUN_8001ffb4(0xc5c), iVar1 == 0)) {
      *param_3 = -*pfVar2;
      *param_4 = -pfVar2[1];
    }
    iVar1 = FUN_8001ffb4(0xc5b);
    if (iVar1 != 0) {
      FUN_800200e8(0xc5c,0);
    }
    iVar1 = FUN_8001ffb4(0xc5b);
    if (iVar1 == 0) {
      FUN_800200e8(0xc5c,1);
    }
  }
  else if ((iVar1 < 0x49b23) && (iVar1 == 0x1ea9)) {
    *param_3 = *pfVar2;
    *param_4 = pfVar2[1];
  }
  else {
    *param_3 = *pfVar2;
    *param_4 = pfVar2[1];
  }
  return;
}

