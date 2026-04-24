// Function: FUN_801b7708
// Entry: 801b7708
// Size: 348 bytes

void FUN_801b7708(int param_1,undefined4 param_2,float *param_3,float *param_4)

{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  if (pfVar3[4] == 0.0) {
    FUN_8000a538((int *)0xdf,1);
  }
  pfVar3[4] = 2.8026e-44;
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if (iVar2 == 0x49b23) {
    uVar1 = FUN_80020078(0xc5c);
    if ((uVar1 != 0) && (uVar1 = FUN_80020078(0xc5b), uVar1 == 0)) {
      *param_3 = *pfVar3;
      *param_4 = pfVar3[1];
    }
    uVar1 = FUN_80020078(0xc5b);
    if ((uVar1 != 0) && (uVar1 = FUN_80020078(0xc5c), uVar1 == 0)) {
      *param_3 = -*pfVar3;
      *param_4 = -pfVar3[1];
    }
    uVar1 = FUN_80020078(0xc5b);
    if (uVar1 != 0) {
      FUN_800201ac(0xc5c,0);
    }
    uVar1 = FUN_80020078(0xc5b);
    if (uVar1 == 0) {
      FUN_800201ac(0xc5c,1);
    }
  }
  else if ((iVar2 < 0x49b23) && (iVar2 == 0x1ea9)) {
    *param_3 = *pfVar3;
    *param_4 = pfVar3[1];
  }
  else {
    *param_3 = *pfVar3;
    *param_4 = pfVar3[1];
  }
  return;
}

