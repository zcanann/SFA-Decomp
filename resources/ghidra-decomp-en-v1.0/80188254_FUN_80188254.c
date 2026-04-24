// Function: FUN_80188254
// Entry: 80188254
// Size: 292 bytes

void FUN_80188254(int param_1)

{
  int iVar1;
  float fVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  iVar1 = FUN_8001ffb4(0x1bf);
  if ((iVar1 == 0) || (iVar1 = FUN_8001ffb4(0x1bd), iVar1 != 0)) {
    if (pfVar3[1] == 0.0) {
      fVar2 = (float)FUN_8002b9ec();
      pfVar3[1] = fVar2;
    }
    else {
      iVar1 = FUN_80295c40();
      if (iVar1 == 0) {
        *pfVar3 = FLOAT_803e3b68;
      }
      else {
        if (FLOAT_803e3b68 == *pfVar3) {
          FUN_80036450(pfVar3[1],param_1,0x1c,0,1);
        }
        *pfVar3 = *pfVar3 + FLOAT_803db414;
        if (FLOAT_803e3b6c < *pfVar3) {
          FUN_80036450(pfVar3[1],param_1,0x1c,1,1);
          *pfVar3 = *pfVar3 - FLOAT_803e3b6c;
        }
      }
    }
  }
  else {
    (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    FUN_800200e8(0x1bd,1);
  }
  return;
}

