// Function: FUN_801887ac
// Entry: 801887ac
// Size: 292 bytes

void FUN_801887ac(int param_1)

{
  uint uVar1;
  float fVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  uVar1 = FUN_80020078(0x1bf);
  if ((uVar1 == 0) || (uVar1 = FUN_80020078(0x1bd), uVar1 != 0)) {
    if (pfVar3[1] == 0.0) {
      fVar2 = (float)FUN_8002bac4();
      pfVar3[1] = fVar2;
    }
    else {
      uVar1 = FUN_802963a0((int)pfVar3[1]);
      if (uVar1 == 0) {
        *pfVar3 = FLOAT_803e4800;
      }
      else {
        if (FLOAT_803e4800 == *pfVar3) {
          FUN_80036548((int)pfVar3[1],param_1,'\x1c',0,1);
        }
        *pfVar3 = *pfVar3 + FLOAT_803dc074;
        if (FLOAT_803e4804 < *pfVar3) {
          FUN_80036548((int)pfVar3[1],param_1,'\x1c',1,1);
          *pfVar3 = *pfVar3 - FLOAT_803e4804;
        }
      }
    }
  }
  else {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    FUN_800201ac(0x1bd,1);
  }
  return;
}

