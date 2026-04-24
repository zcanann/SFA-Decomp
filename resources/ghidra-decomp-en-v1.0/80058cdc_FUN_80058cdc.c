// Function: FUN_80058cdc
// Entry: 80058cdc
// Size: 96 bytes

void FUN_80058cdc(double param_1,double param_2,double param_3)

{
  uint uVar1;
  uint uVar2;
  
  if (((DAT_803dcde8 & 2) == 0) || ((DAT_803dcde8 & 0x800) != 0)) {
    FLOAT_803dce64 = (float)param_1;
    FLOAT_803dce60 = (float)param_2;
    FLOAT_803dce5c = (float)param_3;
    uVar2 = DAT_803dcde8 | 2;
    uVar1 = DAT_803dcde8 & 0x800;
    DAT_803dcde8 = uVar2;
    if (uVar1 != 0) {
      FUN_80058094();
    }
  }
  return;
}

