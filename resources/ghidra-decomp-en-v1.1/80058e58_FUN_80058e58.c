// Function: FUN_80058e58
// Entry: 80058e58
// Size: 96 bytes

void FUN_80058e58(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  uint uVar2;
  
  if (((DAT_803dda68 & 2) == 0) || ((DAT_803dda68 & 0x800) != 0)) {
    FLOAT_803ddae4 = (float)param_1;
    FLOAT_803ddae0 = (float)param_2;
    FLOAT_803ddadc = (float)param_3;
    uVar2 = DAT_803dda68 | 2;
    uVar1 = DAT_803dda68 & 0x800;
    DAT_803dda68 = uVar2;
    if (uVar1 != 0) {
      FUN_80058210(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  }
  return;
}

