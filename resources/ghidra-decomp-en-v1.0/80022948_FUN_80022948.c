// Function: FUN_80022948
// Entry: 80022948
// Size: 124 bytes

void FUN_80022948(undefined4 param_1,undefined4 param_2,int param_3)

{
  if ((DAT_803dd610 == 4) || (DAT_803dd610 == 0)) {
    FUN_80241c8c(param_1);
  }
  else {
    if (param_3 == 0) {
      param_3 = 0x1000;
    }
    else {
      param_3 = param_3 << 5;
    }
    FUN_80003494(param_1,param_2,param_3);
    FUN_802419e8(param_1,param_3);
  }
  return;
}

