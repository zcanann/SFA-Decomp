// Function: FUN_800229f8
// Entry: 800229f8
// Size: 80 bytes

void FUN_800229f8(undefined4 param_1,undefined4 param_2,int param_3)

{
  if ((DAT_803dd610 == 4) || (DAT_803dd610 == 0)) {
    FUN_80241c68();
  }
  else {
    if (param_3 == 0) {
      param_3 = 0x1000;
    }
    else {
      param_3 = param_3 << 5;
    }
    FUN_80003494(param_1,param_2,param_3);
  }
  return;
}

