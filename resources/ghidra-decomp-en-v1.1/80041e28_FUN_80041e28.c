// Function: FUN_80041e28
// Entry: 80041e28
// Size: 104 bytes

void FUN_80041e28(int param_1,int *param_2)

{
  if (param_1 < 0) {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
  }
  else {
    FUN_802493c8(param_2);
    FUN_800241f8(DAT_803dd90c,param_2);
    DAT_803dd908 = DAT_803dd908 + -1;
  }
  return;
}

