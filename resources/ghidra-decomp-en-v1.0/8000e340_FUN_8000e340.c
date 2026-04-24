// Function: FUN_8000e340
// Entry: 8000e340
// Size: 64 bytes

int FUN_8000e340(undefined4 param_1)

{
  FUN_8000e180(param_1,(int)DAT_803dc888);
  DAT_803dc888 = DAT_803dc888 + '\x01';
  return DAT_803dc888 + -1;
}

