// Function: FUN_80286788
// Entry: 80286788
// Size: 52 bytes

undefined4 FUN_80286788(undefined4 param_1,undefined4 param_2)

{
  if (DAT_803d68e8 == 0) {
    DAT_803d68e0 = param_1;
    DAT_803d68e4 = param_2;
    DAT_803d68e8 = 1;
    return 0;
  }
  return 0xffffffff;
}

