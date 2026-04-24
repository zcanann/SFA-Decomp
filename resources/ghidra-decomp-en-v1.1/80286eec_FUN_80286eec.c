// Function: FUN_80286eec
// Entry: 80286eec
// Size: 52 bytes

undefined4 FUN_80286eec(undefined4 param_1,undefined4 param_2)

{
  if (DAT_803d7548 == 0) {
    DAT_803d7540 = param_1;
    DAT_803d7544 = param_2;
    DAT_803d7548 = 1;
    return 0;
  }
  return 0xffffffff;
}

