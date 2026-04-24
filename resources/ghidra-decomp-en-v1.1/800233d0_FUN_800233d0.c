// Function: FUN_800233d0
// Entry: 800233d0
// Size: 220 bytes

void FUN_800233d0(undefined4 param_1)

{
  if (DAT_803dd7c0 == 2000) {
    FUN_8004a9e4();
    FUN_8004a5b8('\x01');
    FUN_8004a9e4();
    FUN_8004a5b8('\x01');
    for (; 0 < DAT_803dd7c0; DAT_803dd7c0 = DAT_803dd7c0 + -1) {
      FUN_800234ac(DAT_8033d480);
      DAT_8033d480 = *(uint *)(&DAT_8033d478 + DAT_803dd7c0 * 8);
      DAT_8033d484 = (&DAT_8033d47c)[DAT_803dd7c0 * 8];
    }
    FUN_8007d858();
  }
  (&DAT_8033d480)[DAT_803dd7c0 * 2] = param_1;
  (&DAT_8033d484)[DAT_803dd7c0 * 8] = (char)DAT_803dd7bc;
  DAT_803dd7c0 = DAT_803dd7c0 + 1;
  return;
}

