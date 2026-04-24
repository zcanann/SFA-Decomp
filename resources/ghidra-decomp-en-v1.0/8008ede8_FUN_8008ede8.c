// Function: FUN_8008ede8
// Entry: 8008ede8
// Size: 48 bytes

void FUN_8008ede8(undefined4 *param_1)

{
  if (DAT_803dd19c == (undefined4 *)0x0) {
    return;
  }
  *param_1 = *DAT_803dd19c;
  param_1[1] = DAT_803dd19c[1];
  param_1[2] = DAT_803dd19c[2];
  return;
}

