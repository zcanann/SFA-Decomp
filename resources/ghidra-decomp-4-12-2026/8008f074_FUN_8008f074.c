// Function: FUN_8008f074
// Entry: 8008f074
// Size: 48 bytes

void FUN_8008f074(undefined4 *param_1)

{
  if (DAT_803dde1c == (undefined4 *)0x0) {
    return;
  }
  *param_1 = *DAT_803dde1c;
  param_1[1] = DAT_803dde1c[1];
  param_1[2] = DAT_803dde1c[2];
  return;
}

