// Function: FUN_80278cc4
// Entry: 80278cc4
// Size: 176 bytes

void FUN_80278cc4(int *param_1)

{
  bool bVar1;
  
  if (param_1[0x13] == 1) {
    if ((*(char *)(param_1 + 0x1a) == '\0') || (param_1[0x15] == 0)) {
      bVar1 = false;
    }
    else {
      param_1[0xe] = param_1[0x18];
      param_1[0xd] = param_1[0x15];
      param_1[0x15] = 0;
      FUN_802790f4(param_1);
      bVar1 = true;
    }
    if ((!bVar1) && ((param_1[0x46] & 0x40000U) != 0)) {
      FUN_802790f4(param_1);
    }
  }
  return;
}

