// Function: FUN_8001d6b0
// Entry: 8001d6b0
// Size: 100 bytes

void FUN_8001d6b0(int param_1)

{
  short sVar1;
  
  if (*(char *)(param_1 + 0x2f8) == '\0') {
    return;
  }
  if (*(char *)(param_1 + 0x4c) == '\0') {
    return;
  }
  sVar1 = (ushort)*(byte *)(param_1 + 0x2f9) + (short)*(char *)(param_1 + 0x2fa);
  if (sVar1 < 0) {
    sVar1 = 0;
    *(undefined *)(param_1 + 0x2fa) = 0;
  }
  else if (0xff < sVar1) {
    sVar1 = 0xff;
    *(undefined *)(param_1 + 0x2fa) = 0;
  }
  *(char *)(param_1 + 0x2f9) = (char)sVar1;
  return;
}

