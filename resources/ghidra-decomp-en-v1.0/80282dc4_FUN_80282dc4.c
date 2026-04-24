// Function: FUN_80282dc4
// Entry: 80282dc4
// Size: 152 bytes

void FUN_80282dc4(int param_1,undefined4 param_2,short param_3)

{
  byte bVar1;
  
  if (param_3 < 0) {
    param_3 = 0;
  }
  else if (0x3fff < param_3) {
    param_3 = 0x3fff;
  }
  bVar1 = FUN_80282cb4(param_2);
  if (((0xa1 < bVar1) || (bVar1 < 0xa0)) && (*(char *)(param_1 + 0x121) != -1)) {
    FUN_80281908(param_2,*(char *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122),(int)param_3);
  }
  return;
}

