// Function: FUN_80253188
// Entry: 80253188
// Size: 244 bytes

void FUN_80253188(int param_1,int *param_2)

{
  int iVar1;
  
  if (param_1 == 1) {
    if ((*param_2 == 0) || ((param_2[3] & 0x10U) != 0)) {
      FUN_80243b44(0x80000);
    }
    else {
      FUN_80243bcc(0x80000);
    }
  }
  else if (param_1 < 1) {
    if (-1 < param_1) {
      if (((*param_2 == 0) && (DAT_803ae480 == 0)) || ((param_2[3] & 0x10U) != 0)) {
        FUN_80243b44(0x410000);
      }
      else {
        FUN_80243bcc(0x410000);
      }
    }
  }
  else if (param_1 < 3) {
    iVar1 = FUN_802437e4(0x19);
    if ((iVar1 == 0) || ((param_2[3] & 0x10U) != 0)) {
      FUN_80243b44(0x40);
    }
    else {
      FUN_80243bcc(0x40);
    }
  }
  return;
}

