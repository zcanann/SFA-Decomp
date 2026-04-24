// Function: FUN_802538ec
// Entry: 802538ec
// Size: 244 bytes

void FUN_802538ec(int param_1,int *param_2)

{
  int iVar1;
  
  if (param_1 == 1) {
    if ((*param_2 == 0) || ((param_2[3] & 0x10U) != 0)) {
      FUN_8024423c(0x80000);
    }
    else {
      FUN_802442c4(0x80000);
    }
  }
  else if (param_1 < 1) {
    if (-1 < param_1) {
      if (((*param_2 == 0) && (DAT_803af0e0 == 0)) || ((param_2[3] & 0x10U) != 0)) {
        FUN_8024423c(0x410000);
      }
      else {
        FUN_802442c4(0x410000);
      }
    }
  }
  else if (param_1 < 3) {
    iVar1 = FUN_80243edc(0x19);
    if ((iVar1 == 0) || ((param_2[3] & 0x10U) != 0)) {
      FUN_8024423c(0x40);
    }
    else {
      FUN_802442c4(0x40);
    }
  }
  return;
}

