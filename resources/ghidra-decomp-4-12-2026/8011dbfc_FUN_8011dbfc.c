// Function: FUN_8011dbfc
// Entry: 8011dbfc
// Size: 152 bytes

void FUN_8011dbfc(uint param_1)

{
  ushort uVar1;
  
  uVar1 = 0;
  if (DAT_803de542 == 3) {
    uVar1 = 0x3fc;
  }
  else if (DAT_803de542 < 3) {
    if (DAT_803de542 == 1) {
      uVar1 = 0x3f8;
    }
    else if (DAT_803de542 < 1) {
      if (-1 < DAT_803de542) {
        uVar1 = 0x3fb;
      }
    }
    else {
      uVar1 = 0x3f7;
    }
  }
  else if (DAT_803de542 == 5) {
    uVar1 = 0x3fa;
  }
  else if (DAT_803de542 < 5) {
    uVar1 = 0x3f9;
  }
  if (uVar1 != 0) {
    FUN_8000b4f0(param_1,uVar1,1);
  }
  return;
}

