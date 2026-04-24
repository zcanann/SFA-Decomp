// Function: FUN_8011d918
// Entry: 8011d918
// Size: 152 bytes

void FUN_8011d918(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = 0;
  if (DAT_803dd8c2 == 3) {
    iVar1 = 0x3fc;
  }
  else if (DAT_803dd8c2 < 3) {
    if (DAT_803dd8c2 == 1) {
      iVar1 = 0x3f8;
    }
    else if (DAT_803dd8c2 < 1) {
      if (-1 < DAT_803dd8c2) {
        iVar1 = 0x3fb;
      }
    }
    else {
      iVar1 = 0x3f7;
    }
  }
  else if (DAT_803dd8c2 == 5) {
    iVar1 = 0x3fa;
  }
  else if (DAT_803dd8c2 < 5) {
    iVar1 = 0x3f9;
  }
  if (iVar1 != 0) {
    FUN_8000b4d0(param_1,iVar1,1);
  }
  return;
}

