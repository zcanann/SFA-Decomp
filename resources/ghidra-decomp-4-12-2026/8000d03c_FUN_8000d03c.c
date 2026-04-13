// Function: FUN_8000d03c
// Entry: 8000d03c
// Size: 152 bytes

void FUN_8000d03c(void)

{
  int iVar1;
  
  if (DAT_803dd4e8 == 0) {
    DAT_803dd4c8 = 0;
  }
  else {
    FUN_802501f4(0);
    FUN_80250220(0);
    iVar1 = FUN_8024b73c((undefined4 *)&DAT_803378a0,FUN_8000d004);
    if (iVar1 == 0) {
      FUN_8007d858();
      DAT_803dd4c8 = 0;
    }
    DAT_803dd4f4 = 0;
    DAT_803dd4f0 = 0;
    DAT_803dd4e8 = 0;
    DAT_803dd4ec = 0;
    DAT_803dd448 = 0;
    DAT_803dd4dc = 0;
    DAT_803dd4e0 = 0;
  }
  return;
}

