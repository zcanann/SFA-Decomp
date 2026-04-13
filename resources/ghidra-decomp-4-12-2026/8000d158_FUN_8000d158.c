// Function: FUN_8000d158
// Entry: 8000d158
// Size: 200 bytes

void FUN_8000d158(void)

{
  int iVar1;
  
  if (DAT_803dd4f0 == 0) {
    if (DAT_803dd4f4 == 0) {
      if (DAT_803dd4e8 == 0) {
        DAT_803dd4dc = 0;
        DAT_803dd4e0 = 0;
        DAT_803dd4ec = 0;
        DAT_803dd448 = 0;
      }
    }
    else {
      iVar1 = FUN_800206e4();
      if (iVar1 == 1) {
        iVar1 = FUN_800206e4();
        if (iVar1 == 1) {
          FUN_802501f4((uint)DAT_803dbeb0);
          FUN_80250220((uint)DAT_803dbeb1);
          FUN_8024ff34(1);
          DAT_803dd4c8 = 1;
          FLOAT_803dd4d8 = FLOAT_803df250;
          DAT_803dd4e8 = DAT_803dd4f4;
          DAT_803dd4f4 = 0;
          DAT_803dd4f0 = 0;
          DAT_803dd4ec = 0;
        }
        else {
          DAT_803dd4c8 = 0;
        }
      }
    }
  }
  else {
    DAT_803dd4ec = 1;
  }
  return;
}

