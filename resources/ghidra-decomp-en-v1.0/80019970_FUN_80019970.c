// Function: FUN_80019970
// Entry: 80019970
// Size: 420 bytes

void FUN_80019970(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 local_18 [5];
  
  iVar2 = DAT_803dc9c8;
  DAT_803dc9a7 = 0xff;
  DAT_803dc9a6 = 0xff;
  DAT_803dc9a5 = 0xff;
  DAT_803dc9a4 = 0xff;
  if (param_1 == 3) {
    DAT_803dc9ec = &DAT_8033af90;
    DAT_803dc9e8 = 2;
    local_18[0] = DAT_803db3c8;
    FUN_800753b8(0,0,0xa00,0x780,local_18);
    iVar2 = DAT_803dc9c8;
    DAT_803dc99c = 0;
    if (DAT_803dc96c == 0) {
      iVar1 = DAT_803dc9c8 * 5;
      DAT_803dc9c8 = DAT_803dc9c8 + 1;
      (&DAT_8033a540)[iVar1] = 0xf;
      (&DAT_8033a544)[iVar2 * 5] = 2;
    }
  }
  else {
    DAT_803dc9dc = param_1;
    if (param_1 == 0x1c) {
      DAT_803dc9ec = &DAT_8033afb8;
      DAT_803dc9e8 = 3;
      if (DAT_803dc96c == 0) {
        iVar1 = DAT_803dc9c8 * 5;
        DAT_803dc9c8 = DAT_803dc9c8 + 1;
        (&DAT_8033a540)[iVar1] = 0xf;
        (&DAT_8033a544)[iVar2 * 5] = 3;
      }
      FUN_8001a66c(3);
    }
    else {
      DAT_803dc9ec = (undefined4 *)&DAT_8033af40;
      DAT_803dc9e8 = 0;
      if (DAT_803dc96c == 0) {
        iVar1 = DAT_803dc9c8 * 5;
        DAT_803dc9c8 = DAT_803dc9c8 + 1;
        (&DAT_8033a540)[iVar1] = 0xf;
        (&DAT_8033a544)[iVar2 * 5] = 0;
      }
      iVar2 = FUN_8001bcb4();
      if (((iVar2 == 0) || (iVar2 = FUN_8001b44c(param_1), iVar2 == 0)) &&
         (DAT_803dc9dc != DAT_803dc9d8)) {
        FUN_8001a66c(0);
      }
    }
  }
  return;
}

