// Function: FUN_80249958
// Entry: 80249958
// Size: 252 bytes

undefined4 FUN_80249958(void)

{
  undefined4 uVar1;
  
  uVar1 = 0x80330000;
  if (DAT_803debc8 == 0) {
    FUN_8024142c();
    DAT_803debc8 = 1;
    FUN_80248fd4();
    FUN_8024c0d4();
    FUN_80248180();
    DAT_803deb90 = -0x80000000;
    DAT_803deb8c = 0x80000000;
    FUN_80243ec0(0x15,&LAB_802481c0);
    FUN_802442c4(0x400);
    FUN_802464dc((undefined4 *)&DAT_803deb80);
    DAT_cc006000 = 0x2a;
    DAT_cc006004 = 0;
    if (*(int *)(DAT_803deb90 + 0x20) == -0x1adf83de) {
      FUN_8007d858();
      FUN_8007d858();
      uVar1 = FUN_8024c53c();
    }
    else if (*(int *)(DAT_803deb90 + 0x20) == 0xd15ea5e) {
      uVar1 = FUN_8007d858();
    }
    else {
      DAT_803debc4 = 1;
      uVar1 = FUN_8007d858();
    }
  }
  return uVar1;
}

