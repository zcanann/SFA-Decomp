// Function: FUN_801195e0
// Entry: 801195e0
// Size: 288 bytes

undefined4 FUN_801195e0(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  FUN_800033a8(-0x7fc59640,0,0x1a8);
  FUN_802446f8((undefined4 *)&DAT_803a692c,&DAT_803a6920,3);
  iVar1 = FUN_8026c0d8();
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    FUN_80243e74();
    DAT_803de2f8 = 0;
    DAT_803de2f4 = 0;
    DAT_803de2f0 = 0;
    DAT_803de2ec = param_1;
    DAT_803de2e8 = FUN_8024fe1c(FUN_801182c0);
    if ((DAT_803de2e8 == 0) && (DAT_803de2ec != 0)) {
      FUN_8024fe1c(0);
      FUN_80243e9c();
      uVar2 = 0;
    }
    else {
      FUN_80243e9c();
      if (DAT_803de2ec == 0) {
        FUN_800033a8(-0x7fc59be0,0,0x500);
        FUN_802420e0(0x803a6420,0x500);
        FUN_8024fe60(&DAT_803a6420 + DAT_803de2f8 * 0x280,0x280);
        FUN_8024fee8();
      }
      DAT_803de2e0 = 1;
      uVar2 = 1;
    }
  }
  return uVar2;
}

