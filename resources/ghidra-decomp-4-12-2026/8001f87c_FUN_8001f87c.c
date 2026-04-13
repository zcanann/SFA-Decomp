// Function: FUN_8001f87c
// Entry: 8001f87c
// Size: 444 bytes

void FUN_8001f87c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined8 uVar4;
  
  iVar2 = FUN_8007db10();
  bVar1 = false;
  if (iVar2 < 0xc) {
    FUN_800206f8(1,1);
    DAT_803dd6bc = 0xff;
    uVar4 = FUN_80019940(0xff,0xff,0xff,0xff);
    if (DAT_803dd74c == 0) {
      switch(iVar2) {
      case 1:
        uVar4 = FUN_800168a8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x325);
        break;
      case 2:
        uVar4 = FUN_800168a8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x494);
        break;
      case 3:
        uVar4 = FUN_800168a8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x496);
        break;
      case 4:
        uVar4 = FUN_800168a8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32c);
        break;
      case 5:
      case 6:
        uVar4 = FUN_800168a8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x326);
        bVar1 = true;
        break;
      case 9:
        uVar4 = FUN_800168a8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32a);
        break;
      case 10:
        uVar4 = FUN_800168a8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x497);
        bVar1 = true;
        break;
      case 0xb:
        uVar4 = FUN_800168a8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x4c7);
      }
    }
    uVar3 = FUN_80014f14(0);
    if (bVar1) {
      FUN_80016848(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x495,0,200);
    }
    else {
      FUN_80016848(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x493,0,200);
    }
    if ((uVar3 & 0x100) == 0) {
      if ((bVar1) && ((uVar3 & 0x200) != 0)) {
        FUN_80014b68(0,0x200);
        DAT_803dc084 = 0;
        DAT_803dd6ba = 0;
        DAT_803dd6bc = 0;
        FUN_8000b734(0);
        FUN_8007db04();
      }
    }
    else {
      FUN_80014b68(0,0x100);
      FUN_8007db04();
      DAT_803dd6ba = 0;
      DAT_803dd6bc = 0;
      uVar4 = FUN_8000b734(0);
      if (iVar2 == 10) {
        FUN_8007db18(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
    }
  }
  return;
}

