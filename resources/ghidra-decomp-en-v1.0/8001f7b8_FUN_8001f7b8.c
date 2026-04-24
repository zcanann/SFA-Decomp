// Function: FUN_8001f7b8
// Entry: 8001f7b8
// Size: 444 bytes

void FUN_8001f7b8(void)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  
  iVar2 = FUN_8007d994();
  bVar1 = false;
  if (iVar2 < 0xc) {
    FUN_80020634(1,1);
    DAT_803dca3c = 0xff;
    FUN_80019908(0xff,0xff,0xff,0xff);
    if (DAT_803dcacc == 0) {
      switch(iVar2) {
      case 1:
        FUN_80016870(0x325);
        break;
      case 2:
        FUN_80016870(0x494);
        break;
      case 3:
        FUN_80016870(0x496);
        break;
      case 4:
        FUN_80016870(0x32c);
        break;
      case 5:
      case 6:
        FUN_80016870(0x326);
        bVar1 = true;
        break;
      case 9:
        FUN_80016870(0x32a);
        break;
      case 10:
        FUN_80016870(0x497);
        bVar1 = true;
        break;
      case 0xb:
        FUN_80016870(0x4c7);
      }
    }
    uVar3 = FUN_80014ee8(0);
    if (bVar1) {
      FUN_80016810(0x495,0,200);
    }
    else {
      FUN_80016810(0x493,0,200);
    }
    if ((uVar3 & 0x100) == 0) {
      if ((bVar1) && ((uVar3 & 0x200) != 0)) {
        FUN_80014b3c(0,0x200);
        DAT_803db424 = 0;
        DAT_803dca3a = 0;
        DAT_803dca3c = 0;
        FUN_8000b714(0);
        FUN_8007d988();
      }
    }
    else {
      FUN_80014b3c(0,0x100);
      FUN_8007d988();
      DAT_803dca3a = 0;
      DAT_803dca3c = 0;
      FUN_8000b714(0);
      if (iVar2 == 10) {
        FUN_8007d99c();
      }
    }
  }
  return;
}

