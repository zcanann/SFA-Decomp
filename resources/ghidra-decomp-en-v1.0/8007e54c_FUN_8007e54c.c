// Function: FUN_8007e54c
// Entry: 8007e54c
// Size: 392 bytes

void FUN_8007e54c(void)

{
  char cVar3;
  uint uVar1;
  undefined4 uVar2;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 local_28;
  int local_24 [9];
  
  cVar3 = FUN_802860dc();
  FUN_80017434(0);
  iVar5 = 0;
  do {
    FUN_80014f40();
    FUN_800234ec(0);
    FUN_8004a868();
    uVar1 = FUN_8001fd88(local_24);
    if ((uVar1 & 0xff) == 0) {
      local_28 = DAT_803db708;
      uVar2 = FUN_8006c73c();
      FUN_80076d78(uVar2,0,0,&local_28,0x200,0);
    }
    else {
      (**(code **)(*DAT_803dca4c + 4))(0,0,0);
      FUN_80076510((double)FLOAT_803def98,(double)FLOAT_803def98,0x280,0x1e0);
      iVar6 = 0;
      for (iVar4 = 0; iVar4 < (int)(uVar1 & 0xff); iVar4 = iVar4 + 1) {
        FUN_8003b8f4((double)FLOAT_803def9c,*(undefined4 *)(local_24[0] + iVar6),0,0,0,0);
        iVar6 = iVar6 + 4;
      }
      FUN_8001476c(0,0,0,0);
    }
    FUN_80019908(0xff,0xff,0xff,0xff);
    if (cVar3 == '\x01') {
      FUN_80016810(0x323,0,200);
    }
    else if (cVar3 == '\x02') {
      FUN_80016810(0x573,0,200);
    }
    else {
      FUN_80016810(0x56c,0,200);
    }
    FUN_80019c24();
    FUN_8004a43c(1,0);
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x3c);
  FUN_80286128();
  return;
}

