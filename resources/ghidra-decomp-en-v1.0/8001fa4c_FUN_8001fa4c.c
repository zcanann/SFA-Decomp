// Function: FUN_8001fa4c
// Entry: 8001fa4c
// Size: 828 bytes

void FUN_8001fa4c(void)

{
  undefined uVar1;
  bool bVar2;
  int iVar3;
  undefined4 uVar4;
  char cVar6;
  uint uVar5;
  uint uVar7;
  
  uVar7 = 0;
  bVar2 = true;
  iVar3 = FUN_800173c8(0);
  uVar1 = *(undefined *)(iVar3 + 0x10);
  *(undefined *)(iVar3 + 0x10) = 0;
  do {
    uVar7 = uVar7 + 1;
    FUN_80014f40();
    FUN_800202cc();
    FUN_800234ec(0);
    FUN_8004a868();
    FUN_80019908(0xc0,0xc0,0xc0,0xff);
    FUN_80016870(0x33f);
    if (bVar2) {
      FUN_80019908(0xff,0xff,0xff,0xff);
    }
    else {
      FUN_80019908(0x80,0x80,0x80,0x80);
    }
    uVar4 = FUN_80019444(0x3cd);
    FUN_80015dc8(uVar4,0,DAT_803db428,100);
    if (bVar2) {
      FUN_80019908(0x80,0x80,0x80,0x80);
    }
    else {
      FUN_80019908(0xff,0xff,0xff,0xff);
    }
    uVar4 = FUN_80019444(0x3cc);
    FUN_80015dc8(uVar4,0,DAT_803db42c,100);
    FUN_80019c24();
    FUN_80015624();
    FUN_80014f3c();
    FUN_8004a43c(0,0);
    cVar6 = FUN_80014cc0(0);
    if ((cVar6 < '\0') || (cVar6 = FUN_80014c18(0), cVar6 < '\0')) {
      bVar2 = true;
    }
    else {
      cVar6 = FUN_80014cc0(0);
      if (('\0' < cVar6) || (cVar6 = FUN_80014c18(0), '\0' < cVar6)) {
        bVar2 = false;
      }
    }
    uVar5 = FUN_80014e70(0);
  } while (((uVar5 & 0x100) == 0) && (uVar7 < 600));
  *(undefined *)(iVar3 + 0x10) = uVar1;
  FUN_8004a868();
  FUN_8004a43c(0,0);
  FUN_8004a868();
  FUN_8004a43c(0,0);
  FUN_8024d6dc(1);
  FUN_8024d554();
  FUN_8024c8f0();
  FUN_8024c8f0();
  FUN_8024c8f0();
  FUN_8024c8f0();
  if (bVar2) {
    DAT_803dccf0 = &DAT_8032e65c;
    FUN_80245858(1);
    FUN_802590f4(DAT_803dccf0[0x19],DAT_803dccf0 + 0x1a,0,DAT_803dccf0 + 0x32);
    FUN_8024cdb8(DAT_803dccf0);
    FUN_8024d6dc(1);
    FUN_8024d554();
    uVar4 = 0x340;
  }
  else {
    DAT_803dccf0 = &DAT_8032e620;
    FUN_80245858(0);
    FUN_802590f4(DAT_803dccf0[0x19],DAT_803dccf0 + 0x1a,1,DAT_803dccf0 + 0x32);
    FUN_8024cdb8(DAT_803dccf0);
    FUN_8024d6dc(1);
    FUN_8024d554();
    uVar4 = 0x341;
  }
  uVar7 = 0;
  do {
    FUN_8024c8f0();
    uVar7 = uVar7 + 1;
  } while (uVar7 < 100);
  FUN_8024d6dc(0);
  FUN_8024d554();
  FUN_8024c8f0();
  FUN_8024c8f0();
  uVar7 = 0;
  do {
    uVar7 = uVar7 + 1;
    FUN_80014f40();
    FUN_800202cc();
    FUN_800234ec(0);
    FUN_8004a868();
    if (uVar7 < 0xff) {
      FUN_80019908(0xff,0xff,0xff,0xff);
    }
    else {
      FUN_80019908(0xff,0xff,0xff,0xff);
    }
    FUN_80016870(uVar4);
    FUN_80019c24();
    FUN_80015624();
    FUN_80014f3c();
    FUN_8004a43c(0,0);
  } while (uVar7 < 0xf0);
  return;
}

