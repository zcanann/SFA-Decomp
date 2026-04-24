// Function: FUN_80020d8c
// Entry: 80020d8c
// Size: 1456 bytes

void FUN_80020d8c(void)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  char cVar5;
  char cVar6;
  uint uVar4;
  char cVar7;
  char cVar8;
  
  FUN_802860dc();
  cVar5 = '\0';
  cVar6 = '\0';
  bVar1 = false;
  FUN_80240564();
  FUN_802491f4();
  FUN_8024c478();
  FUN_8024e654();
  FUN_80241c08();
  DAT_803dccf0 = &DAT_8032e620;
  DAT_803dcae4 = FUN_802457e8(0x70007);
  iVar2 = FUN_80244b20();
  if ((iVar2 == 0) || (DAT_803dcae4 != '\x01')) {
    FUN_80245858(0);
  }
  else {
    DAT_803dccf0 = &DAT_8032e65c;
    FUN_80245858(1);
  }
  FUN_80049b6c(&DAT_8033c3b8,0);
  FUN_8004a3d4();
  FUN_80115d54();
  FUN_80023f9c();
  FUN_80022d3c(1);
  FUN_8004a83c();
  FUN_80022d3c(0);
  FUN_8000fc54();
  FUN_80022d3c(1);
  FUN_8001a234();
  FUN_80022d3c(0);
  FUN_80019970(3);
  FUN_80022d3c(1);
  FUN_800154ac();
  uVar3 = FUN_80023834(0);
  do {
    FUN_800234ec(0);
    FUN_80014f40();
    FUN_800202cc();
    FUN_8004a868();
    if (cVar5 == '\0') {
      cVar5 = FUN_80009bf8();
    }
    if (!bVar1) {
      FUN_80022d3c(1);
      FUN_8004b628();
    }
    if ((cVar5 != '\0') && (cVar6 == '\0')) {
      FUN_80022d3c(1);
      cVar6 = FUN_80049200();
    }
    if (!bVar1) {
      FUN_80022d3c(1);
      FUN_8006d020();
    }
    bVar1 = true;
    FUN_801159e4();
    FUN_80015624();
    FUN_80019c24();
    if (*DAT_803dcafc == '\0') {
      cVar8 = '\0';
      cVar7 = '\0';
      iVar2 = FUN_8024d97c();
      if (iVar2 != 0) {
        iVar2 = FUN_80244b20();
        cVar7 = cVar8;
        if (((iVar2 != 0) && (DAT_803dcae4 != '\x01')) &&
           (uVar4 = FUN_80014ee8(0), (uVar4 & 0x200) != 0)) {
          cVar7 = '\x01';
        }
        iVar2 = FUN_80244b20();
        if ((iVar2 == 0) &&
           ((DAT_803dcae4 == '\x01' || (uVar4 = FUN_80014ee8(0), (uVar4 & 0x200) != 0)))) {
          cVar7 = '\x01';
        }
      }
      *DAT_803dcafc = cVar7;
    }
    FUN_8004a43c(1,0);
  } while (((cVar6 == '\0') || (cVar5 == '\0')) && (DAT_803dca3d == '\0'));
  while (DAT_803dca3d != '\0') {
    FUN_800234ec(0);
    FUN_80014f40();
    FUN_800202cc();
    FUN_8004a868();
    FUN_8004a43c(1,0);
  }
  FUN_80023834(uVar3);
  FUN_80022d3c(1);
  FUN_8004a56c(5);
  FUN_80137d28();
  FUN_80054db0();
  FUN_8005ca4c();
  FUN_800296a4();
  FUN_80013f68();
  FUN_8001a204();
  FUN_80019970(0x15);
  FUN_8002e994();
  FUN_80137998();
  FUN_80069990();
  FUN_80062c34();
  FUN_8006fccc();
  FUN_800149f8();
  FUN_800297e0();
  FUN_8007def0();
  FUN_802b6f48();
  FUN_800ea4c8();
  FUN_8001bd14();
  FUN_80058ea8();
  DAT_803dca68 = FUN_80013ec8(0,0xf);
  DAT_803dca50 = FUN_80013ec8(1,0x17);
  DAT_803dca94 = FUN_80013ec8(0x12,8);
  DAT_803dca8c = FUN_80013ec8(0xf,0x16);
  DAT_803dca54 = FUN_80013ec8(2,0x1d);
  DAT_803dca4c = FUN_80013ec8(0x16,4);
  DAT_803dca58 = FUN_80013ec8(5,0xf);
  DAT_803dca5c = FUN_80013ec8(6,0xc);
  DAT_803dca60 = FUN_80013ec8(7,8);
  DAT_803dca64 = FUN_80013ec8(9,10);
  DAT_803dca6c = FUN_80013ec8(3,0xd);
  DAT_803dca70 = FUN_80013ec8(4,0x24);
  DAT_803dca74 = DAT_803dca70;
  DAT_803dca78 = FUN_80013ec8(10,10);
  DAT_803dca7c = FUN_80013ec8(0xb,0xc);
  DAT_803dca80 = FUN_80013ec8(0xc,8);
  DAT_803dca84 = FUN_80013ec8(0xd,3);
  DAT_803dca88 = FUN_80013ec8(0xe,2);
  DAT_803dca90 = FUN_80013ec8(0x11,3);
  DAT_803dca98 = FUN_80013ec8(0x13,7);
  DAT_803dca9c = FUN_80013ec8(0x14,0x26);
  DAT_803dcaa0 = FUN_80013ec8(0x3c,7);
  DAT_803dcaa8 = FUN_80013ec8(0x15,9);
  DAT_803dcaac = (int *)FUN_80013ec8(0x17,0x24);
  DAT_803dcab4 = FUN_80013ec8(0x18,6);
  DAT_803dcab8 = FUN_80013ec8(0x19,0x16);
  DAT_803dcabc = FUN_80013ec8(0x31,2);
  DAT_803dcac0 = FUN_80013ec8(0x2f,0xc);
  DAT_803dcaa4 = FUN_80013ec8(0x3d,10);
  FUN_800534f8();
  FUN_80093db4();
  FUN_80022d3c(0);
  FUN_8001f768(&DAT_803dcadc,0x33);
  iVar2 = FUN_80048f10(0x33);
  DAT_803dcad8 = (undefined2)(iVar2 >> 1);
  DAT_803dcae0 = (**(code **)(*DAT_803dcaac + 0x88))();
  DAT_803dca3f = 1;
  FUN_80014948(2);
  FUN_8005c7e8();
  FUN_800207f4();
  FUN_8005cef0(0);
  if (*DAT_803dcafc != '\0') {
    FUN_80244760(DAT_803dcafc,DAT_803dcafc + 1);
    FUN_8024d6dc(0);
    FUN_8024d554();
    FUN_8024c8f0();
    FUN_8001fa4c();
  }
  FUN_80244760(0,0);
  FUN_80003494(&DAT_8033c378,DAT_803dccf0,0x3c);
  DAT_803dccf0 = &DAT_8033c378;
  FUN_80049b2c();
  FUN_80049504();
  FUN_8007d6dc(s_finished_init_802ca5e0);
  FUN_80286128();
  return;
}

