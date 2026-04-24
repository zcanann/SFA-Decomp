// Function: FUN_8007e1ac
// Entry: 8007e1ac
// Size: 928 bytes

void FUN_8007e1ac(void)

{
  bool bVar1;
  bool bVar2;
  int iVar3;
  char cVar7;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 *puVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  double dVar15;
  undefined4 local_88;
  int local_84;
  undefined4 local_80 [8];
  uint local_60 [8];
  longlong local_40;
  
  cVar7 = FUN_802860c4();
  iVar14 = 0;
  bVar1 = false;
  iVar13 = 0;
  bVar2 = false;
  DAT_803dd058 = 0;
  if ((DAT_803db700 != 0xd) && ((cVar7 == '\0' || (DAT_803db700 != 0xc)))) {
    do {
      FUN_800202cc();
      FUN_80014f40();
      FUN_800234ec(0);
      iVar13 = iVar13 + 1000;
      FUN_8004a868();
      local_88 = DAT_803db708;
      uVar4 = FUN_8006c73c();
      FUN_80076d78(uVar4,0,0,&local_88,0x200,0);
      if (bVar1) {
        local_60[0] = 6;
        local_60[1] = 5;
        local_80[0] = 0x327;
        local_80[1] = 0x321;
        local_80[2] = 800;
        local_84 = 2;
      }
      else {
        FUN_8007df10(local_60,local_80,&local_84);
      }
      FUN_80019908(0xff,0xc0,0x40,0xff);
      puVar11 = local_80;
      iVar10 = 100;
      for (iVar9 = 0; iVar9 < local_84 + 1; iVar9 = iVar9 + 1) {
        iVar5 = FUN_80019570(*puVar11);
        if (iVar9 < 1) {
          iVar3 = 0;
        }
        else {
          iVar3 = 100;
        }
        iVar3 = iVar10 + iVar3;
        iVar12 = 0;
        for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar5 + 2); iVar8 = iVar8 + 1) {
          FUN_80015dc8(*(undefined4 *)(*(int *)(iVar5 + 8) + iVar12),0,0,iVar3);
          iVar3 = iVar3 + 0x18;
          iVar12 = iVar12 + 4;
        }
        if (iVar9 == iVar14) {
          dVar15 = (double)FUN_80293ac4(iVar13);
          iVar5 = (int)((double)FLOAT_803def94 * dVar15 + (double)FLOAT_803def90);
          local_40 = (longlong)iVar5;
          FUN_80019908(iVar5,iVar5,iVar5,0xff);
        }
        else {
          FUN_80019908(0xa0,0xa0,0xa0,0xff);
        }
        puVar11 = puVar11 + 1;
        iVar10 = iVar10 + 0x14;
      }
      FUN_80019c24();
      FUN_8004a43c(1,0);
      cVar7 = FUN_80014c6c(0);
      if ((cVar7 < '\0') || (cVar7 = FUN_80014bc4(0), cVar7 < '\0')) {
        if (!bVar2) {
          iVar14 = iVar14 + 1;
          bVar2 = true;
        }
      }
      else {
        cVar7 = FUN_80014c6c(0);
        if ((cVar7 < '\x01') && (cVar7 = FUN_80014bc4(0), cVar7 < '\x01')) {
          bVar2 = false;
        }
        else if (!bVar2) {
          iVar14 = iVar14 + -1;
          bVar2 = true;
        }
      }
      if (iVar14 < 0) {
        iVar14 = 0;
      }
      else if (local_84 + -1 < iVar14) {
        iVar14 = local_84 + -1;
      }
      uVar6 = FUN_80014e70(0);
      if ((uVar6 & 0x100) != 0) {
        switch(local_60[iVar14]) {
        case 0:
          bVar1 = true;
          iVar14 = 0;
          break;
        case 1:
          DAT_803db700 = 0xd;
          DAT_803dd058 = 1;
          break;
        case 2:
          DAT_803db424 = 0;
          DAT_803db700 = 0xd;
          break;
        case 3:
          FUN_80020614(6);
          DAT_803db424 = 0;
          DAT_803db700 = 0xd;
          break;
        case 4:
          FUN_8007d99c();
          FUN_8007dd04(0);
          if (DAT_803db700 == 0xd) {
            DAT_803dd058 = 1;
          }
          break;
        case 5:
          bVar1 = false;
          iVar9 = FUN_8007d72c();
          if (iVar9 != 0) {
            FUN_8007dd04(0);
          }
          if (DAT_803db700 == 0xd) {
            DAT_803dd058 = 1;
          }
          break;
        case 6:
          bVar1 = false;
          break;
        default:
          DAT_803db700 = 0xd;
        }
      }
    } while (DAT_803db700 != 0xd);
  }
  FUN_80286110();
  return;
}

