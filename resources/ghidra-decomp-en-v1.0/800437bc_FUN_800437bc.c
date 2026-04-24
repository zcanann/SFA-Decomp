// Function: FUN_800437bc
// Entry: 800437bc
// Size: 1324 bytes

void FUN_800437bc(void)

{
  undefined4 *puVar1;
  bool bVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  int *piVar12;
  int iVar13;
  ulonglong uVar14;
  undefined4 uStack284;
  int local_118 [70];
  
  uVar14 = FUN_802860c4();
  iVar5 = (int)(uVar14 >> 0x20);
  iVar11 = 0;
  bVar2 = false;
  (**(code **)(*DAT_803dcaac + 0x90))();
  puVar7 = &uStack284;
  puVar6 = &DAT_802c1b6c;
  iVar13 = 0x1c;
  do {
    puVar1 = puVar6 + 1;
    puVar6 = puVar6 + 2;
    uVar3 = *puVar6;
    puVar7[1] = *puVar1;
    puVar7 = puVar7 + 2;
    *puVar7 = uVar3;
    iVar13 = iVar13 + -1;
  } while (iVar13 != 0);
  while( true ) {
    FUN_8024377c();
    iVar13 = DAT_803dcc80;
    FUN_802437a4();
    if ((iVar13 == 0) || (iVar13 == 0x100000)) break;
    FUN_80014f40();
    FUN_800202cc();
    if (bVar2) {
      FUN_8004a868();
    }
    FUN_800481d4(0);
    FUN_80015624();
    if (bVar2) {
      FUN_800234ec(0);
      FUN_80019c24();
      FUN_8004a43c(1,0);
    }
    if (DAT_803dc950 != '\0') {
      bVar2 = true;
    }
  }
  iVar13 = (**(code **)(*DAT_803dcaac + 0x90))();
  iVar8 = (int)*(char *)(iVar13 + 0xe);
  if ((iVar8 != DAT_803db5b0) && (iVar8 != iRam803db5b4)) {
    if (((uVar14 & 0x10000000) != 0) && (iVar5 != iVar8)) {
      *(undefined *)(iVar13 + 0xe) = 0xff;
    }
    if (((uVar14 & 0x20000000) != 0) && (iVar5 == *(char *)(iVar13 + 0xe))) {
      *(undefined *)(iVar13 + 0xe) = 0xff;
    }
    if ((uVar14 & 0x80000000) != 0) {
      *(undefined *)(iVar13 + 0xe) = 0xff;
    }
  }
  piVar9 = (int *)&stack0xfffffee0;
  do {
    piVar12 = piVar9 + 2;
    if (((((uVar14 & 0x20000000) != 0) && (iVar5 == (&DAT_8035ef48)[*piVar12])) ||
        (((uVar14 & 0x10000000) != 0 && (iVar5 != (&DAT_8035ef48)[*piVar12])))) ||
       ((((uint)uVar14 & piVar9[3]) != 0 && (iVar5 == (&DAT_8035ef48)[*piVar12])))) {
      (&DAT_8035ef48)[*piVar12] = 0xffffffff;
    }
    iVar13 = *piVar12;
    if ((((&DAT_8035f3e8)[iVar13] != 0) &&
        (((((uVar14 & 0x80000000) != 0 ||
           ((((uint)uVar14 & piVar9[3]) != 0 && (iVar5 == (short)(&DAT_8035f548)[iVar13])))) ||
          (((uVar14 & 0x10000000) != 0 && (iVar5 != (short)(&DAT_8035f548)[iVar13])))) ||
         (((uVar14 & 0x20000000) != 0 && (iVar5 == (short)(&DAT_8035f548)[iVar13])))))) &&
       ((DAT_803db5b0 != (short)(&DAT_8035f548)[iVar13] &&
        (iRam803db5b4 != (short)(&DAT_8035f548)[iVar13])))) {
      switch(iVar13) {
      case 0xe:
      case 0x1a:
      case 0x21:
      case 0x24:
      case 0x2a:
      case 0x2b:
      case 0x2f:
      case 0x30:
      case 0x45:
      case 0x46:
      case 0x49:
      case 0x4a:
      case 0x4c:
      case 0x4e:
      case 0x53:
      case 0x56:
        FUN_80023834(0);
        break;
      case 0x20:
      case 0x23:
      case 0x4b:
      case 0x4d:
        FUN_80023834(0);
        break;
      case 0x26:
      case 0x48:
        FUN_80023834(0);
        iVar13 = 0;
        piVar9 = &DAT_802cbcd0;
        iVar8 = 0xf;
        do {
          iVar4 = (int)(short)(&DAT_8035f548)[*piVar12];
          iVar10 = iVar13;
          if ((((*piVar9 == iVar4) || (iVar10 = iVar13 + 1, piVar9[1] == iVar4)) ||
              (iVar10 = iVar13 + 2, piVar9[2] == iVar4)) ||
             ((iVar10 = iVar13 + 3, piVar9[3] == iVar4 || (iVar10 = iVar13 + 4, piVar9[4] == iVar4))
             )) break;
          piVar9 = piVar9 + 5;
          iVar13 = iVar13 + 5;
          iVar8 = iVar8 + -1;
          iVar10 = iVar13;
        } while (iVar8 != 0);
        if (((iVar10 < 0x51) && (iVar10 != 0x49)) && ((iVar10 != 0x43 && (iVar10 != 5)))) {
          FUN_80023800((&DAT_8035f208)[iVar10]);
          (&DAT_8035f208)[iVar10] = 0;
        }
      }
      FUN_80023800((&DAT_8035f3e8)[*piVar12]);
      FUN_80023834(2);
      iVar13 = *piVar12;
      (&DAT_8035f3e8)[iVar13] = 0;
      (&DAT_8035f548)[iVar13] = 0xffff;
      (&DAT_8035f0a8)[iVar13] = 0;
      switch(iVar13) {
      case 0xe:
      case 0x56:
        FUN_80043ce8(&DAT_803460d0,0xe,0x56,0x1fd0);
        break;
      case 0x1a:
      case 0x53:
        FUN_80043ce8(&DAT_8034e010,0x1a,0x53,0x800);
        break;
      case 0x21:
      case 0x4c:
        FUN_80043ce8(&DAT_80352010,0x21,0x4c,0x1000);
        break;
      case 0x24:
      case 0x4e:
        FUN_80043ce8(&DAT_80356010,0x24,0x4e,0x1000);
        break;
      case 0x26:
      case 0x48:
        FUN_80043ce8(&DAT_80350010,0x26,0x48,0x800);
        break;
      case 0x2a:
      case 0x45:
        FUN_80043ce8(&DAT_8035cef0,0x2a,0x45,0x800);
        break;
      case 0x2f:
      case 0x49:
        FUN_80043ce8(&DAT_8035a010,0x2f,0x49,3000);
      }
    }
    iVar11 = iVar11 + 2;
    piVar9 = piVar12;
    if (0x37 < iVar11) {
      FUN_80286110(1);
      return;
    }
  } while( true );
}

