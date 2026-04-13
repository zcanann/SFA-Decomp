// Function: FUN_80043938
// Entry: 80043938
// Size: 1324 bytes

void FUN_80043938(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

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
  undefined8 uVar14;
  ulonglong uVar15;
  undefined4 uStack_11c;
  int local_118 [70];
  
  uVar15 = FUN_80286828();
  iVar5 = (int)(uVar15 >> 0x20);
  iVar11 = 0;
  bVar2 = false;
  (**(code **)(*DAT_803dd72c + 0x90))();
  puVar7 = &uStack_11c;
  puVar6 = &DAT_802c22ec;
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
    FUN_80243e74();
    iVar13 = DAT_803dd900;
    FUN_80243e9c();
    if ((iVar13 == 0) || (iVar13 == 0x100000)) break;
    uVar14 = FUN_80014f6c();
    FUN_80020390();
    if (bVar2) {
      uVar14 = FUN_8004a9e4();
    }
    uVar14 = FUN_80048350(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80015650(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (bVar2) {
      uVar14 = FUN_800235b0();
      FUN_80019c5c(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8004a5b8('\x01');
    }
    if (DAT_803dd5d0 != '\0') {
      bVar2 = true;
    }
  }
  iVar13 = (**(code **)(*DAT_803dd72c + 0x90))();
  iVar8 = (int)*(char *)(iVar13 + 0xe);
  if ((iVar8 != DAT_803dc210) && (iVar8 != iRam803dc214)) {
    if (((uVar15 & 0x10000000) != 0) && (iVar5 != iVar8)) {
      *(undefined *)(iVar13 + 0xe) = 0xff;
    }
    if (((uVar15 & 0x20000000) != 0) && (iVar5 == *(char *)(iVar13 + 0xe))) {
      *(undefined *)(iVar13 + 0xe) = 0xff;
    }
    if ((uVar15 & 0x80000000) != 0) {
      *(undefined *)(iVar13 + 0xe) = 0xff;
    }
  }
  piVar9 = (int *)&stack0xfffffee0;
  do {
    piVar12 = piVar9 + 2;
    if (((((uVar15 & 0x20000000) != 0) && (iVar5 == (&DAT_8035fba8)[*piVar12])) ||
        (((uVar15 & 0x10000000) != 0 && (iVar5 != (&DAT_8035fba8)[*piVar12])))) ||
       ((((uint)uVar15 & piVar9[3]) != 0 && (iVar5 == (&DAT_8035fba8)[*piVar12])))) {
      (&DAT_8035fba8)[*piVar12] = 0xffffffff;
    }
    iVar13 = *piVar12;
    if ((((&DAT_80360048)[iVar13] != 0) &&
        (((((uVar15 & 0x80000000) != 0 ||
           ((((uint)uVar15 & piVar9[3]) != 0 && (iVar5 == (short)(&DAT_803601a8)[iVar13])))) ||
          (((uVar15 & 0x10000000) != 0 && (iVar5 != (short)(&DAT_803601a8)[iVar13])))) ||
         (((uVar15 & 0x20000000) != 0 && (iVar5 == (short)(&DAT_803601a8)[iVar13])))))) &&
       ((DAT_803dc210 != (short)(&DAT_803601a8)[iVar13] &&
        (iRam803dc214 != (short)(&DAT_803601a8)[iVar13])))) {
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
        FUN_800238f8(0);
        break;
      case 0x20:
      case 0x23:
      case 0x4b:
      case 0x4d:
        FUN_800238f8(0);
        break;
      case 0x26:
      case 0x48:
        FUN_800238f8(0);
        iVar13 = 0;
        piVar9 = &DAT_802cc8a8;
        iVar8 = 0xf;
        do {
          iVar4 = (int)(short)(&DAT_803601a8)[*piVar12];
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
          FUN_800238c4((&DAT_8035fe68)[iVar10]);
          (&DAT_8035fe68)[iVar10] = 0;
        }
      }
      FUN_800238c4((&DAT_80360048)[*piVar12]);
      FUN_800238f8(2);
      iVar13 = *piVar12;
      (&DAT_80360048)[iVar13] = 0;
      (&DAT_803601a8)[iVar13] = 0xffff;
      (&DAT_8035fd08)[iVar13] = 0;
      switch(iVar13) {
      case 0xe:
      case 0x56:
        FUN_80043e64((uint *)&DAT_80346d30,0xe,0x56);
        break;
      case 0x1a:
      case 0x53:
        FUN_80043e64((uint *)&DAT_8034ec70,0x1a,0x53);
        break;
      case 0x21:
      case 0x4c:
        FUN_80043e64((uint *)&DAT_80352c70,0x21,0x4c);
        break;
      case 0x24:
      case 0x4e:
        FUN_80043e64((uint *)&DAT_80356c70,0x24,0x4e);
        break;
      case 0x26:
      case 0x48:
        FUN_80043e64((uint *)&DAT_80350c70,0x26,0x48);
        break;
      case 0x2a:
      case 0x45:
        FUN_80043e64((uint *)&DAT_8035db50,0x2a,0x45);
        break;
      case 0x2f:
      case 0x49:
        FUN_80043e64((uint *)&DAT_8035ac70,0x2f,0x49);
      }
    }
    iVar11 = iVar11 + 2;
    piVar9 = piVar12;
    if (0x37 < iVar11) {
      FUN_80286874();
      return;
    }
  } while( true );
}

