// Function: FUN_80129ee0
// Entry: 80129ee0
// Size: 5604 bytes

/* WARNING: Removing unreachable block (ram,0x8012a308) */

void FUN_80129ee0(void)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  char cVar9;
  ushort uVar8;
  int iVar6;
  undefined4 uVar7;
  byte bVar10;
  byte bVar13;
  undefined2 uVar11;
  undefined2 uVar12;
  byte bVar14;
  uint uVar15;
  uint uVar16;
  short sVar17;
  int *piVar18;
  double dVar19;
  undefined uStack72;
  char local_47 [3];
  char local_44 [20];
  undefined4 local_30;
  int iStack44;
  
  FUN_802860d0();
  iVar4 = FUN_8002b9ec();
  uVar16 = 0;
  bVar3 = false;
  FUN_80295bc8();
  bVar14 = 1;
  bVar13 = 5;
  iVar5 = (**(code **)(*DAT_803dcaac + 0x8c))();
  dVar19 = (double)FUN_80019c00();
  if (dVar19 == (double)FLOAT_803e1e3c) {
    uVar16 = FUN_80014e70(0);
    uVar16 = uVar16 & 0xffff;
    FUN_80014ee8(0);
  }
  DAT_803dd778 = DAT_803dd778 - (ushort)DAT_803db410;
  if (DAT_803dd778 < 0) {
    DAT_803dd778 = 0;
  }
  if ((iVar4 == 0) && (iVar4 = FUN_8022d768(), iVar4 != 0)) {
    bVar3 = true;
  }
  cVar9 = FUN_8012b6bc();
  if (cVar9 == '\0') {
    bVar14 = 4;
  }
  if (((DAT_803db424 == '\0') || (uVar8 = FUN_800ea2bc(), uVar8 < 3)) ||
     ((iVar4 != 0 &&
      ((iVar6 = FUN_8005afac((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x14)),
       iVar6 == 0 && (iVar6 = FUN_802972a8(iVar4), iVar6 != 0)))))) {
    bVar13 = 4;
  }
  DAT_803dd7d6 = FUN_800ea200();
  if (iVar4 != 0) {
    if (*(int *)(iVar4 + 0x30) == 0) {
      DAT_803dd8e0 = FUN_8005afac((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x14));
    }
    else {
      DAT_803dd8e0 = (uint)*(char *)(*(int *)(iVar4 + 0x30) + 0xac);
    }
    if (DAT_803dd8e0 == 0x36) {
      cVar9 = (**(code **)(*DAT_803dcaac + 0x40))();
      if (cVar9 == '\x01') {
        cVar9 = (**(code **)(*DAT_803dcaac + 0x4c))(DAT_803dd8e0,0);
        if (cVar9 == '\0') {
          cVar9 = (**(code **)(*DAT_803dcaac + 0x4c))(DAT_803dd8e0,1);
          if (cVar9 == '\0') {
            cVar9 = (**(code **)(*DAT_803dcaac + 0x4c))(DAT_803dd8e0,2);
            if (cVar9 != '\0') {
              DAT_803dd8e0 = 0xc;
            }
          }
          else {
            DAT_803dd8e0 = 6;
          }
        }
        else {
          DAT_803dd8e0 = 5;
        }
      }
      else {
        cVar9 = (**(code **)(*DAT_803dcaac + 0x40))(DAT_803dd8e0);
        if (cVar9 == '\x02') {
          cVar9 = (**(code **)(*DAT_803dcaac + 0x4c))(DAT_803dd8e0,0);
          if (cVar9 == '\0') {
            cVar9 = (**(code **)(*DAT_803dcaac + 0x4c))(DAT_803dd8e0,1);
            if (cVar9 == '\0') {
              cVar9 = (**(code **)(*DAT_803dcaac + 0x4c))(DAT_803dd8e0,2);
              if (cVar9 == '\0') {
                cVar9 = (**(code **)(*DAT_803dcaac + 0x4c))(DAT_803dd8e0,3);
                if (cVar9 == '\0') {
                  cVar9 = (**(code **)(*DAT_803dcaac + 0x4c))(DAT_803dd8e0,4);
                  if (cVar9 == '\0') {
                    cVar9 = (**(code **)(*DAT_803dcaac + 0x4c))(DAT_803dd8e0,5);
                    if (cVar9 != '\0') {
                      DAT_803dd8e0 = 3;
                    }
                  }
                  else {
                    DAT_803dd8e0 = 9;
                  }
                }
                else {
                  DAT_803dd8e0 = 10;
                }
              }
              else {
                DAT_803dd8e0 = 6;
              }
            }
            else {
              DAT_803dd8e0 = 6;
            }
          }
          else {
            DAT_803dd8e0 = 6;
          }
        }
      }
    }
    else {
      bVar10 = 0;
      while ((bVar10 < 0x2d && (DAT_803dd8e0 != (ushort)(&DAT_8031b764)[(uint)bVar10 * 2]))) {
        bVar10 = bVar10 + 1;
      }
      if (bVar10 != 0x2d) {
        DAT_803dd8e0 = (uint)(ushort)(&DAT_8031b766)[(uint)bVar10 * 2];
        FUN_800200e8(DAT_803dd8e0 + 0xf10,1);
      }
    }
  }
  dVar19 = (double)(**(code **)(*DAT_803dca4c + 0x18))();
  if ((double)FLOAT_803e1e3c == dVar19) {
    iVar6 = (int)DAT_803dd788 - (uint)DAT_803db410;
    if (iVar6 < 0) {
      iVar6 = 0;
    }
    DAT_803dd788 = (char)iVar6;
  }
  if ((DAT_803dd780 == 1) || ((DAT_803dd780 != 0 && (2 < DAT_803dd780)))) {
    iVar6 = (int)DAT_803dd78c + (uint)DAT_803db410 * 0x32;
    if (0x400 < iVar6) {
      iVar6 = 0x400;
    }
    DAT_803dd78c = (short)iVar6;
  }
  switch(DAT_803dd780) {
  case 0:
    iVar5 = (**(code **)(*DAT_803dca50 + 0x10))();
    bVar2 = true;
    bVar1 = false;
    if (((iVar4 == 0) || ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0)) &&
       ((iVar6 = FUN_80080204(), iVar6 == 0 && (cVar9 = FUN_8000cfa0(), cVar9 == '\0')))) {
      bVar1 = true;
    }
    if ((!bVar1) && (iVar5 != 0x51)) {
      bVar2 = false;
    }
    if ((((((uVar16 & 0x1000) != 0) && (DAT_803dd788 == '\0')) && (DAT_803dd789 == '\0')) &&
        ((dVar19 = (double)(**(code **)(*DAT_803dca4c + 0x18))(), (double)FLOAT_803e1e3c == dVar19
         && (bVar2)))) && ((DAT_803dd75b == '\0' && (iVar5 = FUN_8002073c(), iVar5 == 0)))) {
      DAT_803dd788 = '<';
      FUN_800206e8(1);
      FUN_80020628(0xff);
      FUN_80014b3c(0,0x1000);
      FUN_8012c558();
      DAT_803dba64 = 5;
      if (bVar3) {
        DAT_803dd7cc = 0;
      }
      if ((DAT_803dd772 == 0) && (DAT_803dd770 == 0)) {
        DAT_803dd780 = 1;
        DAT_803dd8dc = FUN_80019bf0();
        FUN_80019970(0xb);
      }
      else {
        DAT_803dd8dc = FUN_80019bf0();
        if (DAT_803dd8e0 == DAT_803dd7d6) {
          FUN_800ea264();
        }
        DAT_803dd780 = 4;
        if (DAT_803dd8e0 == DAT_803dd7d6) {
          FUN_800ea264();
        }
        else {
          FUN_80019970(0xb);
        }
        DAT_803dd8d8 = 0xb;
        FLOAT_803dd764 = FLOAT_803e1e60;
      }
    }
    sVar17 = DAT_803dd772;
    if ((((DAT_803dd772 != 0) && (iVar4 != 0)) && ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0)) &&
       (cVar9 = FUN_8012b6bc(), cVar9 != '\0')) {
      DAT_803dd772 = DAT_803dd772 + (ushort)DAT_803db410;
      if (DAT_803dd772 < 0x1518) {
        if (((9 < DAT_803dd772) && (sVar17 < 10)) || ((0x707 < DAT_803dd772 && (sVar17 < 0x708)))) {
          DAT_803dd770 = 1;
        }
      }
      else {
        DAT_803dd772 = 0;
        DAT_803dd770 = 1;
        FUN_8000bb18(0,0x38d);
      }
    }
    if (DAT_803dd770 != 0) {
      FLOAT_803dd7dc = FLOAT_803dd7dc + FLOAT_803db414;
      if ((DAT_803dd770 == 1) || (FLOAT_803e1f9c <= FLOAT_803dd7dc)) {
        FLOAT_803dd7dc = FLOAT_803e1e3c;
        FUN_8000bb18(0,0x38d);
      }
      DAT_803dd770 = DAT_803dd770 + (ushort)DAT_803db410;
      if (0xff < DAT_803dd770) {
        DAT_803dd770 = 0;
      }
    }
    break;
  case 1:
    FUN_80014b78(0,local_47,&uStack72);
    FUN_8012ddd8(0x2b1,DAT_803dba64,1,3);
    if (((DAT_803dd781 != '\0') && (iVar4 = FUN_8000cf98(), iVar4 == 0)) &&
       (cVar9 = FUN_8000cfa0(), cVar9 == '\0')) {
      FUN_80030334((double)FLOAT_803e1e3c,(&DAT_803a9410)[DAT_803dd781],0,0);
      DAT_803dd781 = '\0';
    }
    if (((local_47[0] != '\0') || (DAT_803dd78c == 0)) ||
       (((char)DAT_803dba64 < (char)bVar14 || ((char)bVar13 < (char)DAT_803dba64)))) {
      iVar4 = (int)(char)DAT_803dba64;
      if (((iVar4 < 4) && (0 < iVar4)) && (0x90000000 < *(uint *)((&DAT_803a9410)[iVar4] + 0x4c))) {
        *(undefined4 *)((&DAT_803a9410)[iVar4] + 0x4c) = 0;
      }
      bVar10 = DAT_803dba64;
      DAT_803dba64 = DAT_803dba64 + local_47[0];
      if ((char)DAT_803dba64 < (char)bVar14) {
        DAT_803dba64 = bVar13;
      }
      if ((char)bVar13 < (char)DAT_803dba64) {
        DAT_803dba64 = bVar14;
      }
      if ((int)(char)DAT_803dba64 != (uint)bVar10) {
        FUN_8000bb18(0,0x37b);
      }
      iVar4 = (int)(char)DAT_803dba64;
      if (((iVar4 < 4) && (0 < iVar4)) && (0x90000000 < *(uint *)((&DAT_803a9410)[iVar4] + 0x4c))) {
        *(undefined4 *)((&DAT_803a9410)[iVar4] + 0x4c) = 0;
      }
    }
    if (DAT_803dd786 < (short)(ushort)DAT_803dbaa2) {
      DAT_803dd786 = DAT_803dd786 + (ushort)DAT_803db410;
      if ((short)(ushort)DAT_803dbaa2 <= DAT_803dd786) {
        FUN_8012ddd8(0x2b1,DAT_803dba64,1,3);
      }
    }
    else {
      DAT_803dd784 = DAT_803dd784 + (ushort)DAT_803db410 * 0x28;
      if (0x400 < DAT_803dd784) {
        DAT_803dd784 = 0x400;
      }
    }
    if ((uVar16 & 0x100) != 0) {
      FUN_8000bb18(0,0x98);
      FUN_80014b3c(0,0x100);
      FLOAT_803dd7bc = FLOAT_803e1e3c;
      FLOAT_803dd7c0 = FLOAT_803e1e3c;
      FLOAT_803dd764 = FLOAT_803e1e60;
      DAT_803dd7d8 = 0;
      FLOAT_803dd768 = FLOAT_803e1e3c;
      if (DAT_803dba64 == 3) {
        FUN_8012ddd8(0x2b1,3,4,3);
        DAT_803dd780 = 4;
        if (DAT_803dd8e0 == DAT_803dd7d6) {
          DAT_803dd8d8 = FUN_800ea264();
        }
        else {
          DAT_803dd8d8 = FUN_80019bf0();
        }
        iVar4 = FUN_800221a0(0,1);
        FUN_8000d200(iVar4 + 0x271d,FUN_8000d138);
      }
      else if ((char)DAT_803dba64 < '\x03') {
        if (DAT_803dba64 == 1) {
          FUN_8012ddd8(0x2b1,1,2,3);
          DAT_803dd780 = 5;
          DAT_803dd7c4 = '\0';
          DAT_803dd7d8 = 2;
          FUN_8000d200(0x272f,FUN_8000d138);
        }
        else if ('\0' < (char)DAT_803dba64) {
          FUN_8012ddd8(0x2b1,DAT_803dba64,2,3);
          DAT_803dd780 = 3;
          DAT_803dd7c4 = '\0';
          iVar4 = FUN_800221a0(0,1);
          FUN_8000d200(iVar4 + 10000,FUN_8000d138);
        }
      }
      else if (DAT_803dba64 == 5) {
        DAT_803dd780 = 7;
        DAT_803dd7d8 = 1;
      }
      else if ((char)DAT_803dba64 < '\x05') {
        DAT_803dd780 = 6;
        DAT_803dd7d8 = 1;
      }
      if (*(int *)(&DAT_8031bff0 + (uint)DAT_803dd780 * 4) != 0) {
        iStack44 = *(int *)(&DAT_803a8980 + (uint)DAT_803dd780 * 4) * 0x3c;
        local_30 = 0x43300000;
        FLOAT_803dd820 = (float)((double)CONCAT44(0x43300000,iStack44) - DOUBLE_803e1e88);
        DAT_803dd81c = 1;
      }
    }
    FUN_8012c000();
    if (((uVar16 & 0x1200) != 0) && (DAT_803dd788 == '\0')) {
      FUN_8000bb18(0,0x100);
      FUN_8000bb18(0,0x3f2);
      DAT_803dd788 = '<';
      FUN_800571f0(1);
      FUN_800206e8(0);
      FUN_80014b3c(0,0x1200);
      DAT_803dd780 = 2;
      FUN_8012ddd8(0x2b1,DAT_803dba64,2,3);
    }
    break;
  case 2:
    DAT_803dd78c = DAT_803dd78c + (ushort)DAT_803db410 * -0x32;
    if (DAT_803dd78c < 0) {
      DAT_803dd78c = 0;
      if (bVar3) {
        DAT_803dd7cc = 1;
      }
      DAT_803dd780 = 0;
      if ((iVar4 == 0) || (iVar4 = FUN_80296c4c(iVar4), iVar4 == 0)) {
        FUN_8000d01c();
      }
      iVar4 = 0;
      piVar18 = &DAT_803a9410;
      do {
        if (*piVar18 != 0) {
          *(undefined4 *)(*(int *)(*piVar18 + 100) + 4) = 0;
          *(undefined4 *)(*(int *)(*piVar18 + 100) + 8) = 0;
          if (0x90000000 < *(uint *)(*piVar18 + 0x4c)) {
            *(undefined4 *)(*piVar18 + 0x4c) = 0;
          }
          FUN_8002cbc4(*piVar18);
          *piVar18 = 0;
        }
        piVar18 = piVar18 + 1;
        iVar4 = iVar4 + 1;
      } while (iVar4 < 4);
      FUN_8000a518(0x23,0);
      FUN_8012ddd8(0x2b1,DAT_803dba64,4,3);
    }
    else {
      FUN_8012c000();
    }
    DAT_803dd784 = DAT_803dd784 + (ushort)DAT_803db410 * -0x50;
    if (DAT_803dd784 < 0) {
      DAT_803dd784 = 0;
    }
    break;
  case 3:
    if ((DOUBLE_803e2160 < (double)FLOAT_803dd760) || (DOUBLE_803e2160 < (double)FLOAT_803dd764)) {
      uVar16 = FUN_8012b4c4();
      if (DAT_803dd7c4 == '\0') {
        DAT_803dd824 = &DAT_8031b818;
        FUN_800ea174(local_44);
        if (((uVar16 & 0xff) != 0) ||
           ((DOUBLE_803e2160 == (double)FLOAT_803dd760 && (DOUBLE_803e2160 < (double)FLOAT_803dd764)
            ))) {
          DAT_803dd7d8 = DAT_803dd8e0;
        }
        for (bVar13 = 0; bVar13 < 0xd; bVar13 = bVar13 + 1) {
          uVar15 = (uint)bVar13;
          if (local_44[uVar15] == '\0') {
            *(undefined2 *)(DAT_803dd824 + uVar15 * 0x20) = 0x49;
          }
          else {
            *(undefined2 *)(DAT_803dd824 + uVar15 * 0x20) = 0x48;
          }
          DAT_803dd824[uVar15 * 0x20 + 8] = 0x10;
          DAT_803dd824[uVar15 * 0x20 + 9] = 0xc;
        }
        if (DAT_803dd7d6 == DAT_803dd8e0) {
          *(undefined2 *)(DAT_803dd824 + DAT_803dd8e0 * 0x20) = 0x4c;
        }
        else {
          *(undefined2 *)(DAT_803dd824 + DAT_803dd8e0 * 0x20) = 0x4b;
          *(undefined2 *)(DAT_803dd824 + (uint)DAT_803dd7d6 * 0x20) = 0x4a;
          DAT_803dd824[(uint)DAT_803dd7d6 * 0x20 + 8] = 0x14;
          DAT_803dd824[(uint)DAT_803dd7d6 * 0x20 + 9] = 0x10;
        }
        DAT_803dd824[DAT_803dd8e0 * 0x20 + 8] = 0x1a;
        DAT_803dd824[DAT_803dd8e0 * 0x20 + 9] = 0x18;
      }
      else {
        DAT_803dd824 = &DAT_8031b9f0;
        for (bVar13 = 0; bVar13 < 0xc; bVar13 = bVar13 + 1) {
          uVar15 = (uint)bVar13;
          iVar4 = FUN_8001ffb4((int)(short)(&DAT_8031b9d8)[uVar15]);
          if (iVar4 == 0) {
            *(undefined2 *)(DAT_803dd824 + uVar15 * 0x20) = 0x25;
          }
          else {
            *(undefined2 *)(DAT_803dd824 + uVar15 * 0x20) = 0x26;
          }
        }
      }
      FUN_8012b978(uVar16);
      FUN_8012b77c();
    }
    else {
      if (DAT_803dd7c8 != 0) {
        FUN_80054308();
        DAT_803dd7c8 = 0;
      }
      FUN_8012ddd8(0x3a9,0,2,0);
      DAT_803dd780 = 1;
      DAT_803dd784 = 0;
    }
    break;
  case 4:
    if ((DOUBLE_803e2160 < (double)FLOAT_803dd760) || (DOUBLE_803e2160 < (double)FLOAT_803dd764)) {
      uVar16 = FUN_800ea2bc();
      DAT_803dd730 = uVar16 & 0xffff;
      DAT_803dd770 = 0;
      DAT_803dd772 = 0;
      FUN_8012b77c();
      if ((DAT_803dd7a4 == (short *)0x0) || (*DAT_803dd7a4 == -1)) {
        DAT_803dd7a4 = (short *)FUN_800ea238();
      }
    }
    else {
      FUN_80019970(DAT_803dd8d8);
      DAT_803dd780 = 1;
      DAT_803dd784 = 0;
      if (DAT_803dd7a4 != (short *)0x0) {
        DAT_803dd7a4 = (short *)0x0;
      }
    }
    break;
  case 5:
    if ((DOUBLE_803e2160 < (double)FLOAT_803dd760) || (DOUBLE_803e2160 < (double)FLOAT_803dd764)) {
      FUN_8012b4c4();
      if (DAT_803dd7c4 == '\0') {
        DAT_803dd824 = &DAT_8031bb90;
      }
      else {
        DAT_803dd824 = &DAT_8031bd90;
      }
      FUN_8012b978();
      uVar15 = 0;
      for (uVar16 = 0; -1 < (int)(&DAT_8031b560)[uVar16 & 0xff]; uVar16 = uVar16 + 1) {
        sVar17 = 0xbf0;
        iVar4 = FUN_8001ffb4();
        if (iVar4 != 0) {
          sVar17 = (&DAT_8031b57e)[(uVar16 & 0xff) * 8];
        }
        uVar7 = FUN_80054d54((int)sVar17);
        (&DAT_803a8b98)[uVar15 & 0xff] = uVar7;
        (&DAT_803a8b48)[uVar15 & 0xff] = sVar17;
        uVar15 = uVar15 + 1;
      }
      uVar15 = 10;
      uVar16 = 0;
      while (-1 < (short)(&DAT_8031b4e0)[(uVar16 & 0xff) * 8]) {
        sVar17 = 0xbf0;
        iVar4 = FUN_8001ffb4();
        if (iVar4 != 0) {
          sVar17 = (&DAT_8031b4e6)[(uVar16 & 0xff) * 8];
        }
        uVar7 = FUN_80054d54((int)sVar17);
        (&DAT_803a8b98)[uVar15 & 0xff] = uVar7;
        (&DAT_803a8b48)[uVar15 & 0xff] = sVar17;
        uVar15 = uVar15 + 1;
        uVar16 = uVar16 + 1;
      }
      uVar11 = 0xbf0;
      iVar4 = FUN_8001ffb4(0x1ee);
      if (iVar4 != 0) {
        uVar11 = 0xc8a;
      }
      DAT_803a8be8 = FUN_80054d54(uVar11);
      uVar12 = 0xbf0;
      DAT_803a8b70 = uVar11;
      iVar4 = FUN_8001ffb4(0x13e);
      if (iVar4 != 0) {
        uVar12 = 0xc06;
      }
      DAT_803a8bec = FUN_80054d54(uVar12);
      uVar11 = 0xbf0;
      DAT_803a8b72 = uVar12;
      iVar4 = FUN_8001ffb4(0xc64);
      if (iVar4 != 0) {
        uVar11 = 0xc05;
      }
      DAT_803a8bf0 = FUN_80054d54(uVar11);
      DAT_803a8b74 = uVar11;
      FUN_8012b77c();
    }
    else {
      for (bVar13 = 0; bVar13 < 0x28; bVar13 = bVar13 + 1) {
        if ((&DAT_803a8b98)[bVar13] != 0) {
          FUN_80054308();
          (&DAT_803a8b98)[bVar13] = 0;
          (&DAT_803a8b48)[bVar13] = 0;
        }
      }
      FUN_8012ddd8(0x3a9,0,2,0);
      DAT_803dd780 = 1;
      DAT_803dd784 = 0;
    }
    break;
  case 6:
  case 7:
  case 8:
  case 9:
  case 10:
    if ((DOUBLE_803e2160 < (double)FLOAT_803dd760) || (DOUBLE_803e2160 < (double)FLOAT_803dd764)) {
      DAT_803dd824 = &DAT_8031bd30;
      FUN_8012b978(0);
      FUN_8012b77c();
      if (((uVar16 & 0x100) != 0) && (DOUBLE_803e2160 < (double)FLOAT_803dd764)) {
        FUN_8000bb18(0,0x418);
        FUN_80014b3c(0,0x100);
        FLOAT_803dd764 = FLOAT_803e2168;
      }
    }
    else if (DAT_803dd7d8 == 1) {
      if (DAT_803dd780 == 9) {
        DAT_803dd780 = 10;
        FLOAT_803dd764 = FLOAT_803e1e60;
      }
      else {
        if (DAT_803dd780 < 9) {
          if (7 < DAT_803dd780) {
            if (DAT_803db424 == '\0') {
              DAT_803dd780 = 10;
            }
            else {
              DAT_803dd780 = 9;
            }
            FLOAT_803dd764 = FLOAT_803e1e60;
            break;
          }
        }
        else if (DAT_803dd780 < 0xb) {
          FUN_8000a518(0x23,0);
          iVar4 = (**(code **)(*DAT_803dcaac + 0x30))();
          if (iVar4 == 0) {
            (**(code **)(*DAT_803dcaac + 0x20))();
          }
          else {
            (**(code **)(*DAT_803dcaac + 0x28))();
          }
          break;
        }
        DAT_803dd780 = 1;
        DAT_803dd784 = 0;
      }
    }
    else if (DAT_803dd780 == 8) {
      *(char *)(iVar5 + 9) = *(char *)(iVar5 + 9) + -1;
      FUN_80296c84(iVar4);
      FUN_80019970(DAT_803dd8dc);
      DAT_803dd780 = 2;
      DAT_803dd788 = '<';
      FUN_8012ddd8(0x2b1,DAT_803dba64,2,3);
    }
    else {
      if (DAT_803dd780 < 8) {
        if (DAT_803dd780 != 6) {
          if (5 < DAT_803dd780) {
            FUN_800e86d0();
            DAT_803dd778 = 0x80;
            DAT_803dd780 = 1;
            DAT_803dd784 = 0;
          }
          break;
        }
      }
      else if (DAT_803dd780 != 10) {
        if (DAT_803dd780 < 10) {
          FUN_800e9948();
          FUN_800e86d0();
          DAT_803dd778 = 0x80;
          DAT_803dd780 = 10;
          DAT_803dd7d8 = 1;
          FLOAT_803dd764 = FLOAT_803e1e60;
          DAT_803dd784 = 0;
        }
        break;
      }
      DAT_803dd8dc = 0x15;
      FUN_80019970(0x15);
      DAT_803dd77e = 0;
      DAT_803dd774 = 0;
      DAT_803dd776 = 0;
      DAT_803dba5c = 0xffffffff;
      FUN_8012ddd8(0x2b1,1,4,3);
      DAT_803dd780 = 2;
      DAT_803dd788 = '<';
      (**(code **)(*DAT_803dca4c + 8))(0x14,1);
      DAT_803dd794 = 1;
    }
    break;
  case 0xb:
    if ((DOUBLE_803e2160 < (double)FLOAT_803dd760) || (DOUBLE_803e2160 < (double)FLOAT_803dd764)) {
      iVar5 = FUN_8001ffb4(0x3f5);
      DAT_803dd758 = '\0';
      if ((iVar4 != 0) &&
         (DAT_803dd8e0 = FUN_8005afac((double)*(float *)(iVar4 + 0xc),
                                      (double)*(float *)(iVar4 + 0x14)), DAT_803dd8e0 == 7)) {
        DAT_803dd756 = 0;
        while( true ) {
          if ((3 < DAT_803dd756) ||
             (iVar4 = FUN_8001ffb4((int)*(short *)(&DAT_8031b030 + DAT_803dd756 * 8)), iVar4 == 0))
          goto LAB_8012b3a4;
          iVar4 = FUN_8001ffb4((int)*(short *)(&DAT_8031b032 + DAT_803dd756 * 8));
          if (iVar4 == 0) break;
          DAT_803dd756 = DAT_803dd756 + 1;
        }
        if (iVar5 < (int)(uint)(byte)(&DAT_8031b034)[DAT_803dd756 * 8]) {
          DAT_803dd758 = '\x01';
        }
        else {
          DAT_803dd758 = '\x02';
        }
      }
LAB_8012b3a4:
      if ((((uVar16 & 0x100) == 0) || ((double)FLOAT_803dd764 <= DOUBLE_803e2160)) ||
         ((double)FLOAT_803dd760 < DOUBLE_803e1f60)) {
        if ((((uVar16 & 0x200) != 0) && (DOUBLE_803e2160 < (double)FLOAT_803dd764)) &&
           (DOUBLE_803e1f60 <= (double)FLOAT_803dd760)) {
          FUN_80014b3c(0,0x200);
          FLOAT_803dd764 = FLOAT_803e2168;
          DAT_803dd759 = 0;
        }
      }
      else {
        if (DAT_803dd758 == '\x02') {
          FUN_800200e8(0x3f5,iVar5 - (uint)(byte)(&DAT_8031b034)[DAT_803dd756 * 8]);
          FUN_800200e8((int)*(short *)(&DAT_8031b032 + DAT_803dd756 * 8),1);
        }
        DAT_803dd759 = 1;
        FUN_80014b3c(0,0x100);
        FLOAT_803dd764 = FLOAT_803e2168;
      }
      FUN_8012b77c();
    }
    else {
      FUN_800206e8(0);
      FUN_800571f0(1);
      DAT_803dd780 = 2;
      DAT_803dd788 = '<';
    }
  }
  FUN_8028611c();
  return;
}

