// Function: FUN_8012df68
// Entry: 8012df68
// Size: 2328 bytes

void FUN_8012df68(void)

{
  bool bVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  short sVar9;
  
  FUN_802860d4();
  iVar3 = FUN_8002b9ec();
  DAT_803dd8c0 = 0xffff;
  if (iVar3 == 0) goto LAB_8012e868;
  iVar4 = (**(code **)(*DAT_803dca50 + 0x10))();
  if (((iVar4 == 0x44) || ((*(ushort *)(iVar3 + 0xb0) & 0x1000) != 0)) || (DAT_803dd780 != '\0')) {
    FUN_80014b3c(0,0xe0800);
  }
  else if (DAT_803dd7b4 != '\0') {
    FUN_80014b3c(0);
  }
  DAT_803dd8a4 = FUN_80014e70(0);
  uVar7 = DAT_803dd8a4 & 0xffff;
  iVar4 = (**(code **)(*DAT_803dca50 + 0x10))();
  if (((iVar4 == 0x44) || ((*(ushort *)(iVar3 + 0xb0) & 0x1000) != 0)) ||
     ((DAT_803dd780 != '\0' || ((DAT_803dd7b4 != '\0' || (DAT_803dd75b != '\0')))))) {
    DAT_803dd8a4 = DAT_803dd8a4 | 0x200;
  }
  else if (DAT_803dd8ac != '\0') {
    DAT_803dd8a4 = DAT_803dd8a0;
    uVar7 = DAT_803dd8a0 & 0xffff;
  }
  if (DAT_803dd8b8 == '\x01') {
    FUN_8000bb18(0,0xfd);
  }
  else if (('\0' < DAT_803dd8b8) && (DAT_803dd8b8 < '\x03')) {
    FUN_8000bb18(0,0xfb);
  }
  DAT_803dd8c2 = 0xffff;
  DAT_803dd8b8 = '\0';
  iVar4 = (int)DAT_803dd8b6;
  uVar8 = *(undefined4 *)(&DAT_8031b5e0 + iVar4 * 0x10);
  bVar1 = iVar4 == 2;
  DAT_803dd8b4 = (&DAT_8031b5dc)[iVar4 * 8];
  DAT_803dd8b0 = FUN_801242dc((&PTR_DAT_8031b5d8)[iVar4 * 4],bVar1);
  if (DAT_803dd884 == 2) {
    iVar6 = FUN_8001ffb4(0x4e4);
    if (iVar6 == 0) {
      DAT_803dd884 = 0;
      DAT_803dd874 = 0xffff;
    }
    if ((DAT_803dd738 & 1 << (uint)DAT_803dd88a) == 0) {
      DAT_803dd87c = '\x01';
    }
    else {
      DAT_803dd87c = '\0';
    }
  }
  else if (DAT_803dd884 < 2) {
    if (DAT_803dd884 != 0) {
LAB_8012e1a4:
      iVar6 = FUN_8001ffb4(DAT_803dd88a);
      if ((iVar6 == 0) || ((-1 < DAT_803dd886 && (iVar6 = FUN_8001ffb4(), iVar6 != 0)))) {
        DAT_803dd884 = 0;
        DAT_803dd874 = 0xffff;
      }
      else if ((DAT_803dd888 < 0) || (iVar6 = FUN_8001ffb4(), iVar6 == 0)) {
        DAT_803dd87c = '\0';
      }
      else {
        DAT_803dd87c = '\x01';
      }
    }
  }
  else if (DAT_803dd884 < 4) goto LAB_8012e1a4;
  if (DAT_803dd8b0 <= DAT_803dd8b4) {
    DAT_803dd8b4 = 0;
  }
  if (DAT_803dd795 == '\0') {
    bVar2 = false;
  }
  else if (DAT_803dd8d6 == DAT_803dba66) {
    bVar2 = true;
  }
  else {
    bVar2 = false;
  }
  if (bVar2) {
    iVar6 = (int)DAT_803dd8b4;
    DAT_803dd8c0 = (ushort)(&DAT_803a9038)[iVar6];
    DAT_803dd8bc = (short)(&DAT_803a8e38)[iVar6];
    DAT_803dd8be = (short)(&DAT_803a8f38)[iVar6];
    if (DAT_803dd7aa == 0) {
      DAT_803dd7aa = (&DAT_803a8d38)[iVar6];
    }
    if (DAT_803dd7ac == '\0') {
      DAT_803dd7ac = '\n';
    }
    sVar9 = DAT_803dd89c;
    if (DAT_803dd8ac == '\0') {
      cVar5 = FUN_80014bc4(0);
      sVar9 = (short)cVar5;
    }
    if (((sVar9 < -9) && (-10 < DAT_803dd790)) || (sVar9 < -0x3c)) {
      iVar6 = (int)DAT_803dd796;
      if (iVar6 < 0) {
        iVar6 = -iVar6;
      }
      if (((7 < iVar6) || (DAT_803dd7b8 != '\0')) || (DAT_803dd79a != 0)) goto LAB_8012e360;
      if (DAT_803dba65 == '\0') {
        FUN_8000bb18(0,0xfc);
      }
      DAT_803dd7b6 = 1;
    }
    else {
LAB_8012e360:
      if (((9 < sVar9) && (DAT_803dd790 < 10)) || (0x3c < sVar9)) {
        iVar6 = (int)DAT_803dd796;
        if (iVar6 < 0) {
          iVar6 = -iVar6;
        }
        if (((iVar6 < 8) && (DAT_803dd7b8 == '\0')) && (DAT_803dd79a == 0)) {
          if (DAT_803dba65 == '\0') {
            FUN_8000bb18(0,0xfc);
          }
          DAT_803dd7b6 = -1;
        }
      }
    }
    if (0xff < DAT_803dd7b6) {
      DAT_803dd7b6 = 0xff;
    }
    if (DAT_803dd7b6 < -0xff) {
      DAT_803dd7b6 = -0xff;
    }
    if (DAT_803dd894 != -1) {
      DAT_803dd8b4 = DAT_803dd894;
    }
    DAT_803dd790 = sVar9;
    if ((DAT_803dd7b6 == 0) || (DAT_803dd796 != 0)) {
      if ((DAT_803dd8a4 & 0x200) == 0) {
        if ((uVar7 & 0x900) != 0) {
          if (DAT_803dd795 == '\0') {
            bVar2 = false;
          }
          else if (DAT_803dd8d6 == DAT_803dba66) {
            bVar2 = true;
          }
          else {
            bVar2 = false;
          }
          if (bVar2) {
            bVar2 = false;
            if ((uVar7 & 0x800) != 0) {
              if ((DAT_803dd884 == 0) || ((uint)DAT_803dd88a != (int)(short)DAT_803dd8c0)) {
                FUN_8000bb18(0,0x408);
                DAT_803dd874 = (&DAT_803a9138)[DAT_803dd8b4];
                DAT_803dd88a = DAT_803dd8c0;
                DAT_803dd888 = DAT_803dd8be;
                DAT_803dd886 = DAT_803dd8bc;
                FLOAT_803dd878 = FLOAT_803dba84;
                if (bVar1) {
                  DAT_803dd884 = 2;
                }
                else {
                  DAT_803dd880 = uVar8;
                  if (DAT_803dd7d4 == '\x04') {
                    DAT_803dd884 = 1;
                  }
                  else {
                    DAT_803dd884 = 3;
                  }
                }
              }
              else {
                bVar2 = true;
              }
            }
            FUN_80014b3c(0,0x900);
            if (bVar1) {
              if ((&DAT_803a8c78)[DAT_803dd8b4] == '\0') {
                DAT_803dd8c2 = 0xffff;
                DAT_803dd8b8 = '\0';
                FUN_8000bb18(0,0xfd);
              }
              else if (((uVar7 & 0x100) != 0) || (bVar2)) {
                DAT_803dd795 = '\0';
                DAT_803dd8c2 = DAT_803dd8c0;
                FUN_8011d918(iVar3);
                DAT_803dd8b8 = '\0';
              }
            }
            else if ((&DAT_803a8c78)[DAT_803dd8b4] == '\0') {
              DAT_803dd8c2 = 0xffff;
              DAT_803dd8b8 = '\0';
              FUN_8000bb18(0,0xfd);
            }
            else {
              if (((uVar7 & 0x100) != 0) || (bVar2)) {
                FUN_800378c4(iVar3,uVar8,0,(int)(short)DAT_803dd8c0);
                DAT_803dd8c2 = DAT_803dd8c0;
                DAT_803dd8b8 = (&DAT_803a8cb8)[DAT_803dd8b4];
                DAT_803dd795 = '\0';
              }
              FUN_8000bb18(0,0xf7);
            }
          }
        }
      }
      else {
        FUN_8000bb18(0,0x37c);
        DAT_803dd795 = '\0';
      }
    }
    else if (DAT_803dd7b6 < 1) {
      DAT_803dd7b6 = DAT_803dd7b6 + 1;
      if (1 < DAT_803dd8b0) {
        if ((DAT_803dd8b0 == 2) && (DAT_803dd8b4 == 0)) {
          DAT_803dd796 = -100;
        }
        else {
          DAT_803dd796 = -0x32;
        }
        DAT_803dba65 = -3;
        DAT_803dd7b8 = '\0';
        DAT_803dd8b4 = DAT_803dd8b4 + -1;
        if (DAT_803dd8b4 < 0) {
          DAT_803dd8b4 = (short)DAT_803dd8b0 + -1;
        }
      }
    }
    else {
      DAT_803dd7b6 = DAT_803dd7b6 + -1;
      if (1 < DAT_803dd8b0) {
        if ((DAT_803dd8b0 == 2) && (DAT_803dd8b4 == 1)) {
          DAT_803dd796 = 100;
        }
        else {
          DAT_803dd796 = 0x32;
        }
        DAT_803dba65 = '\x03';
        DAT_803dd7b8 = '\0';
        DAT_803dd8b4 = DAT_803dd8b4 + 1;
        if (DAT_803dd8b0 <= DAT_803dd8b4) {
          DAT_803dd8b4 = 0;
        }
      }
    }
  }
  else if ((uVar7 & 0x800) != 0) {
    if ((DAT_803dd884 == 3) && (DAT_803dd87c == '\0')) {
      FUN_800378c4(iVar3,DAT_803dd880,0,DAT_803dd88a);
      DAT_803dd8c2 = DAT_803dd88a;
      FUN_80014b3c(0,0x900);
    }
    else if ((DAT_803dd884 == 2) && ((DAT_803dd738 & 1 << (uint)DAT_803dd88a) != 0)) {
      DAT_803dd8c2 = DAT_803dd88a;
      FUN_8011d918(iVar3);
      FUN_80014b3c(0,0x900);
    }
  }
  if (DAT_803dd793 != '\0') {
    FUN_80124d80();
  }
  if (DAT_803dd795 == '\0') {
    if (DAT_803dd8d6 == 0) {
      bVar1 = true;
    }
    else {
      bVar1 = false;
    }
  }
  else {
    bVar1 = false;
  }
  if (bVar1) {
    DAT_803dd7d4 = '\0';
    DAT_803dd8a8 = 0;
    DAT_803dd7b6 = 0;
  }
  if (DAT_803dd795 != '\0') {
    FUN_80014b3c(0,0x300);
  }
  (&DAT_8031b5dc)[iVar4 * 8] = DAT_803dd8b4;
LAB_8012e868:
  FUN_80286120();
  return;
}

