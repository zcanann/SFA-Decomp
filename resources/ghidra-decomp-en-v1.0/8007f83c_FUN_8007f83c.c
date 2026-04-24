// Function: FUN_8007f83c
// Entry: 8007f83c
// Size: 1468 bytes

undefined4 FUN_8007f83c(char param_1)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  uint local_88;
  uint local_84;
  undefined auStack128 [46];
  byte local_52;
  int local_50;
  ushort local_4c;
  ushort local_4a;
  int local_48;
  
  bVar2 = false;
  bVar3 = false;
  iVar4 = FUN_8007de0c(0);
  if (iVar4 == 0) {
    bVar1 = false;
  }
  else {
    DAT_803dd040 = FUN_80023cc8(0xa000,0xffffffff,0);
    if (DAT_803dd040 == 0) {
      DAT_803db700 = 8;
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
  }
  if (bVar1) {
    DAT_803db700 = 0;
    iVar4 = FUN_802623ac(0,DAT_803dd040,&LAB_8007fdf8);
    if (iVar4 == -6) {
      iVar4 = FUN_80261a28(0);
    }
    if ((iVar4 == 0) || (iVar4 == -0xd)) {
      iVar5 = FUN_80261a28(0);
      iVar4 = FUN_802643e8(0,&local_88);
      if (iVar4 == 0) {
        iVar4 = iVar5;
        if (DAT_803dd059 == '\0') {
          DAT_803dd04c = local_84;
          DAT_803dd048 = local_88;
        }
        else if ((DAT_803dd04c | DAT_803dd048) == 0) {
          DAT_803dd04c = local_84;
          DAT_803dd048 = local_88;
        }
        else if ((local_84 ^ DAT_803dd04c | local_88 ^ DAT_803dd048) != 0) {
          DAT_803db700 = 0xb;
          iVar4 = -0x55;
        }
      }
    }
    if (iVar4 == 0) {
      iVar4 = FUN_80262fac(0,DAT_803db704,&DAT_80396900);
      if ((iVar4 == -4) && (param_1 == '\0')) {
        bVar2 = true;
        bVar3 = true;
      }
      if (iVar4 == 0) {
        DAT_803dd05a = '\x01';
      }
    }
    if (((iVar4 == 0) && (iVar4 = FUN_80264100(0,DAT_80396904,auStack128), iVar4 == 0)) &&
       ((local_50 == -1 || (local_48 == -1)))) {
      if (param_1 == '\0') {
        bVar3 = true;
      }
      else {
        iVar4 = -4;
      }
    }
    if (bVar3) {
      DAT_803dd05c = FUN_80023cc8(0x4000,0xffffffff,0);
      if (DAT_803dd05c == 0) {
        DAT_803db700 = 8;
        FUN_80262490(0);
        FUN_80023800(DAT_803dd040);
        DAT_803dd040 = 0;
        return 0;
      }
      FUN_800033a8(DAT_803dd05c,0,0x4000);
      FUN_8007f2e0();
    }
    if (bVar2) {
      iVar4 = FUN_802634d0(0,DAT_803db704,0x6000,&DAT_80396900);
    }
    if (bVar3) {
      if (iVar4 == 0) {
        iVar4 = FUN_80263cc4(&DAT_80396900,DAT_803dd05c,0x4000,0);
        if (iVar4 == 0) {
          iVar4 = FUN_80263cc4(&DAT_80396900,DAT_803dd05c + 0x2000,0x2000,0x4000);
        }
        if (iVar4 == -5) {
          FUN_80263ec0(0,DAT_803db704);
        }
        if ((bVar2) && (iVar4 == 0)) {
          iVar4 = FUN_80264100(0,DAT_80396904,auStack128);
        }
        if (iVar4 == 0) {
          local_48 = 0;
          local_50 = 0x40;
          local_52 = local_52 & 0xf8 | 6;
          local_4c = local_4c & 0xff00 | 0x55;
          local_4a = local_4a & 0xfc00 | 0xff;
          iVar4 = FUN_802643a0(0,DAT_80396904,auStack128);
          if (iVar4 == 0) {
            DAT_803dd050 = *(undefined4 *)(DAT_803dd05c + 0x3ff8);
            DAT_803dd054 = *(undefined4 *)(DAT_803dd05c + 0x3ffc);
          }
        }
      }
      FUN_80023800(DAT_803dd05c);
    }
    if (iVar4 == -6) {
      DAT_803db700 = 5;
    }
    else if (iVar4 < -6) {
      if (iVar4 == -0xd) {
        DAT_803db700 = 6;
      }
      else if (((-0xe < iVar4) && (iVar4 < -7)) && (-10 < iVar4)) {
        DAT_803db700 = 9;
      }
    }
    else {
      if (iVar4 == 0) {
        if (!bVar3) {
          return 2;
        }
        return 1;
      }
      if (iVar4 < 0) {
        if (iVar4 == -3) {
          if (DAT_803db700 != 3) {
            DAT_803db700 = 2;
          }
        }
        else if (iVar4 < -3) {
          if (iVar4 < -4) {
            DAT_803db700 = 4;
          }
          else {
            DAT_803db700 = 0xc;
          }
        }
      }
      else if (iVar4 < 2) {
        DAT_803db700 = 1;
      }
    }
    if (DAT_803dd05a != '\0') {
      DAT_803dd05a = '\0';
      FUN_80263124(&DAT_80396900);
    }
    FUN_80262490(0);
    FUN_80023800(DAT_803dd040);
    DAT_803dd040 = 0;
  }
  return 0;
}

