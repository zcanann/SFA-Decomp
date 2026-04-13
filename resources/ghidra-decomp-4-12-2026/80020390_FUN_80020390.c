// Function: FUN_80020390
// Entry: 80020390
// Size: 828 bytes

/* WARNING: Removing unreachable block (ram,0x800203f0) */

uint FUN_80020390(void)

{
  uint uVar1;
  bool bVar2;
  
  uVar1 = 0x802d0000;
  if ((DAT_803dd926 != '\0') && (DAT_803dd5d1 == '\0')) {
    DAT_803dd926 = '\0';
    if (DAT_803dd6bd == 4) {
      FUN_8007d858();
      while ((DAT_803dd5d0 == '\0' && ((DAT_803dd4c8 != '\0' || (DAT_803dd4c9 != '\0'))))) {
        DAT_803dd5e0 = FUN_8024bad0();
        switch(DAT_803dd5e0) {
        case 4:
          DAT_803dd5d0 = '\x01';
          break;
        case 5:
          DAT_803dd5d0 = '\x01';
          break;
        case 6:
          DAT_803dd5d0 = '\x01';
          break;
        case 0xb:
          DAT_803dd5d0 = '\x01';
          break;
        case -1:
          DAT_803dd5d0 = '\x01';
        }
      }
      FUN_8024ff34(0);
      FUN_80009b14();
      FUN_8007d858();
      FUN_80014a54();
      FUN_8004a9e4();
      FUN_8004a5b8('\x01');
      FUN_8004a9e4();
      FUN_8004a5b8('\x01');
      FUN_8007d858();
      FUN_80242338();
      FUN_8024bb7c(1);
      FUN_8024de40(1);
      FUN_8024dcb8();
      FUN_8024d054();
      FUN_8007d858();
      DAT_803dd6bd = 5;
      if (DAT_803dd745 == '\0') {
        bVar2 = FUN_80244fa0(0,-0x80000000,0);
        uVar1 = (uint)bVar2;
      }
      else {
        bVar2 = FUN_80244fa0(1,-0x80000000,1);
        uVar1 = (uint)bVar2;
      }
    }
    else {
      if (DAT_803dd6bd < 4) {
        if (DAT_803dd6bd != 2) {
          if (1 < DAT_803dd6bd) {
            FLOAT_803dd780 = FLOAT_803dd780 - FLOAT_803df428;
            if (FLOAT_803df430 < FLOAT_803dd780) {
              DAT_803dd926 = 0;
              return 0x802d0000;
            }
            DAT_803dd6bd = 4;
            DAT_803dd926 = 0;
            return 0x802d0000;
          }
          if (DAT_803dd6be != '\0') {
            DAT_803dd6bd = 2;
          }
          uVar1 = FUN_80014ef0(0);
          if ((((uVar1 & 0x200) == 0) || (uVar1 = FUN_80014ef0(0), (uVar1 & 0x400) == 0)) ||
             (uVar1 = FUN_80014ef0(0), (uVar1 & 0x1000) == 0)) {
            bVar2 = false;
            uVar1 = (uint)DAT_803dc085;
            if (uVar1 != 0) {
              DAT_803dc085 = DAT_803dc085 - 1;
            }
          }
          else {
            bVar2 = true;
          }
          if ((bVar2) && (DAT_803dc085 == 0)) {
            FLOAT_803dd748 = FLOAT_803dd748 + FLOAT_803df428;
            if (FLOAT_803dd748 < FLOAT_803df42c) {
              return uVar1;
            }
            DAT_803dd6bd = 2;
            return uVar1;
          }
          FLOAT_803dd748 = FLOAT_803df430;
          return uVar1;
        }
      }
      else if (DAT_803dd6bd != 6) {
        uVar1 = FUN_8007d858();
        return uVar1;
      }
      FUN_8007d858();
      if (DAT_803dd6c9 != '\0') {
        (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
      }
      DAT_803dd745 = DAT_803dd6bd == 6;
      FUN_80014a54();
      FUN_802501f4(0);
      FUN_80250220(0);
      uVar1 = FUN_80009b4c();
      DAT_803dd6bd = 3;
      FLOAT_803dd780 = FLOAT_803df42c;
    }
  }
  return uVar1;
}

