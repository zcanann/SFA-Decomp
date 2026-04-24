// Function: FUN_800202cc
// Entry: 800202cc
// Size: 828 bytes

/* WARNING: Removing unreachable block (ram,0x8002032c) */

void FUN_800202cc(void)

{
  bool bVar1;
  uint uVar2;
  
  if ((DAT_803dcca6 != '\0') && (DAT_803dc951 == '\0')) {
    DAT_803dcca6 = '\0';
    if (DAT_803dca3d == 4) {
      FUN_8007d6dc(s_GAME_STATE_RESETNOW_802ca54c);
      while ((DAT_803dc950 == '\0' && ((DAT_803dc848 != '\0' || (DAT_803dc849 != '\0'))))) {
        DAT_803dc960 = FUN_8024b36c();
        switch(DAT_803dc960) {
        case 4:
          DAT_803dc950 = '\x01';
          break;
        case 5:
          DAT_803dc950 = '\x01';
          break;
        case 6:
          DAT_803dc950 = '\x01';
          break;
        case 0xb:
          DAT_803dc950 = '\x01';
          break;
        case 0xffffffff:
          DAT_803dc950 = '\x01';
        }
      }
      FUN_8024f7d0(0);
      FUN_80009b14();
      FUN_8007d6dc(s_audioQuit_passed_802ca564);
      FUN_80014a28();
      FUN_8004a868();
      FUN_8004a43c(1,0);
      FUN_8004a868();
      FUN_8004a43c(1,0);
      FUN_8007d6dc(s_GX_flush_passed_802ca578);
      FUN_80241c40();
      FUN_8024b418(1);
      FUN_8024d6dc(1);
      FUN_8024d554();
      FUN_8024c8f0();
      FUN_8007d6dc(s_VIFlush_passed_802ca58c);
      DAT_803dca3d = 5;
      if (DAT_803dcac5 == '\0') {
        FUN_802448a8(0,0x80000000,0);
      }
      else {
        FUN_802448a8(1,0x80000000,1);
      }
    }
    else {
      if (DAT_803dca3d < 4) {
        if (DAT_803dca3d != 2) {
          if (1 < DAT_803dca3d) {
            FLOAT_803dcb00 = FLOAT_803dcb00 - FLOAT_803de7a8;
            if (FLOAT_803de7b0 < FLOAT_803dcb00) {
              DAT_803dcca6 = 0;
              return;
            }
            DAT_803dca3d = 4;
            DAT_803dcca6 = 0;
            return;
          }
          if (DAT_803dca3e != '\0') {
            DAT_803dca3d = 2;
          }
          uVar2 = FUN_80014ec4(0);
          if ((((uVar2 & 0x200) == 0) || (uVar2 = FUN_80014ec4(0), (uVar2 & 0x400) == 0)) ||
             (uVar2 = FUN_80014ec4(0), (uVar2 & 0x1000) == 0)) {
            bVar1 = false;
            if (DAT_803db425 != '\0') {
              DAT_803db425 = DAT_803db425 + -1;
            }
          }
          else {
            bVar1 = true;
          }
          if ((bVar1) && (DAT_803db425 == '\0')) {
            FLOAT_803dcac8 = FLOAT_803dcac8 + FLOAT_803de7a8;
            if (FLOAT_803dcac8 < FLOAT_803de7ac) {
              return;
            }
            DAT_803dca3d = 2;
            return;
          }
          FLOAT_803dcac8 = FLOAT_803de7b0;
          return;
        }
      }
      else if (DAT_803dca3d != 6) {
        FUN_8007d6dc(s_reset_default_802ca59c);
        return;
      }
      FUN_8007d6dc(s_GAME_STATE_RESETPRESSED_802ca530);
      if (DAT_803dca49 != '\0') {
        (**(code **)(*DAT_803dca4c + 8))(0x1e,1);
      }
      DAT_803dcac5 = DAT_803dca3d == 6;
      FUN_80014a28();
      FUN_8024fa90(0);
      FUN_8024fabc(0);
      FUN_80009b4c();
      DAT_803dca3d = 3;
      FLOAT_803dcb00 = FLOAT_803de7ac;
    }
  }
  return;
}

