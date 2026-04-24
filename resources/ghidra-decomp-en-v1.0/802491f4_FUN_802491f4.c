// Function: FUN_802491f4
// Entry: 802491f4
// Size: 252 bytes

void FUN_802491f4(void)

{
  if (DAT_803ddf48 == 0) {
    FUN_80240d34();
    DAT_803ddf48 = 1;
    FUN_80248870();
    FUN_8024b970();
    FUN_80247a1c();
    DAT_803ddf10 = -0x80000000;
    DAT_803ddf0c = 0x80000000;
    FUN_802437c8(0x15,&LAB_80247a5c);
    FUN_80243bcc(0x400);
    FUN_80245d78(&DAT_803ddf00);
    write_volatile_4(DAT_cc006000,0x2a);
    write_volatile_4(DAT_cc006004,0);
    if (*(int *)(DAT_803ddf10 + 0x20) == -0x1adf83de) {
      FUN_8007d6dc(s_app_booted_via_JTAG_8032dc20);
      FUN_8007d6dc(s_load_fst_8032dc38);
      FUN_8024bdd8();
    }
    else if (*(int *)(DAT_803ddf10 + 0x20) == 0xd15ea5e) {
      FUN_8007d6dc(s_app_booted_from_bootrom_8032dc44);
    }
    else {
      DAT_803ddf44 = 1;
      FUN_8007d6dc(s_bootrom_8032dc60);
    }
  }
  return;
}

