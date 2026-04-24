// Function: FUN_8011a280
// Entry: 8011a280
// Size: 400 bytes

void FUN_8011a280(int param_1,char param_2)

{
  DAT_803dd6b0 = DAT_803dd6a8;
  if (param_1 == 0) {
    FUN_8000bb18(0,0x100);
    (**(code **)(*DAT_803dca4c + 8))(0x14,5);
    DAT_803dd6cf = 0x23;
    DAT_803dd6cc = 1;
  }
  else if ((param_1 != -1) && (param_1 == 1)) {
    DAT_803dd6a4 = param_2;
    if (*(char *)(DAT_803dd6a8 + param_2 * 0x24 + 0x20) == '\0') {
      FUN_80014948(6);
    }
    else {
      FUN_8000bb18(0,0x418);
      if (DAT_803db9fb != -1) {
        (**(code **)(*DAT_803dcaa0 + 8))();
      }
      DAT_803db9fb = '\x01';
      *(ushort *)(PTR_DAT_8031a7c8 + 0x16) = *(ushort *)(PTR_DAT_8031a7c8 + 0x16) & 0xbfff;
      PTR_DAT_8031a7c8[0x56] = 0;
      *(undefined2 *)(PTR_DAT_8031a7c8 + 0x3c) = 0x3d6;
      DAT_803dd6c5 = 0;
      (**(code **)(*DAT_803dcaa0 + 4))
                (PTR_DAT_8031a7c8,DAT_8031a7cc,0,0,5,4,0x14,200,0xff,0xff,0xff,0xff);
      (**(code **)(*DAT_803dcaa0 + 0x18))(0);
      DAT_803dd6bc = 0;
      DAT_803dd6bd = 0;
      DAT_803dd6be = 0;
      DAT_803dd6ce = 2;
    }
  }
  return;
}

