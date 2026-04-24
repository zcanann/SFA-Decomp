// Function: FUN_8011a528
// Entry: 8011a528
// Size: 400 bytes

void FUN_8011a528(int param_1,char param_2)

{
  DAT_803de330 = DAT_803de328;
  if (param_1 == 0) {
    FUN_8000bb38(0,0x100);
    (**(code **)(*DAT_803dd6cc + 8))(0x14,5);
    DAT_803de34f = 0x23;
    DAT_803de34c = 1;
  }
  else if ((param_1 != -1) && (param_1 == 1)) {
    DAT_803de324 = param_2;
    if (*(char *)(DAT_803de328 + param_2 * 0x24 + 0x20) == '\0') {
      FUN_80014974(6);
    }
    else {
      FUN_8000bb38(0,0x418);
      if (DAT_803dc65b != -1) {
        (**(code **)(*DAT_803dd720 + 8))();
      }
      DAT_803dc65b = '\x01';
      *(ushort *)(PTR_DAT_8031b418 + 0x16) = *(ushort *)(PTR_DAT_8031b418 + 0x16) & 0xbfff;
      PTR_DAT_8031b418[0x56] = 0;
      *(undefined2 *)(PTR_DAT_8031b418 + 0x3c) = 0x3d6;
      DAT_803de345 = 0;
      (**(code **)(*DAT_803dd720 + 4))
                (PTR_DAT_8031b418,DAT_8031b41c,0,0,5,4,0x14,200,0xff,0xff,0xff,0xff);
      (**(code **)(*DAT_803dd720 + 0x18))(0);
      DAT_803de33c = 0;
      DAT_803de33d = 0;
      DAT_803de33e = 0;
      DAT_803de34e = 2;
    }
  }
  return;
}

