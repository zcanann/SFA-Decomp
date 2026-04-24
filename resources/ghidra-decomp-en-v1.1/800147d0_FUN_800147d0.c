// Function: FUN_800147d0
// Entry: 800147d0
// Size: 184 bytes

void FUN_800147d0(void)

{
  if (DAT_803dd568 != (int *)0x0) {
    (**(code **)(*DAT_803dd568 + 8))();
  }
  if (DAT_803dd56c != 0) {
    DAT_803dd56c = DAT_803dd56c + -1;
    DAT_803dd574 = DAT_803dd570;
    if (DAT_803dd568 != (int *)0x0) {
      FUN_80013e4c((undefined *)DAT_803dd568);
      DAT_803dd568 = (int *)0x0;
    }
    if (*(uint *)(&DAT_802c7588 + DAT_803dd56c * 4) == 0xffffffff) {
      DAT_803dd568 = (int *)0x0;
      DAT_803dd56c = 0;
    }
    else {
      DAT_803dd568 = (int *)FUN_80013ee8(*(uint *)(&DAT_802c7588 + DAT_803dd56c * 4) & 0xffff);
    }
    DAT_803dd570 = DAT_803dd56c;
    DAT_803dd56c = 0;
  }
  return;
}

