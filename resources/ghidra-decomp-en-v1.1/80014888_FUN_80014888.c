// Function: FUN_80014888
// Entry: 80014888
// Size: 204 bytes

undefined4 FUN_80014888(void)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  if (DAT_803dd568 != (int *)0x0) {
    uVar1 = (**(code **)(*DAT_803dd568 + 4))();
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
  return uVar1;
}

