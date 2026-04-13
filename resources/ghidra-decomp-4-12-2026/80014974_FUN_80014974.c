// Function: FUN_80014974
// Entry: 80014974
// Size: 176 bytes

/* WARNING: Removing unreachable block (ram,0x800149bc) */

void FUN_80014974(int param_1)

{
  if (((param_1 != DAT_803dd570) && (DAT_803dd56c = param_1 + 1, DAT_803dd568 == 0)) &&
     (DAT_803dd56c != 0)) {
    DAT_803dd574 = DAT_803dd570;
    if (*(uint *)(&DAT_802c7588 + param_1 * 4) == 0xffffffff) {
      DAT_803dd568 = 0;
      DAT_803dd56c = 0;
    }
    else {
      DAT_803dd56c = param_1;
      DAT_803dd568 = FUN_80013ee8(*(uint *)(&DAT_802c7588 + param_1 * 4) & 0xffff);
    }
    DAT_803dd570 = DAT_803dd56c;
    DAT_803dd56c = 0;
  }
  return;
}

