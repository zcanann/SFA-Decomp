// Function: FUN_80014948
// Entry: 80014948
// Size: 176 bytes

/* WARNING: Removing unreachable block (ram,0x80014990) */

void FUN_80014948(int param_1)

{
  if (((param_1 != DAT_803dc8f0) && (DAT_803dc8ec = param_1 + 1, DAT_803dc8e8 == 0)) &&
     (DAT_803dc8ec != 0)) {
    DAT_803dc8f4 = DAT_803dc8f0;
    if (*(uint *)(&DAT_802c6e08 + param_1 * 4) == 0xffffffff) {
      DAT_803dc8e8 = 0;
      DAT_803dc8ec = 0;
    }
    else {
      DAT_803dc8ec = param_1;
      DAT_803dc8e8 = FUN_80013ec8(*(uint *)(&DAT_802c6e08 + param_1 * 4) & 0xffff,1);
    }
    DAT_803dc8f0 = DAT_803dc8ec;
    DAT_803dc8ec = 0;
  }
  return;
}

