// Function: FUN_802755e0
// Entry: 802755e0
// Size: 148 bytes

undefined4 FUN_802755e0(uint param_1)

{
  DAT_803def18 = param_1 >> 6 & 0x3ff;
  if ((ushort)(&DAT_803c62d8)[DAT_803def18 * 2] != 0) {
    DAT_803def14 = (uint)(ushort)(&DAT_803c62da)[DAT_803def18 * 2];
    uRam803def20 = (undefined2)param_1;
    DAT_803def24 = (undefined4 *)
                   FUN_8028364c(&DAT_803def1c,(int)(&DAT_803c6ad8 + DAT_803def14 * 8),
                                (uint)(ushort)(&DAT_803c62d8)[DAT_803def18 * 2],8,&LAB_802755d0);
    if (DAT_803def24 != (undefined4 *)0x0) {
      return *DAT_803def24;
    }
  }
  return 0;
}

