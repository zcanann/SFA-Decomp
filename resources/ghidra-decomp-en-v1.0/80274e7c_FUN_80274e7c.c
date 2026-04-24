// Function: FUN_80274e7c
// Entry: 80274e7c
// Size: 148 bytes

undefined4 FUN_80274e7c(uint param_1)

{
  DAT_803de298 = param_1 >> 6 & 0x3ff;
  if ((&DAT_803c5678)[DAT_803de298 * 2] != 0) {
    DAT_803de294 = (uint)(ushort)(&DAT_803c567a)[DAT_803de298 * 2];
    uRam803de2a0 = (undefined2)param_1;
    DAT_803de2a4 = (undefined4 *)
                   FUN_80282ee8(&DAT_803de29c,&DAT_803c5e78 + DAT_803de294 * 8,
                                (&DAT_803c5678)[DAT_803de298 * 2],8,&LAB_80274e6c);
    if (DAT_803de2a4 != (undefined4 *)0x0) {
      return *DAT_803de2a4;
    }
  }
  return 0;
}

