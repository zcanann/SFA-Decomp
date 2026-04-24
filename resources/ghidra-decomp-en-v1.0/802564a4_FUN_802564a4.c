// Function: FUN_802564a4
// Entry: 802564a4
// Size: 152 bytes

void FUN_802564a4(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = FUN_8024377c();
  FUN_80256614();
  *(short *)(DAT_803de0ac + 0x3c) = (short)param_1;
  *(ushort *)(DAT_803de0ac + 0x3e) = (ushort)((uint)param_1 >> 0x10) & 0x3fff;
  *(uint *)(DAT_803dc5a8 + 8) = *(uint *)(DAT_803dc5a8 + 8) & 0xfffffffd | 2;
  *(uint *)(DAT_803dc5a8 + 8) = *(uint *)(DAT_803dc5a8 + 8) & 0xffffffdf | 0x20;
  *(short *)(DAT_803de0ac + 2) = (short)*(undefined4 *)(DAT_803dc5a8 + 8);
  DAT_803de0d4 = param_1;
  FUN_802565ec();
  FUN_802437a4(uVar1);
  return;
}

