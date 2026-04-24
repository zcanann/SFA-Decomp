// Function: FUN_80284ef0
// Entry: 80284ef0
// Size: 204 bytes

bool FUN_80284ef0(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  bool bVar1;
  
  DAT_803df024 = FUN_802852d0();
  bVar1 = DAT_803df024 != 0;
  if (bVar1) {
    FUN_800033a8(DAT_803df024,0,0xa00);
    FUN_802420e0(DAT_803df024,0xa00);
    DAT_803df02c = 0;
    DAT_803df028 = 1;
    DAT_803df044 = 1;
    DAT_803df030 = 0;
    DAT_803df020 = param_1;
    FUN_8024fe1c(&LAB_80284dd4);
    FUN_8024fe60(DAT_803df024 + 0x80000000 + (uint)DAT_803df044 * 0x280,0x280);
    DAT_803bddb4 = 0x20;
    *param_3 = 32000;
  }
  return bVar1;
}

