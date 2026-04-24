// Function: FUN_800e9af4
// Entry: 800e9af4
// Size: 192 bytes

void FUN_800e9af4(uint param_1,uint param_2)

{
  uint uVar1;
  
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  FUN_800201ac((uint)(ushort)(&DAT_80312370)[param_1],param_2);
  DAT_803de10c = (undefined)param_1;
  uRam803de10d = (undefined)param_2;
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  if ((ushort)(&DAT_80312460)[param_1] != 0) {
    uVar1 = FUN_80020078((uint)(ushort)(&DAT_80312460)[param_1]);
    (&DAT_803a3c1c)[param_1] = uVar1;
  }
  return;
}

