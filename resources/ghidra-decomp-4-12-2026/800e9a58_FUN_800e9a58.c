// Function: FUN_800e9a58
// Entry: 800e9a58
// Size: 156 bytes

undefined FUN_800e9a58(uint param_1)

{
  uint uVar1;
  
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  if (param_1 != (int)DAT_803de10c) {
    DAT_803de10c = (char)param_1;
    if ((((int)param_1 < 0) || (0x77 < (int)param_1)) || ((ushort)(&DAT_80312370)[param_1] == 0)) {
      uRam803de10d = 0;
    }
    else {
      uVar1 = FUN_80020078((uint)(ushort)(&DAT_80312370)[param_1]);
      uRam803de10d = (undefined)uVar1;
    }
  }
  return uRam803de10d;
}

