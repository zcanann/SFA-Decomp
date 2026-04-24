// Function: FUN_800e99dc
// Entry: 800e99dc
// Size: 124 bytes

uint FUN_800e99dc(uint param_1,uint param_2)

{
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  if (param_1 != DAT_803de104) {
    DAT_803de104 = param_1;
    uRam803de108 = FUN_80020078((uint)(ushort)(&DAT_80312460)[param_1]);
  }
  return (int)uRam803de108 >> (param_2 & 0x3f) & 1;
}

