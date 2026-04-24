// Function: FUN_8012e114
// Entry: 8012e114
// Size: 316 bytes

void FUN_8012e114(undefined4 param_1,byte param_2,uint param_3,undefined param_4)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = (uint)param_2;
  if (((param_3 & 8) != 0) &&
     (DAT_803de3fa = param_2,
     uVar1 = FUN_80020078((uint)*(ushort *)(&DAT_8031bcda + (uint)param_2 * 0x1c)), uVar1 == 0)) {
    uVar2 = 5;
  }
  DAT_803de3fb = param_4;
  if ((param_3 & 4) == 0) {
    if ((param_3 & 2) == 0) {
      if ((param_3 & 1) != 0) {
        DAT_803de3ff = 1;
      }
      DAT_803dc6c4 = uVar2;
      DAT_803dc6c8 = param_1;
      if (DAT_803de3f4 == 0) {
        DAT_803de3f4 = 1;
      }
      else if (0x7f < DAT_803de3f4) {
        DAT_803de3f4 = 0xff - DAT_803de3f4;
      }
    }
    else if (DAT_803de3f4 != 0) {
      if (DAT_803de3f4 < 0x7f) {
        DAT_803de3f4 = 0xff - DAT_803de3f4;
      }
      if (DAT_803de3f4 < 0xd9) {
        DAT_803de3f4 = 0xd9;
      }
      DAT_803de3ff = 0;
    }
  }
  else {
    DAT_803de3f4 = 0;
  }
  return;
}

