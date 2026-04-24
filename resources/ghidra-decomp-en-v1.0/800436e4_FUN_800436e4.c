// Function: FUN_800436e4
// Entry: 800436e4
// Size: 216 bytes

undefined * FUN_800436e4(int param_1)

{
  if (param_1 != 0x25) {
    if (param_1 < 0x25) {
      if (param_1 == 0x1a) {
        return &DAT_8034e010;
      }
      if (param_1 < 0x1a) {
        if (param_1 == 0xe) {
          return &DAT_803460d0;
        }
      }
      else {
        if (param_1 == 0x21) {
          return &DAT_80352010;
        }
        if ((0x20 < param_1) && (0x23 < param_1)) {
          return &DAT_80356010;
        }
      }
    }
    else {
      if (param_1 == 0x2f) {
        return &DAT_8035a010;
      }
      if (param_1 < 0x2f) {
        if (param_1 == 0x2a) {
          return &DAT_8035cef0;
        }
        if ((param_1 < 0x2a) && (param_1 < 0x27)) {
          return &DAT_80350010;
        }
      }
      else if (param_1 == 0x50) {
        return DAT_8035f528;
      }
    }
  }
  return (undefined *)0x0;
}

