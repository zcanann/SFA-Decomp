// Function: FUN_80043860
// Entry: 80043860
// Size: 216 bytes

undefined * FUN_80043860(int param_1)

{
  if (param_1 != 0x25) {
    if (param_1 < 0x25) {
      if (param_1 == 0x1a) {
        return &DAT_8034ec70;
      }
      if (param_1 < 0x1a) {
        if (param_1 == 0xe) {
          return &DAT_80346d30;
        }
      }
      else {
        if (param_1 == 0x21) {
          return &DAT_80352c70;
        }
        if ((0x20 < param_1) && (0x23 < param_1)) {
          return &DAT_80356c70;
        }
      }
    }
    else {
      if (param_1 == 0x2f) {
        return &DAT_8035ac70;
      }
      if (param_1 < 0x2f) {
        if (param_1 == 0x2a) {
          return &DAT_8035db50;
        }
        if ((param_1 < 0x2a) && (param_1 < 0x27)) {
          return &DAT_80350c70;
        }
      }
      else if (param_1 == 0x50) {
        return DAT_80360188;
      }
    }
  }
  return (undefined *)0x0;
}

