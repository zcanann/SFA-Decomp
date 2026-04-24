// Function: FUN_80261a7c
// Entry: 80261a7c
// Size: 204 bytes

undefined4 FUN_80261a7c(undefined1 *param_1)

{
  uint uVar1;
  
  if ((((uint)param_1 & 0xffff0000) != 0) && ((param_1 != &DAT_80000004 || (DAT_803dc608 == -1)))) {
    return 0;
  }
  if (((uint)param_1 & 3) != 0) {
    return 0;
  }
  uVar1 = (uint)param_1 & 0xfc;
  if (uVar1 != 0x20) {
    if (uVar1 < 0x20) {
      if (uVar1 != 8) {
        if (uVar1 < 8) {
          if (uVar1 != 4) {
            return 0;
          }
        }
        else if (uVar1 != 0x10) {
          return 0;
        }
      }
    }
    else if (uVar1 != 0x80) {
      if (0x7f < uVar1) {
        return 0;
      }
      if (uVar1 != 0x40) {
        return 0;
      }
    }
  }
  if (*(uint *)(&DAT_8032ed40 + ((uint)param_1 >> 9 & 0x1c)) == 0) {
    return 0;
  }
  if ((((uint)param_1 & 0xfc) << 0x11) / *(uint *)(&DAT_8032ed40 + ((uint)param_1 >> 9 & 0x1c)) < 8)
  {
    return 0;
  }
  return 1;
}

