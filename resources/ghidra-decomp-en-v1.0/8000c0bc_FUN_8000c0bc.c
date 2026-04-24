// Function: FUN_8000c0bc
// Entry: 8000c0bc
// Size: 236 bytes

uint FUN_8000c0bc(undefined4 *param_1,ushort *param_2)

{
  ushort uVar1;
  uint uVar2;
  
  uVar1 = *param_2;
  if (uVar1 != 0x170) {
    if (0x16f < uVar1) {
      if (uVar1 == 0x420) {
        FUN_8000a518(0xe7,0);
        FUN_8000a518(0xe7,1);
        return 0;
      }
      if (0x41f < uVar1) {
        if (uVar1 != 0x487) {
          return 1;
        }
LAB_8000c14c:
        *param_1 = 0;
        return 1;
      }
      if (uVar1 != 0x409) {
        if (0x408 < uVar1) {
          return 1;
        }
        if (uVar1 != 0x38c) {
          return 1;
        }
        uVar2 = countLeadingZeros(DAT_803dc7c8 & 4);
        return uVar2 >> 5;
      }
      goto LAB_8000c140;
    }
    if (uVar1 != 0xca) {
      if (uVar1 < 0xca) {
        if (uVar1 != 0x7e) {
          if (0x7d < uVar1) {
            return 1;
          }
          if (uVar1 != 0) {
            return 1;
          }
          return 0;
        }
        goto LAB_8000c14c;
      }
      if (uVar1 != 0x109) {
        return 1;
      }
    }
  }
  *param_2 = 0x409;
LAB_8000c140:
  *param_1 = 0;
  return 1;
}

