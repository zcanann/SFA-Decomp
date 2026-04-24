// Function: FUN_800d8fe0
// Entry: 800d8fe0
// Size: 296 bytes

void FUN_800d8fe0(ushort *param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  if (*(int *)(param_2 + 0x2d0) != 0) {
    uVar1 = FUN_80021884();
    uVar1 = (uVar1 & 0xffff) - (uint)*param_1;
    if (0x8000 < (int)uVar1) {
      uVar1 = uVar1 - 0xffff;
    }
    if ((int)uVar1 < -0x8000) {
      uVar1 = uVar1 + 0xffff;
    }
    *param_1 = *param_1 +
               (short)(int)(((float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                    DOUBLE_803e1218) * FLOAT_803dc074) /
                           (FLOAT_803e1204 *
                           (float)((double)CONCAT44(0x43300000,param_3 ^ 0x80000000) -
                                  DOUBLE_803e1218)));
  }
  return;
}

