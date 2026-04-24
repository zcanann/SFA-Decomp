// Function: FUN_8027bfe4
// Entry: 8027bfe4
// Size: 244 bytes

undefined4
FUN_8027bfe4(undefined2 *param_1,undefined2 *param_2,short *param_3,short param_4,int param_5,
            ushort param_6)

{
  int iVar1;
  
  if (param_4 != *param_3) {
    iVar1 = (int)(short)(param_4 - *param_3);
    if ((0x1f < iVar1) && (iVar1 < 0xa0)) {
      iVar1 = (int)(short)(iVar1 >> 5);
      if (iVar1 < 5) {
        *(ushort *)(param_5 + iVar1 * 2) = *(ushort *)(param_5 + iVar1 * 2) | param_6;
      }
      *param_2 = 1;
      *param_3 = *param_3 + (short)(iVar1 << 5);
      return 1;
    }
    if ((iVar1 < -0x1f) && (-0xa0 < iVar1)) {
      iVar1 = (int)(short)(-iVar1 >> 5);
      if (iVar1 < 5) {
        *(ushort *)(param_5 + iVar1 * 2) = *(ushort *)(param_5 + iVar1 * 2) | param_6;
      }
      *param_2 = 0xffff;
      *param_3 = *param_3 - (short)(iVar1 << 5);
      return 1;
    }
    if ((param_4 == 0) && (-0x20 < iVar1)) {
      *param_3 = 0;
      *param_1 = 0;
    }
  }
  *param_2 = 0;
  return 0;
}

