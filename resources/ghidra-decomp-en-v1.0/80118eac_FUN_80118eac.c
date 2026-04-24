// Function: FUN_80118eac
// Entry: 80118eac
// Size: 256 bytes

void FUN_80118eac(uint *param_1,int *param_2,int *param_3,int *param_4,int *param_5,
                 undefined4 *param_6)

{
  uint uVar1;
  int iVar2;
  
  if (DAT_803a5df8 != 0) {
    if (DAT_803a5e08 == 0) {
      uVar1 = (DAT_803a5da4 + 0x1fU & 0xffffffe0) * 10;
    }
    else {
      uVar1 = DAT_803a5db8 + 0x1fU & 0xffffffe0;
    }
    *param_1 = uVar1;
    *param_2 = (DAT_803a5de0 * DAT_803a5de4 + 0x1fU & 0xffffffe0) * 3;
    *param_3 = (((uint)(DAT_803a5de0 * DAT_803a5de4) >> 2) + 0x1f & 0xffffffe0) * 3;
    *param_4 = (((uint)(DAT_803a5de0 * DAT_803a5de4) >> 2) + 0x1f & 0xffffffe0) * 3;
    if (DAT_803a5dff == '\0') {
      iVar2 = 0;
    }
    else {
      iVar2 = (DAT_803a5da8 * 4 + 0x1fU & 0xffffffe0) * 3;
    }
    *param_5 = iVar2;
    *param_6 = 0x1000;
    return;
  }
  *param_1 = 0;
  *param_2 = 0;
  *param_3 = 0;
  *param_4 = 0;
  *param_5 = 0;
  *param_6 = 0;
  return;
}

