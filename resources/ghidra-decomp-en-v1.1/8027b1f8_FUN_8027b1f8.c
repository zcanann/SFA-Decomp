// Function: FUN_8027b1f8
// Entry: 8027b1f8
// Size: 416 bytes

/* WARNING: Removing unreachable block (ram,0x8027b220) */

undefined4 FUN_8027b1f8(char *param_1,undefined2 *param_2,short *param_3)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = 0;
  if (*param_1 == '\x01') {
    if (param_1[1] == '\x03') {
      *param_2 = (short)((uint)*(undefined4 *)(param_1 + 8) >> 0x10);
      *param_3 = 0;
    }
    else {
      iVar3 = *(int *)(param_1 + 8);
      if ((param_1[0x26] == '\0') && (param_1[1] == '\x01')) {
        *(int *)(param_1 + 8) = iVar3 + *(int *)(param_1 + 0x10);
      }
      else {
        *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + *(int *)(param_1 + 0x10);
        iVar2 = 0xc1 - (*(int *)(param_1 + 0xc) + 0x8000 >> 0x10);
        if (iVar2 < 0) {
          iVar2 = 0;
        }
        *(uint *)(param_1 + 8) = (uint)(ushort)(&DAT_80330278)[iVar2] << 0x10;
      }
      *param_2 = (short)((uint)iVar3 >> 0x10);
      iVar3 = *(int *)(param_1 + 8) - iVar3;
      if (iVar3 < 0) {
        *param_3 = -(short)(-iVar3 >> 0x15);
      }
      else {
        *param_3 = (short)(iVar3 >> 0x15);
      }
      iVar3 = *(int *)(param_1 + 4);
      *(int *)(param_1 + 4) = iVar3 + -1;
      if (iVar3 + -1 == 0) {
        uVar1 = FUN_8027adc4(param_1);
      }
    }
  }
  else if (*param_1 == '\0') {
    if (param_1[1] == '\x03') {
      *param_2 = (short)((uint)*(undefined4 *)(param_1 + 8) >> 0x10);
      *param_3 = 0;
    }
    else {
      iVar3 = *(int *)(param_1 + 8);
      *(int *)(param_1 + 8) = iVar3 + *(int *)(param_1 + 0x10);
      *param_2 = (short)((uint)iVar3 >> 0x10);
      iVar3 = *(int *)(param_1 + 0x10);
      if (iVar3 < 0) {
        *param_3 = -(short)(-iVar3 >> 0x15);
      }
      else {
        *param_3 = (short)(iVar3 >> 0x15);
      }
      iVar3 = *(int *)(param_1 + 4);
      *(int *)(param_1 + 4) = iVar3 + -1;
      if (iVar3 + -1 == 0) {
        uVar1 = FUN_8027adc4(param_1);
      }
    }
  }
  return uVar1;
}

