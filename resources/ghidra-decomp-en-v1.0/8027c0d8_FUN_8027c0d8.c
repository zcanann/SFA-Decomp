// Function: FUN_8027c0d8
// Entry: 8027c0d8
// Size: 696 bytes

void FUN_8027c0d8(int param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  *(undefined *)((int)param_2 + 0xed) = 0;
  iVar3 = 0x7fffff;
  *(undefined2 *)(*param_2 + 0xe) = 0;
  iVar2 = *param_2;
  *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + (int)*(short *)(iVar2 + 0x52);
  iVar1 = *(int *)(param_1 + 4);
  if ((iVar1 < 0x800000) && (iVar3 = iVar1, iVar1 < -0x7fffff)) {
    iVar3 = -0x7fffff;
  }
  *(int *)(param_1 + 4) = iVar3;
  iVar3 = 0x7fffff;
  *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + (int)*(short *)(iVar2 + 0x58);
  iVar1 = *(int *)(param_1 + 8);
  if ((iVar1 < 0x800000) && (iVar3 = iVar1, iVar1 < -0x7fffff)) {
    iVar3 = -0x7fffff;
  }
  *(int *)(param_1 + 8) = iVar3;
  if ((*(ushort *)(iVar2 + 0xc) & 4) != 0) {
    iVar3 = 0x7fffff;
    *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + (int)*(short *)(iVar2 + 0x5e);
    iVar1 = *(int *)(param_1 + 0xc);
    if ((iVar1 < 0x800000) && (iVar3 = iVar1, iVar1 < -0x7fffff)) {
      iVar3 = -0x7fffff;
    }
    *(int *)(param_1 + 0xc) = iVar3;
  }
  if ((*(ushort *)(iVar2 + 0xc) & 1) != 0) {
    iVar3 = 0x7fffff;
    *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + (int)*(short *)(iVar2 + 0x54);
    iVar1 = *(int *)(param_1 + 0x10);
    if ((iVar1 < 0x800000) && (iVar3 = iVar1, iVar1 < -0x7fffff)) {
      iVar3 = -0x7fffff;
    }
    *(int *)(param_1 + 0x10) = iVar3;
    iVar3 = 0x7fffff;
    *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + (int)*(short *)(iVar2 + 0x5a);
    iVar1 = *(int *)(param_1 + 0x14);
    if ((iVar1 < 0x800000) && (iVar3 = iVar1, iVar1 < -0x7fffff)) {
      iVar3 = -0x7fffff;
    }
    *(int *)(param_1 + 0x14) = iVar3;
    if ((*(ushort *)(iVar2 + 0xc) & 0x14) != 0) {
      iVar3 = 0x7fffff;
      *(int *)(param_1 + 0x18) = *(int *)(param_1 + 0x18) + (int)*(short *)(iVar2 + 0x60);
      iVar1 = *(int *)(param_1 + 0x18);
      if ((iVar1 < 0x800000) && (iVar3 = iVar1, iVar1 < -0x7fffff)) {
        iVar3 = -0x7fffff;
      }
      *(int *)(param_1 + 0x18) = iVar3;
    }
  }
  if ((*(ushort *)(iVar2 + 0xc) & 0x12) != 0) {
    iVar3 = 0x7fffff;
    *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + (int)*(short *)(iVar2 + 0x56);
    iVar1 = *(int *)(param_1 + 0x1c);
    if ((iVar1 < 0x800000) && (iVar3 = iVar1, iVar1 < -0x7fffff)) {
      iVar3 = -0x7fffff;
    }
    *(int *)(param_1 + 0x1c) = iVar3;
    iVar3 = 0x7fffff;
    *(int *)(param_1 + 0x20) = *(int *)(param_1 + 0x20) + (int)*(short *)(iVar2 + 0x5c);
    iVar1 = *(int *)(param_1 + 0x20);
    if ((iVar1 < 0x800000) && (iVar3 = iVar1, iVar1 < -0x7fffff)) {
      iVar3 = -0x7fffff;
    }
    *(int *)(param_1 + 0x20) = iVar3;
    if ((*(ushort *)(iVar2 + 0xc) & 4) != 0) {
      iVar3 = 0x7fffff;
      *(int *)(param_1 + 0x24) = *(int *)(param_1 + 0x24) + (int)*(short *)(iVar2 + 0x62);
      iVar1 = *(int *)(param_1 + 0x24);
      if ((iVar1 < 0x800000) && (iVar3 = iVar1, iVar1 < -0x7fffff)) {
        iVar3 = -0x7fffff;
      }
      *(int *)(param_1 + 0x24) = iVar3;
      return;
    }
    return;
  }
  return;
}

