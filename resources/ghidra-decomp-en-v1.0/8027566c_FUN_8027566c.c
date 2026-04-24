// Function: FUN_8027566c
// Entry: 8027566c
// Size: 344 bytes

void FUN_8027566c(int param_1,uint *param_2)

{
  uint uVar1;
  short sVar3;
  int iVar2;
  
  if (*(short *)(param_1 + 0xaa) == 0) {
    if ((*param_2 >> 0x10 & 1) == 0) {
      *(short *)(param_1 + 0xaa) = (short)(param_2[1] >> 0x10);
    }
    else {
      uVar1 = FUN_80282e5c();
      *(short *)(param_1 + 0xaa) =
           (short)(uVar1 & 0xffff) -
           (short)((uVar1 & 0xffff) / (param_2[1] >> 0x10)) * (short)(param_2[1] >> 0x10);
    }
    if (*(short *)(param_1 + 0xaa) == -1) goto LAB_80275708;
    *(short *)(param_1 + 0xaa) = *(short *)(param_1 + 0xaa) + 1;
  }
  else if (*(short *)(param_1 + 0xaa) == -1) goto LAB_80275708;
  sVar3 = *(short *)(param_1 + 0xaa) + -1;
  *(short *)(param_1 + 0xaa) = sVar3;
  if (sVar3 == 0) {
    return;
  }
LAB_80275708:
  if (((*param_2 >> 8 & 1) == 0) ||
     ((*(uint *)(param_1 + 0x118) & 8 ^ 8 | *(uint *)(param_1 + 0x114) & 0x100) != 0)) {
    if (((*param_2 >> 0x18 & 1) == 0) ||
       (((*(uint *)(param_1 + 0x118) & 0x20) != 0 ||
        (iVar2 = FUN_80283254(*(uint *)(param_1 + 0xf4) & 0xff), iVar2 != 0)))) {
      *(uint *)(param_1 + 0x38) = *(int *)(param_1 + 0x34) + (param_2[1] & 0xffff) * 8;
    }
    else {
      *(undefined2 *)(param_1 + 0xaa) = 0;
    }
  }
  else {
    *(undefined2 *)(param_1 + 0xaa) = 0;
  }
  return;
}

