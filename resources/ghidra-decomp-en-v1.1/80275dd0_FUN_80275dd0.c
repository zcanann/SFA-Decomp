// Function: FUN_80275dd0
// Entry: 80275dd0
// Size: 344 bytes

void FUN_80275dd0(int param_1,uint *param_2)

{
  uint uVar1;
  short sVar2;
  bool bVar3;
  
  if (*(short *)(param_1 + 0xaa) == 0) {
    if ((*param_2 >> 0x10 & 1) == 0) {
      *(short *)(param_1 + 0xaa) = (short)(param_2[1] >> 0x10);
    }
    else {
      uVar1 = FUN_802835c0();
      *(short *)(param_1 + 0xaa) =
           (short)uVar1 -
           (short)((uVar1 & 0xffff) / (param_2[1] >> 0x10)) * (short)(param_2[1] >> 0x10);
    }
    if (*(short *)(param_1 + 0xaa) == -1) goto LAB_80275e6c;
    *(short *)(param_1 + 0xaa) = *(short *)(param_1 + 0xaa) + 1;
  }
  else if (*(short *)(param_1 + 0xaa) == -1) goto LAB_80275e6c;
  sVar2 = *(short *)(param_1 + 0xaa) + -1;
  *(short *)(param_1 + 0xaa) = sVar2;
  if (sVar2 == 0) {
    return;
  }
LAB_80275e6c:
  if (((*param_2 >> 8 & 1) == 0) ||
     ((*(uint *)(param_1 + 0x118) & 8) != 8 || (*(uint *)(param_1 + 0x114) & 0x100) != 0)) {
    if (((*param_2 >> 0x18 & 1) == 0) ||
       (((*(uint *)(param_1 + 0x118) & 0x20) != 0 ||
        (bVar3 = FUN_802839b8(*(uint *)(param_1 + 0xf4) & 0xff), bVar3)))) {
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

