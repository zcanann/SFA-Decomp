// Function: FUN_8024d0a8
// Entry: 8024d0a8
// Size: 724 bytes

void FUN_8024d0a8(int param_1,uint *param_2,uint *param_3,uint *param_4,uint *param_5)

{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = (uint)*(byte *)(param_1 + 0x2c) * 0x20;
  iVar4 = *(int *)(param_1 + 0x20);
  uVar1 = *(ushort *)(param_1 + 10);
  *param_2 = *(int *)(param_1 + 0x30) +
             (*(ushort *)(param_1 + 0x16) & 0x7ffffff0) * 2 +
             iVar3 * (uint)*(ushort *)(param_1 + 0xe);
  if (iVar4 == 0) {
    uVar2 = *param_2;
  }
  else {
    uVar2 = *param_2 + iVar3;
  }
  *param_3 = uVar2;
  if ((uint)uVar1 + ((int)(uint)uVar1 >> 1) * -2 == 1) {
    uVar2 = *param_2;
    *param_2 = *param_3;
    *param_3 = uVar2;
  }
  *param_2 = *param_2 & 0x3fffffff;
  *param_3 = *param_3 & 0x3fffffff;
  if (*(int *)(param_1 + 0x44) != 0) {
    iVar3 = (uint)*(byte *)(param_1 + 0x2c) * 0x20;
    iVar4 = *(int *)(param_1 + 0x20);
    uVar1 = *(ushort *)(param_1 + 10);
    *param_4 = *(int *)(param_1 + 0x48) +
               (*(ushort *)(param_1 + 0x16) & 0x7ffffff0) * 2 +
               iVar3 * (uint)*(ushort *)(param_1 + 0xe);
    if (iVar4 == 0) {
      uVar2 = *param_4;
    }
    else {
      uVar2 = *param_4 + iVar3;
    }
    *param_5 = uVar2;
    if ((uint)uVar1 + ((int)(uint)uVar1 >> 1) * -2 == 1) {
      uVar2 = *param_4;
      *param_4 = *param_5;
      *param_5 = uVar2;
    }
    *param_4 = *param_4 & 0x3fffffff;
    *param_5 = *param_5 & 0x3fffffff;
  }
  if ((((*param_2 < 0x1000000) && (*param_3 < 0x1000000)) && (*param_4 < 0x1000000)) &&
     (*param_5 < 0x1000000)) {
    iVar3 = 0;
  }
  else {
    iVar3 = 1;
  }
  if (iVar3 != 0) {
    *param_2 = *param_2 >> 5;
    *param_3 = *param_3 >> 5;
    *param_4 = *param_4 >> 5;
    *param_5 = *param_5 >> 5;
  }
  DAT_803aece6 = (short)*param_2;
  DAT_803aece4 = (ushort)(iVar3 << 0xc) |
                 (ushort)(*param_2 >> 0x10) | (ushort)*(byte *)(param_1 + 0x3c) << 8;
  DAT_803aecee = (short)*param_3;
  DAT_803aecec = (short)(*param_3 >> 0x10);
  uVar2 = DAT_803dec08 | 0x33000;
  if (*(int *)(param_1 + 0x44) != 0) {
    DAT_803aecea = (undefined2)*param_4;
    DAT_803aece8 = (undefined2)(*param_4 >> 0x10);
    DAT_803aecf2 = (undefined2)*param_5;
    DAT_803aecf0 = (undefined2)(*param_5 >> 0x10);
    uVar2 = DAT_803dec08 | 0x3fc00;
  }
  DAT_803dec08 = uVar2;
  return;
}

