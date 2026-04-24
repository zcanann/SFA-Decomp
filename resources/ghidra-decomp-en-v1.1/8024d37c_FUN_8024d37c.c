// Function: FUN_8024d37c
// Entry: 8024d37c
// Size: 416 bytes

void FUN_8024d37c(ushort param_1,ushort param_2,byte param_3,short param_4,short param_5,
                 short param_6,short param_7,short param_8,int param_9)

{
  short sVar1;
  uint uVar2;
  short sVar3;
  
  if (param_3 < 10) {
    uVar2 = 2;
    sVar3 = 1;
  }
  else {
    uVar2 = 1;
    sVar3 = 2;
  }
  if ((uint)param_1 == ((int)(uint)param_1 >> 1) * 2) {
    sVar1 = sVar3 * (((short)uVar2 * param_4 - param_2) - param_1);
    DAT_803aecd6 = param_5 + sVar3 * param_1;
    DAT_803aecd4 = param_7 + sVar1;
    DAT_803aecda = param_6 + sVar3 * param_1;
    DAT_803aecd8 = param_8 + sVar1;
  }
  else {
    sVar1 = sVar3 * (((short)uVar2 * param_4 - param_2) - param_1);
    DAT_803aecd6 = param_6 + sVar3 * param_1;
    DAT_803aecd4 = param_8 + sVar1;
    DAT_803aecda = param_5 + sVar3 * param_1;
    DAT_803aecd8 = param_7 + sVar1;
  }
  uVar2 = param_2 / uVar2;
  if (param_9 != 0) {
    sVar3 = (short)uVar2 * 2 + -2;
    DAT_803aecd6 = DAT_803aecd6 + sVar3;
    DAT_803aecda = DAT_803aecda + sVar3;
    uVar2 = 0;
    DAT_803aecd4 = DAT_803aecd4 + 2;
    DAT_803aecd8 = DAT_803aecd8 + 2;
  }
  DAT_803aecc8 = (ushort)param_3 | (ushort)(uVar2 << 4);
  DAT_803dec08 = DAT_803dec08 | 0x83c00000;
  return;
}

