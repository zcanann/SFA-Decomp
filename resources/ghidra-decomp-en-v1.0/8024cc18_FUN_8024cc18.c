// Function: FUN_8024cc18
// Entry: 8024cc18
// Size: 416 bytes

void FUN_8024cc18(uint param_1,ushort param_2,byte param_3,short param_4,short param_5,short param_6
                 ,short param_7,short param_8,int param_9)

{
  short sVar1;
  short sVar2;
  uint uVar3;
  short sVar4;
  
  if (param_3 < 10) {
    uVar3 = 2;
    sVar4 = 1;
  }
  else {
    uVar3 = 1;
    sVar4 = 2;
  }
  param_1 = param_1 & 0xffff;
  sVar2 = (short)param_1;
  if (param_1 == ((int)param_1 >> 1) * 2) {
    sVar1 = sVar4 * (((short)uVar3 * param_4 - param_2) - sVar2);
    DAT_803ae076 = param_5 + sVar4 * sVar2;
    DAT_803ae074 = param_7 + sVar1;
    DAT_803ae07a = param_6 + sVar4 * sVar2;
    DAT_803ae078 = param_8 + sVar1;
  }
  else {
    sVar1 = sVar4 * (((short)uVar3 * param_4 - param_2) - sVar2);
    DAT_803ae076 = param_6 + sVar4 * sVar2;
    DAT_803ae074 = param_8 + sVar1;
    DAT_803ae07a = param_5 + sVar4 * sVar2;
    DAT_803ae078 = param_7 + sVar1;
  }
  uVar3 = param_2 / uVar3;
  if (param_9 != 0) {
    sVar4 = (short)uVar3 * 2 + -2;
    DAT_803ae076 = DAT_803ae076 + sVar4;
    DAT_803ae07a = DAT_803ae07a + sVar4;
    uVar3 = 0;
    DAT_803ae074 = DAT_803ae074 + 2;
    DAT_803ae078 = DAT_803ae078 + 2;
  }
  DAT_803ae068 = (ushort)param_3 | (ushort)(uVar3 << 4);
  DAT_803ddf88 = DAT_803ddf88 | 0x83c00000;
  return;
}

