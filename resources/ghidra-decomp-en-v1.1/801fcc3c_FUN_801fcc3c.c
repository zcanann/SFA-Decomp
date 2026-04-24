// Function: FUN_801fcc3c
// Entry: 801fcc3c
// Size: 232 bytes

void FUN_801fcc3c(undefined2 *param_1,int param_2)

{
  uint uVar1;
  short *psVar2;
  
  psVar2 = *(short **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[2] = (short)((int)*(char *)(param_2 + 0x19) << 8);
  param_1[1] = *(undefined2 *)(param_2 + 0x1c);
  *psVar2 = *(short *)(param_2 + 0x1e);
  uVar1 = FUN_80020078((int)*psVar2);
  if (uVar1 != 0) {
    FUN_800303fc((double)FLOAT_803e6db4,(int)param_1);
    *(byte *)(psVar2 + 1) = *(byte *)(psVar2 + 1) & 0x7f | 0x80;
    *(byte *)(psVar2 + 1) = *(byte *)(psVar2 + 1) & 0xbf | 0x40;
    param_1[3] = param_1[3] | 0x4000;
  }
  if ((param_1[0x23] == 999) && (*(char *)(psVar2 + 1) < '\0')) {
    *(undefined *)((int)param_1 + 0xad) = 1;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

