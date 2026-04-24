// Function: FUN_801fc604
// Entry: 801fc604
// Size: 232 bytes

void FUN_801fc604(undefined2 *param_1,int param_2)

{
  int iVar1;
  short *psVar2;
  
  psVar2 = *(short **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[2] = (short)((int)*(char *)(param_2 + 0x19) << 8);
  param_1[1] = *(undefined2 *)(param_2 + 0x1c);
  *psVar2 = *(short *)(param_2 + 0x1e);
  iVar1 = FUN_8001ffb4((int)*psVar2);
  if (iVar1 != 0) {
    FUN_80030304((double)FLOAT_803e611c,param_1);
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

