// Function: FUN_8020926c
// Entry: 8020926c
// Size: 152 bytes

void FUN_8020926c(undefined2 *param_1,int param_2)

{
  int iVar1;
  short *psVar2;
  
  psVar2 = *(short **)(param_1 + 0x5c);
  *psVar2 = *(short *)(param_2 + 0x1e);
  psVar2[1] = *(short *)(param_2 + 0x20);
  *(undefined *)(psVar2 + 2) = 0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  iVar1 = FUN_8001ffb4((int)*psVar2);
  if (iVar1 != 0) {
    *(undefined *)(psVar2 + 2) = 1;
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

