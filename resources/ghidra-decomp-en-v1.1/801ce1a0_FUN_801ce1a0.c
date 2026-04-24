// Function: FUN_801ce1a0
// Entry: 801ce1a0
// Size: 140 bytes

void FUN_801ce1a0(undefined2 *param_1,int param_2)

{
  uint uVar1;
  short *psVar2;
  
  psVar2 = *(short **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_801cdd90;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[1] = *(undefined2 *)(param_2 + 0x1a);
  param_1[2] = *(undefined2 *)(param_2 + 0x1c);
  psVar2[1] = (short)*(char *)(param_2 + 0x19);
  *psVar2 = *(short *)(param_2 + 0x1e);
  uVar1 = FUN_80020078((int)*psVar2);
  if (uVar1 != 0) {
    psVar2[2] = 0x154;
  }
  *(undefined *)((int)psVar2 + 7) = 4;
  return;
}

