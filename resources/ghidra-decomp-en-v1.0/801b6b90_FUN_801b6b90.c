// Function: FUN_801b6b90
// Entry: 801b6b90
// Size: 148 bytes

void FUN_801b6b90(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar2 != 0) {
    uVar1 = (int)*(short *)(param_2 + 0x1a) << 0xd;
    iVar2 = (int)uVar1 / 0x2d +
            ((int)(uVar1 | (uint)(int)*(short *)(param_2 + 0x1a) >> 0x13) >> 0x1f);
    param_1[1] = (short)iVar2 - (short)(iVar2 >> 0x1f);
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0xe000;
  return;
}

