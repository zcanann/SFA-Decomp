// Function: FUN_801b7144
// Entry: 801b7144
// Size: 148 bytes

void FUN_801b7144(undefined2 *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  
  uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar2 != 0) {
    uVar2 = (int)*(short *)(param_2 + 0x1a) << 0xd;
    iVar1 = (int)uVar2 / 0x2d +
            ((int)(uVar2 | (uint)(int)*(short *)(param_2 + 0x1a) >> 0x13) >> 0x1f);
    param_1[1] = (short)iVar1 - (short)(iVar1 >> 0x1f);
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0xe000;
  return;
}

