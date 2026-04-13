// Function: FUN_801b206c
// Entry: 801b206c
// Size: 136 bytes

void FUN_801b206c(undefined2 *param_1,int param_2)

{
  uint uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0x5c);
  *puVar2 = (char)*(undefined2 *)(param_2 + 0x1a);
  if ((int)*(short *)(param_2 + 0x1e) != 0xffffffff) {
    uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
    puVar2[1] = (char)uVar1;
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x4000;
  return;
}

