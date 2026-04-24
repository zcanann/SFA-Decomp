// Function: FUN_801b1ab8
// Entry: 801b1ab8
// Size: 136 bytes

void FUN_801b1ab8(undefined2 *param_1,int param_2)

{
  undefined uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0x5c);
  *puVar2 = (char)*(undefined2 *)(param_2 + 0x1a);
  if (*(short *)(param_2 + 0x1e) != -1) {
    uVar1 = FUN_8001ffb4();
    puVar2[1] = uVar1;
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x4000;
  return;
}

