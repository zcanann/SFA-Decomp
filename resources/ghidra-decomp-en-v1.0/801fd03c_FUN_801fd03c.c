// Function: FUN_801fd03c
// Entry: 801fd03c
// Size: 248 bytes

void FUN_801fd03c(undefined2 *param_1,int param_2)

{
  undefined2 *puVar1;
  
  puVar1 = *(undefined2 **)(param_1 + 0x5c);
  if (param_1[0x23] == 0x3c5) {
    puVar1[3] = 0x78;
    *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * FLOAT_803e6138;
    FUN_80035df4(param_1,0xe,1,0);
  }
  else {
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  }
  *puVar1 = *(undefined2 *)(param_2 + 0x1e);
  puVar1[1] = *(undefined2 *)(param_2 + 0x20);
  puVar1[2] = 100;
  *(char *)((int)puVar1 + 0xb) = (char)*(undefined2 *)(param_2 + 0x1a);
  if (*(char *)(param_2 + 0x19) == '\x01') {
    *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * FLOAT_803e6138;
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  DAT_803ddcc0 = FUN_80013ec8(0xa5,1);
  return;
}

