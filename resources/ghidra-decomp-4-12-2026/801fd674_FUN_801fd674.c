// Function: FUN_801fd674
// Entry: 801fd674
// Size: 248 bytes

void FUN_801fd674(undefined2 *param_1,int param_2)

{
  undefined2 *puVar1;
  
  puVar1 = *(undefined2 **)(param_1 + 0x5c);
  if (param_1[0x23] == 0x3c5) {
    puVar1[3] = 0x78;
    *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * FLOAT_803e6dd0;
    FUN_80035eec((int)param_1,0xe,1,0);
  }
  else {
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  }
  *puVar1 = *(undefined2 *)(param_2 + 0x1e);
  puVar1[1] = *(undefined2 *)(param_2 + 0x20);
  puVar1[2] = 100;
  *(char *)((int)puVar1 + 0xb) = (char)*(undefined2 *)(param_2 + 0x1a);
  if (*(char *)(param_2 + 0x19) == '\x01') {
    *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * FLOAT_803e6dd0;
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  DAT_803de940 = FUN_80013ee8(0xa5);
  return;
}

