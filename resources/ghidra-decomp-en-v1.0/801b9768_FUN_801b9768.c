// Function: FUN_801b9768
// Entry: 801b9768
// Size: 160 bytes

void FUN_801b9768(undefined2 *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar1 == 0) {
    *(undefined *)(iVar2 + 6) = 0;
    *(undefined *)(param_1 + 0x1b) = 0xff;
  }
  else {
    *(undefined *)(iVar2 + 6) = 2;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(float *)(param_1 + 0x14) = FLOAT_803e4b80;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

