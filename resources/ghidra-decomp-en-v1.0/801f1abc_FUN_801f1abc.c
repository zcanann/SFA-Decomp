// Function: FUN_801f1abc
// Entry: 801f1abc
// Size: 260 bytes

void FUN_801f1abc(undefined2 *param_1,int param_2)

{
  int iVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0x5c);
  *(undefined **)(param_1 + 0x5e) = &LAB_801f160c;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(short *)(puVar2 + 2) = *(short *)(param_2 + 0x1e) * 0x3c;
  puVar2[1] = 0;
  if (*(int *)(*(int *)(param_1 + 0x26) + 0x14) == 0x1f1a) {
    *(undefined2 *)(puVar2 + 4) = 0xf45;
  }
  else if (*(int *)(*(int *)(param_1 + 0x26) + 0x14) == 0x47293) {
    *(undefined2 *)(puVar2 + 4) = 0xf46;
  }
  else {
    *(undefined2 *)(puVar2 + 4) = 0xffff;
  }
  if ((*(short *)(puVar2 + 4) != -1) && (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    puVar2[6] = puVar2[6] & 0xbf | 0x40;
  }
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1c));
  if (iVar1 != 0) {
    *(float *)(param_1 + 8) = *(float *)(param_2 + 0xc) - FLOAT_803e5d78;
    *puVar2 = 0x1e;
  }
  return;
}

