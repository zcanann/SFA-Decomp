// Function: FUN_801f20f4
// Entry: 801f20f4
// Size: 260 bytes

void FUN_801f20f4(undefined2 *param_1,int param_2)

{
  uint uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0x5c);
  *(undefined **)(param_1 + 0x5e) = &LAB_801f1c44;
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
  if (((int)*(short *)(puVar2 + 4) != 0xffffffff) &&
     (uVar1 = FUN_80020078((int)*(short *)(puVar2 + 4)), uVar1 != 0)) {
    puVar2[6] = puVar2[6] & 0xbf | 0x40;
  }
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1c));
  if (uVar1 != 0) {
    *(float *)(param_1 + 8) = *(float *)(param_2 + 0xc) - FLOAT_803e6a10;
    *puVar2 = 0x1e;
  }
  return;
}

