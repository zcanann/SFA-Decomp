// Function: FUN_80206e7c
// Entry: 80206e7c
// Size: 228 bytes

void FUN_80206e7c(undefined2 *param_1,int param_2)

{
  uint uVar1;
  undefined2 *puVar2;
  
  puVar2 = *(undefined2 **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined **)(param_1 + 0x5e) = &LAB_80206aac;
  *(undefined *)((int)puVar2 + 5) = *(undefined *)(param_2 + 0x19);
  *puVar2 = *(undefined2 *)(param_2 + 0x1e);
  puVar2[1] = *(undefined2 *)(param_2 + 0x20);
  *(undefined4 *)(puVar2 + 4) = 0;
  if ((int)*(short *)(param_2 + 0x1c) != 0) {
    *(float *)(param_1 + 4) =
         FLOAT_803e70a0 /
         ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
                 DOUBLE_803e70c8) / FLOAT_803e70c4);
  }
  uVar1 = FUN_80020078((int)(short)puVar2[1]);
  if (uVar1 != 0) {
    *(undefined *)(puVar2 + 2) = 1;
    *(float *)(param_1 + 8) = *(float *)(param_2 + 0xc) - FLOAT_803e70a4;
  }
  return;
}

