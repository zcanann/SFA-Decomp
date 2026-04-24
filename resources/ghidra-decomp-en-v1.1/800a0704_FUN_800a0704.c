// Function: FUN_800a0704
// Entry: 800a0704
// Size: 172 bytes

void FUN_800a0704(int param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined2 *puVar4;
  undefined2 *puVar5;
  
  puVar5 = *(undefined2 **)(param_1 + (1 - (uint)*(byte *)(param_1 + 0x130)) * 4 + 0x78);
  puVar4 = *(undefined2 **)(param_1 + 0x80);
  for (iVar3 = 0; fVar2 = FLOAT_803e00b4, iVar3 < *(short *)(param_1 + 0xea); iVar3 = iVar3 + 1) {
    *puVar4 = *puVar5;
    puVar4[1] = puVar5[1];
    puVar4[2] = puVar5[2];
    *(undefined *)(puVar4 + 6) = *(undefined *)(puVar5 + 6);
    *(undefined *)((int)puVar4 + 0xd) = *(undefined *)((int)puVar5 + 0xd);
    *(undefined *)(puVar4 + 7) = *(undefined *)(puVar5 + 7);
    *(undefined *)((int)puVar4 + 0xf) = *(undefined *)((int)puVar5 + 0xf);
    puVar4 = puVar4 + 8;
    puVar5 = puVar5 + 8;
  }
  *(float *)(param_1 + 0x30) = FLOAT_803e00b4;
  *(float *)(param_1 + 0x34) = fVar2;
  *(float *)(param_1 + 0x38) = fVar2;
  fVar1 = FLOAT_803e00b0;
  *(float *)(param_1 + 0x3c) = FLOAT_803e00b0;
  *(float *)(param_1 + 0x40) = fVar1;
  *(float *)(param_1 + 0x44) = fVar1;
  *(float *)(param_1 + 0x48) = fVar2;
  *(float *)(param_1 + 0x4c) = fVar2;
  *(float *)(param_1 + 0x50) = fVar2;
  *(float *)(param_1 + 0x54) = fVar1;
  *(float *)(param_1 + 0x58) = fVar1;
  *(float *)(param_1 + 0x5c) = fVar1;
  return;
}

