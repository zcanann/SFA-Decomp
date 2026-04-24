// Function: FUN_801870b0
// Entry: 801870b0
// Size: 272 bytes

void FUN_801870b0(int param_1,int param_2)

{
  float fVar1;
  undefined2 uVar2;
  undefined4 *puVar3;
  
  puVar3 = *(undefined4 **)(param_1 + 0xb8);
  FUN_80037200(param_1,0x30);
  fVar1 = FLOAT_803e3ab8;
  puVar3[1] = FLOAT_803e3ab8;
  puVar3[5] = fVar1;
  puVar3[9] = fVar1;
  puVar3[2] = fVar1;
  puVar3[6] = fVar1;
  puVar3[10] = fVar1;
  puVar3[3] = fVar1;
  puVar3[7] = fVar1;
  puVar3[0xb] = fVar1;
  puVar3[4] = fVar1;
  puVar3[8] = fVar1;
  puVar3[0xc] = fVar1;
  *puVar3 = 0;
  *(undefined *)((int)puVar3 + 0x6e) = 0;
  puVar3[0x11] = FLOAT_803e3ad8;
  puVar3[0x12] = FLOAT_803e3adc;
  puVar3[0x10] = FLOAT_803e3aa0;
  *(undefined *)(puVar3 + 0x1b) = 0;
  *(undefined *)((int)puVar3 + 0x6b) = 0;
  uVar2 = FUN_800221a0(500,0x5dc);
  *(undefined2 *)((int)puVar3 + 0x66) = uVar2;
  uVar2 = FUN_800221a0(0,65000);
  *(undefined2 *)(puVar3 + 0x19) = uVar2;
  *(undefined2 *)(puVar3 + 0x1a) = 4;
  *(undefined *)((int)puVar3 + 0x6a) = 4;
  puVar3[0x13] = FLOAT_803e3ab8;
  puVar3[0x14] = FLOAT_803e3ae0;
  puVar3[0x15] = *(undefined4 *)(param_2 + 8);
  puVar3[0x16] = *(undefined4 *)(param_2 + 0xc);
  puVar3[0x17] = *(undefined4 *)(param_2 + 0x10);
  *(undefined *)((int)puVar3 + 0x6f) = 0;
  *(byte *)(puVar3 + 0x1c) = *(byte *)(puVar3 + 0x1c) & 0x3f;
  return;
}

