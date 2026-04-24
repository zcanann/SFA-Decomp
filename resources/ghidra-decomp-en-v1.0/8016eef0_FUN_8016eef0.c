// Function: FUN_8016eef0
// Entry: 8016eef0
// Size: 184 bytes

void FUN_8016eef0(int param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  
  puVar2 = *(undefined4 **)(param_1 + 0xb8);
  *(undefined *)((int)puVar2 + 0xaa) = 1;
  *(undefined2 *)(puVar2 + 0x2c) = 2;
  puVar2[0x14] = FLOAT_803e3328;
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined2 *)(*(int *)(param_1 + 0x54) + 0xb2) = 0x109;
  }
  iVar3 = 0;
  do {
    uVar1 = FUN_80023cc8(60000,0x1a,0);
    *puVar2 = uVar1;
    *(undefined2 *)(puVar2 + 4) = 0xffff;
    puVar2 = puVar2 + 6;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 3);
  DAT_803ac6d4 = 0;
  DAT_803ac6d8 = 0;
  return;
}

