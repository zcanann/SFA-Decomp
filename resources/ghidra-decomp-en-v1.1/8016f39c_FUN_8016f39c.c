// Function: FUN_8016f39c
// Entry: 8016f39c
// Size: 184 bytes

void FUN_8016f39c(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  *(undefined *)((int)piVar2 + 0xaa) = 1;
  *(undefined2 *)(piVar2 + 0x2c) = 2;
  piVar2[0x14] = (int)FLOAT_803e3fc0;
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined2 *)(*(int *)(param_1 + 0x54) + 0xb2) = 0x109;
  }
  iVar3 = 0;
  do {
    iVar1 = FUN_80023d8c(60000,0x1a);
    *piVar2 = iVar1;
    *(undefined2 *)(piVar2 + 4) = 0xffff;
    piVar2 = piVar2 + 6;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 3);
  DAT_803ad338 = 0;
  DAT_803ad334 = 0;
  return;
}

