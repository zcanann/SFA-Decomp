// Function: FUN_8021133c
// Entry: 8021133c
// Size: 188 bytes

void FUN_8021133c(int param_1)

{
  float fVar1;
  int iVar2;
  
  iVar2 = FUN_80080150(*(int *)(param_1 + 0xb8) + 0x14);
  if (iVar2 == 0) {
    iVar2 = FUN_8003687c(param_1,0,0,0);
    fVar1 = FLOAT_803e6768;
    if (((*(char *)(*(int *)(param_1 + 0x54) + 0xad) != '\0') || (iVar2 != 0)) ||
       (*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0)) {
      iVar2 = *(int *)(param_1 + 0xb8);
      *(float *)(param_1 + 0x28) = FLOAT_803e6768;
      *(float *)(param_1 + 0x24) = fVar1;
      *(float *)(param_1 + 0x2c) = fVar1;
      *(undefined *)(iVar2 + 0x2c) = 0;
      FUN_8008016c(iVar2 + 0x1c);
      FUN_80080178(iVar2 + 0x1c,1);
      FUN_80080178(iVar2 + 0x14,10);
    }
  }
  return;
}

