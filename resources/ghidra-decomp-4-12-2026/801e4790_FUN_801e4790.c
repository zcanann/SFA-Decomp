// Function: FUN_801e4790
// Entry: 801e4790
// Size: 224 bytes

void FUN_801e4790(uint param_1)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar2 + 0x20) == 0) {
    piVar1 = FUN_8001f58c(param_1,'\x01');
    *(int **)(iVar2 + 0x20) = piVar1;
    if (*(int *)(iVar2 + 0x20) != 0) {
      FUN_8001dbf0(*(int *)(iVar2 + 0x20),2);
      FUN_8001dbb4(*(int *)(iVar2 + 0x20),200,0x3c,0,0);
      FUN_8001dbd8(*(int *)(iVar2 + 0x20),1);
      FUN_8001dcfc((double)FLOAT_803e6560,(double)FLOAT_803e6564,*(int *)(iVar2 + 0x20));
    }
  }
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e6568;
  *(byte *)(iVar2 + 0x1a) = *(byte *)(iVar2 + 0x1a) | 2;
  FUN_8000bb38(param_1,0x35);
  FUN_8000bb38(param_1,0x2ca);
  return;
}

