// Function: FUN_801e4ff8
// Entry: 801e4ff8
// Size: 176 bytes

void FUN_801e4ff8(int param_1)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
  *(ushort *)(*(int *)(param_1 + 0x54) + 0xb2) = *(ushort *)(*(int *)(param_1 + 0x54) + 0xb2) | 1;
  if (*(int *)(iVar2 + 0x18) == 0) {
    piVar1 = FUN_8001f58c(param_1,'\x01');
    *(int **)(iVar2 + 0x18) = piVar1;
    if (*(int *)(iVar2 + 0x18) != 0) {
      FUN_8001dbf0(*(int *)(iVar2 + 0x18),2);
      FUN_8001dbb4(*(int *)(iVar2 + 0x18),0,0x5a,0x96,0);
      FUN_8001dbd8(*(int *)(iVar2 + 0x18),1);
      FUN_8001dcfc((double)FLOAT_803e65a8,(double)FLOAT_803e65ac,*(int *)(iVar2 + 0x18));
    }
  }
  return;
}

