// Function: FUN_801b70c4
// Entry: 801b70c4
// Size: 144 bytes

void FUN_801b70c4(int param_1,int param_2)

{
  int iVar1;
  short *psVar2;
  
  psVar2 = *(short **)(param_1 + 0xb8);
  *(char *)(psVar2 + 1) = (char)*(undefined2 *)(param_2 + 0x1a);
  *psVar2 = *(short *)(param_2 + 0x1e);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  if ((*psVar2 != -1) && (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    FUN_80035f00(param_1);
    *(undefined *)((int)psVar2 + 3) = 2;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  return;
}

