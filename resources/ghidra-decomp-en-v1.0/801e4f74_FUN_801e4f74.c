// Function: FUN_801e4f74
// Entry: 801e4f74
// Size: 196 bytes

void FUN_801e4f74(int param_1)

{
  int iVar1;
  short sVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0xb8);
  if (0 < *(int *)(param_1 + 0xf4)) {
    *(int *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) + -1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *psVar3 = *psVar3 - (ushort)DAT_803db410;
  iVar1 = FUN_8002b9ec();
  FUN_80021704(param_1 + 0x18,iVar1 + 0x18);
  if (*psVar3 < 1) {
    FUN_800221a0(0,10);
    iVar1 = FUN_8001ffb4(0xa71);
    if (iVar1 == 0) {
      FUN_8000bb18(param_1,0x316);
    }
    sVar2 = FUN_800221a0(400,600);
    *psVar3 = sVar2;
  }
  return;
}

