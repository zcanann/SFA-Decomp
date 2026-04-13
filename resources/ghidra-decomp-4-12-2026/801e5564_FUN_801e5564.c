// Function: FUN_801e5564
// Entry: 801e5564
// Size: 196 bytes

void FUN_801e5564(uint param_1)

{
  int iVar1;
  uint uVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0xb8);
  if (0 < *(int *)(param_1 + 0xf4)) {
    *(int *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) + -1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *psVar3 = *psVar3 - (ushort)DAT_803dc070;
  iVar1 = FUN_8002bac4();
  FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
  if (*psVar3 < 1) {
    FUN_80022264(0,10);
    uVar2 = FUN_80020078(0xa71);
    if (uVar2 == 0) {
      FUN_8000bb38(param_1,0x316);
    }
    uVar2 = FUN_80022264(400,600);
    *psVar3 = (short)uVar2;
  }
  return;
}

