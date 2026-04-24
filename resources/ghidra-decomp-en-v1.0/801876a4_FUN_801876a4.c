// Function: FUN_801876a4
// Entry: 801876a4
// Size: 148 bytes

void FUN_801876a4(int param_1)

{
  int iVar1;
  int iVar2;
  byte *pbVar3;
  undefined auStack24 [16];
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (((*pbVar3 & 3) == 0) && (iVar1 = FUN_8003687c(param_1,0,0,auStack24), iVar1 == 0x1a)) {
    iVar2 = (int)*(short *)(iVar2 + 0x1e);
    if (iVar2 != -1) {
      FUN_800200e8(iVar2,1);
      FUN_8000bb18(0,0x409);
    }
    *(float *)(pbVar3 + 4) = FLOAT_803e3afc;
    *pbVar3 = *pbVar3 | 1;
  }
  return;
}

