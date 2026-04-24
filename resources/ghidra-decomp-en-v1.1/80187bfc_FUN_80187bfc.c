// Function: FUN_80187bfc
// Entry: 80187bfc
// Size: 148 bytes

void FUN_80187bfc(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  uint auStack_18 [4];
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if (((*pbVar4 & 3) == 0) &&
     (iVar1 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,auStack_18), iVar1 == 0x1a)) {
    uVar2 = (uint)*(short *)(iVar3 + 0x1e);
    if (uVar2 != 0xffffffff) {
      FUN_800201ac(uVar2,1);
      FUN_8000bb38(0,0x409);
    }
    *(float *)(pbVar4 + 4) = FLOAT_803e4794;
    *pbVar4 = *pbVar4 | 1;
  }
  return;
}

