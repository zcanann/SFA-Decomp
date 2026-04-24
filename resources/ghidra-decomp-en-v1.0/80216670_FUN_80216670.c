// Function: FUN_80216670
// Entry: 80216670
// Size: 292 bytes

void FUN_80216670(int param_1)

{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*(int *)(pbVar3 + 0x10) != 0) {
    *(float *)(pbVar3 + 8) = *(float *)(pbVar3 + 8) - FLOAT_803db414;
    if (FLOAT_803e6898 < *(float *)(pbVar3 + 8)) {
      *(float *)(*(int *)(pbVar3 + 0x10) + 0x10) =
           *(float *)(pbVar3 + 0xc) * FLOAT_803db414 + *(float *)(*(int *)(pbVar3 + 0x10) + 0x10);
    }
    else {
      *(float *)(*(int *)(pbVar3 + 0x10) + 0x10) =
           -(FLOAT_803e68b0 * *(float *)(pbVar3 + 0xc) * FLOAT_803e68b4 -
            *(float *)(*(int *)(pbVar3 + 0x10) + 0x10));
      uVar1 = FUN_800221a0(10,0x78);
      *(float *)(pbVar3 + 8) =
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e68a8);
    }
    FUN_8008f904(*(undefined4 *)(pbVar3 + 0x10));
    *(ushort *)(*(int *)(pbVar3 + 0x10) + 0x20) =
         *(short *)(*(int *)(pbVar3 + 0x10) + 0x20) + (ushort)DAT_803db410;
    if (*(ushort *)(*(int *)(pbVar3 + 0x10) + 0x22) <= *(ushort *)(*(int *)(pbVar3 + 0x10) + 0x20))
    {
      FUN_80023800();
      *(undefined4 *)(pbVar3 + 0x10) = 0;
      *pbVar3 = *pbVar3 & 0xf7;
      FUN_800200e8((int)*(short *)(iVar2 + 0x1e),0);
    }
  }
  return;
}

