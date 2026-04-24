// Function: FUN_80216ce8
// Entry: 80216ce8
// Size: 292 bytes

void FUN_80216ce8(int param_1)

{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*(int *)(pbVar3 + 0x10) != 0) {
    *(float *)(pbVar3 + 8) = *(float *)(pbVar3 + 8) - FLOAT_803dc074;
    if (FLOAT_803e7530 < *(float *)(pbVar3 + 8)) {
      *(float *)(*(int *)(pbVar3 + 0x10) + 0x10) =
           *(float *)(pbVar3 + 0xc) * FLOAT_803dc074 + *(float *)(*(int *)(pbVar3 + 0x10) + 0x10);
    }
    else {
      *(float *)(*(int *)(pbVar3 + 0x10) + 0x10) =
           -(FLOAT_803e7548 * *(float *)(pbVar3 + 0xc) * FLOAT_803e754c -
            *(float *)(*(int *)(pbVar3 + 0x10) + 0x10));
      uVar1 = FUN_80022264(10,0x78);
      *(float *)(pbVar3 + 8) =
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e7540);
    }
    FUN_8008fb90(*(float **)(pbVar3 + 0x10));
    *(ushort *)(*(int *)(pbVar3 + 0x10) + 0x20) =
         *(short *)(*(int *)(pbVar3 + 0x10) + 0x20) + (ushort)DAT_803dc070;
    uVar1 = *(uint *)(pbVar3 + 0x10);
    if (*(ushort *)(uVar1 + 0x22) <= *(ushort *)(uVar1 + 0x20)) {
      FUN_800238c4(uVar1);
      pbVar3[0x10] = 0;
      pbVar3[0x11] = 0;
      pbVar3[0x12] = 0;
      pbVar3[0x13] = 0;
      *pbVar3 = *pbVar3 & 0xf7;
      FUN_800201ac((int)*(short *)(iVar2 + 0x1e),0);
    }
  }
  return;
}

