// Function: FUN_80198954
// Entry: 80198954
// Size: 172 bytes

/* WARNING: Removing unreachable block (ram,0x80198990) */

void FUN_80198954(int param_1,int param_2)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  bVar1 = *(byte *)(param_2 + 0x1d);
  if (bVar1 != 1) {
    if (bVar1 == 0) {
      if (0 < *(short *)(param_2 + 0x18)) {
        fVar2 = (float)FUN_8001ffb4();
        *pfVar4 = fVar2;
      }
    }
    else if (bVar1 < 3) {
      uVar3 = FUN_800221a0(*(undefined *)(param_2 + 0x1e),*(undefined *)(param_2 + 0x1f));
      *pfVar4 = FLOAT_803e40bc *
                (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e40c0);
    }
  }
  return;
}

