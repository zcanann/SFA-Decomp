// Function: FUN_80198ed0
// Entry: 80198ed0
// Size: 172 bytes

/* WARNING: Removing unreachable block (ram,0x80198f0c) */

void FUN_80198ed0(int param_1,int param_2)

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
        fVar2 = (float)FUN_80020078((int)*(short *)(param_2 + 0x18));
        *pfVar4 = fVar2;
      }
    }
    else if (bVar1 < 3) {
      uVar3 = FUN_80022264((uint)*(byte *)(param_2 + 0x1e),(uint)*(byte *)(param_2 + 0x1f));
      *pfVar4 = FLOAT_803e4d54 *
                (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e4d58);
    }
  }
  return;
}

