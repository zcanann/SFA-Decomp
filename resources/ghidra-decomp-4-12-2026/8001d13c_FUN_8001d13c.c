// Function: FUN_8001d13c
// Entry: 8001d13c
// Size: 240 bytes

/* WARNING: Removing unreachable block (ram,0x8001d20c) */
/* WARNING: Removing unreachable block (ram,0x8001d14c) */

double FUN_8001d13c(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  float afStack_28 [4];
  
  if (*(int *)(param_2 + 0xc4) != 0) {
    param_2 = *(int *)(param_2 + 0xc4);
  }
  FUN_80247eb8((float *)(param_2 + 0x18),(float *)(param_1 + 0x10),afStack_28);
  dVar4 = FUN_80247f54(afStack_28);
  fVar2 = -(float)((double)*(float *)(param_2 + 0xa8) * (double)*(float *)(param_2 + 8) - dVar4);
  if ((FLOAT_803df3e8 < fVar2) || (*(float *)(param_1 + 0x144) < fVar2)) {
    dVar4 = (double)FLOAT_803df3dc;
  }
  else {
    fVar1 = *(float *)(param_1 + 0x140);
    fVar3 = FLOAT_803df3e0;
    if (fVar1 <= fVar2) {
      fVar3 = FLOAT_803df3e0 - (fVar2 - fVar1) / (*(float *)(param_1 + 0x144) - fVar1);
    }
    dVar4 = (double)fVar3;
    if (*(int *)(param_1 + 0xb8) != 0) {
      FUN_80247edc((double)(FLOAT_803df3e0 / fVar2),afStack_28,afStack_28);
      FUN_80247f90((float *)(param_1 + 0x34),afStack_28);
    }
  }
  return dVar4;
}

