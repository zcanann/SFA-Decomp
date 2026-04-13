// Function: FUN_8005d530
// Entry: 8005d530
// Size: 312 bytes

/* WARNING: Removing unreachable block (ram,0x8005d594) */
/* WARNING: Removing unreachable block (ram,0x8005d588) */
/* WARNING: Removing unreachable block (ram,0x8005d584) */
/* WARNING: Removing unreachable block (ram,0x8005d574) */
/* WARNING: Removing unreachable block (ram,0x8005d570) */
/* WARNING: Removing unreachable block (ram,0x8005d56c) */

void FUN_8005d530(int param_1,int param_2,int param_3)

{
  int iVar1;
  float *pfVar2;
  uint uVar3;
  double dVar4;
  float local_28;
  float local_24;
  float local_20;
  
  if (DAT_803ddab0 == 1000) {
    FUN_8005dcb4();
    DAT_803ddab0 = 0;
  }
  dVar4 = (double)FLOAT_803df8a0;
  local_28 = FLOAT_803df87c *
             ((float)((double)((longlong)(double)*(short *)(param_1 + 6) * 0x3ff0000000000000) *
                      dVar4 + (double)*(float *)(param_2 + 0x18)) +
             (float)((double)((longlong)(double)*(short *)(param_1 + 0xc) * 0x3ff0000000000000) *
                     dVar4 + (double)*(float *)(param_2 + 0x18)));
  local_24 = FLOAT_803df87c *
             ((float)((double)((longlong)(double)*(short *)(param_1 + 8) * 0x3ff0000000000000) *
                      dVar4 + (double)*(float *)(param_2 + 0x28)) +
             (float)((double)((longlong)(double)*(short *)(param_1 + 0xe) * 0x3ff0000000000000) *
                     dVar4 + (double)*(float *)(param_2 + 0x28)));
  local_20 = FLOAT_803df87c *
             ((float)((double)((longlong)(double)*(short *)(param_1 + 10) * 0x3ff0000000000000) *
                      dVar4 + (double)*(float *)(param_2 + 0x38)) +
             (float)((double)((longlong)(double)*(short *)(param_1 + 0x10) * 0x3ff0000000000000) *
                     dVar4 + (double)*(float *)(param_2 + 0x38)));
  pfVar2 = (float *)FUN_8000f56c();
  FUN_80247bf8(pfVar2,&local_28,&local_28);
  iVar1 = DAT_803ddab0;
  uVar3 = (uint)-local_20;
  if ((int)uVar3 < 0) {
    uVar3 = 0;
  }
  else if (0x7ffffff < (int)uVar3) {
    uVar3 = 0x7ffffff;
  }
  (&DAT_8037ed20)[DAT_803ddab0 * 4] = param_1;
  (&DAT_8037ed24)[iVar1 * 4] = param_2;
  (&DAT_8037ed28)[iVar1 * 4] = uVar3 | param_3 << 0x1b;
  return;
}

