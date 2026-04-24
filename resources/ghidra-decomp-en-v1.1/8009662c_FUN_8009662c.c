// Function: FUN_8009662c
// Entry: 8009662c
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x80096748) */
/* WARNING: Removing unreachable block (ram,0x80096740) */
/* WARNING: Removing unreachable block (ram,0x80096738) */
/* WARNING: Removing unreachable block (ram,0x8009664c) */
/* WARNING: Removing unreachable block (ram,0x80096644) */
/* WARNING: Removing unreachable block (ram,0x8009663c) */

void FUN_8009662c(undefined4 param_1,undefined4 param_2,float *param_3,int param_4)

{
  uint uVar1;
  undefined2 *puVar2;
  double extraout_f1;
  double dVar3;
  double dVar4;
  double dVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286840();
  puVar2 = (undefined2 *)((ulonglong)uVar6 >> 0x20);
  dVar3 = extraout_f1;
  for (uVar1 = (uint)uVar6; (uVar1 & 0xffff) != 0; uVar1 = (int)(uVar1 & 0xffff) >> 1) {
    if ((uVar1 & 1) != 0) {
      dVar5 = (double)*param_3;
      dVar4 = (double)param_3[2];
      if ((*(float *)(param_4 + 0x1b4) < FLOAT_803dffb8) && ((double)FLOAT_803dffbc < dVar3)) {
        FUN_80095c8c(dVar5,(double)(*(float *)(puVar2 + 8) + *(float *)(param_4 + 0x1b4)),dVar4,
                     (double)FLOAT_803dff80);
      }
      FLOAT_803dde8c = FLOAT_803dff98;
      FUN_800959f0(dVar5,(double)(*(float *)(puVar2 + 8) + *(float *)(param_4 + 0x1b4)),dVar4,
                   (double)FLOAT_803dff80,*puVar2,4);
      DAT_8039b7a8 = (float)dVar5;
      DAT_8039b7ac = *(float *)(puVar2 + 8) + *(float *)(param_4 + 0x1b4);
      DAT_8039b7b0 = (float)dVar4;
      DAT_803dde78 = 1;
    }
    param_3 = param_3 + 3;
  }
  FUN_8028688c();
  return;
}

