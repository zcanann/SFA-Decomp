// Function: FUN_80110354
// Entry: 80110354
// Size: 292 bytes

/* WARNING: Removing unreachable block (ram,0x80110458) */
/* WARNING: Removing unreachable block (ram,0x80110450) */
/* WARNING: Removing unreachable block (ram,0x8011036c) */
/* WARNING: Removing unreachable block (ram,0x80110364) */

void FUN_80110354(int param_1,undefined4 param_2,undefined4 *param_3)

{
  short *psVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack_34;
  
  psVar1 = *(short **)(param_1 + 0xa4);
  uStack_34 = (int)*psVar1 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar2 = (double)FUN_802945e0();
  dVar3 = (double)FUN_80294964();
  dVar4 = (double)*(float *)(psVar1 + 0xc);
  local_44 = (float)(dVar2 * (double)FLOAT_803dc628 + dVar4);
  local_40 = FLOAT_803e2788 + *(float *)(psVar1 + 0xe);
  dVar2 = (double)*(float *)(psVar1 + 0x10);
  local_3c = (float)(dVar3 * (double)FLOAT_803dc628 + dVar2);
  FUN_80103900(&local_44,(int)psVar1,&local_44);
  dVar2 = FUN_80293900((double)((float)((double)local_44 - dVar4) *
                                (float)((double)local_44 - dVar4) +
                               (float)((double)local_3c - dVar2) * (float)((double)local_3c - dVar2)
                               ));
  FLOAT_803de228 = (float)dVar2;
  if (param_3 == (undefined4 *)0x0) {
    FLOAT_803dc628 = FLOAT_803e279c;
    FLOAT_803de224 = FLOAT_803e2788;
  }
  else {
    FLOAT_803dc628 = (float)*param_3;
    FLOAT_803de224 = (float)param_3[1];
  }
  return;
}

