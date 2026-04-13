// Function: FUN_80203064
// Entry: 80203064
// Size: 588 bytes

/* WARNING: Removing unreachable block (ram,0x80203290) */
/* WARNING: Removing unreachable block (ram,0x80203288) */
/* WARNING: Removing unreachable block (ram,0x80203280) */
/* WARNING: Removing unreachable block (ram,0x80203278) */
/* WARNING: Removing unreachable block (ram,0x8020308c) */
/* WARNING: Removing unreachable block (ram,0x80203084) */
/* WARNING: Removing unreachable block (ram,0x8020307c) */
/* WARNING: Removing unreachable block (ram,0x80203074) */

void FUN_80203064(undefined4 param_1,undefined4 param_2,float *param_3,int param_4)

{
  float fVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  double dVar7;
  double extraout_f1;
  double dVar8;
  double in_f28;
  double dVar9;
  double in_f29;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar12 = FUN_8028683c();
  psVar2 = (short *)((ulonglong)uVar12 >> 0x20);
  puVar6 = (undefined4 *)uVar12;
  iVar5 = *(int *)(psVar2 + 0x5c);
  dVar10 = (double)FLOAT_803e6f40;
  dVar11 = (double)FLOAT_803e6ff4;
  dVar9 = extraout_f1;
  dVar7 = dVar10;
  for (iVar4 = 0; iVar4 < param_4; iVar4 = iVar4 + 1) {
    local_78 = (float)dVar11;
    iVar3 = FUN_80036e58(*puVar6,psVar2,&local_78);
    if (iVar3 != 0) {
      if (local_78 == FLOAT_803e6f40) goto LAB_80203278;
      fVar1 = FLOAT_803e6f60 - local_78 / FLOAT_803e6ff4;
      fVar1 = fVar1 * fVar1;
      fVar1 = fVar1 * fVar1;
      local_6c = FLOAT_803e6f60 / local_78;
      local_74 = (*(float *)(iVar3 + 0xc) - *(float *)(psVar2 + 6)) * local_6c;
      local_70 = (*(float *)(iVar3 + 0x10) - *(float *)(psVar2 + 8)) * local_6c;
      local_6c = (*(float *)(iVar3 + 0x14) - *(float *)(psVar2 + 10)) * local_6c;
      dVar7 = -(double)(float)(dVar9 * (double)(local_74 * fVar1 * *param_3) - dVar7);
      dVar10 = -(double)(float)(dVar9 * (double)(local_6c * fVar1 * *param_3) - dVar10);
    }
    puVar6 = puVar6 + 1;
    param_3 = param_3 + 1;
  }
  uStack_64 = (int)*psVar2 ^ 0x80000000;
  local_68 = 0x43300000;
  dVar11 = (double)FUN_802945e0();
  uStack_5c = (int)*psVar2 ^ 0x80000000;
  local_60 = 0x43300000;
  dVar8 = (double)FUN_80294964();
  *(float *)(iVar5 + 0x284) =
       *(float *)(iVar5 + 0x284) + (float)(dVar7 * dVar8 - (double)(float)(dVar10 * dVar11));
  *(float *)(iVar5 + 0x280) =
       *(float *)(iVar5 + 0x280) + (float)(-dVar10 * dVar8 - (double)(float)(dVar7 * dVar11));
  dVar11 = (double)*(float *)(iVar5 + 0x280);
  dVar7 = -dVar9;
  dVar10 = dVar7;
  if ((dVar7 <= dVar11) && (dVar10 = dVar11, dVar9 < dVar11)) {
    dVar10 = dVar9;
  }
  *(float *)(iVar5 + 0x280) = (float)dVar10;
  dVar10 = (double)*(float *)(iVar5 + 0x284);
  if ((dVar7 <= dVar10) && (dVar7 = dVar10, dVar9 < dVar10)) {
    dVar7 = dVar9;
  }
  *(float *)(iVar5 + 0x284) = (float)dVar7;
LAB_80203278:
  FUN_80286888();
  return;
}

