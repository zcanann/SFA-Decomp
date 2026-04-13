// Function: FUN_80109da0
// Entry: 80109da0
// Size: 272 bytes

/* WARNING: Removing unreachable block (ram,0x80109e90) */
/* WARNING: Removing unreachable block (ram,0x80109e88) */
/* WARNING: Removing unreachable block (ram,0x80109e80) */
/* WARNING: Removing unreachable block (ram,0x80109e78) */
/* WARNING: Removing unreachable block (ram,0x80109dc8) */
/* WARNING: Removing unreachable block (ram,0x80109dc0) */
/* WARNING: Removing unreachable block (ram,0x80109db8) */
/* WARNING: Removing unreachable block (ram,0x80109db0) */

void FUN_80109da0(undefined8 param_1,double param_2,double param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  double extraout_f1;
  double dVar7;
  double in_f28;
  double dVar8;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar9;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar10;
  int local_68 [12];
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
  uVar10 = FUN_8028683c();
  dVar9 = (double)FLOAT_803e24f8;
  dVar8 = extraout_f1;
  piVar4 = FUN_80037048(7,local_68);
  for (iVar6 = 0; iVar6 < local_68[0]; iVar6 = iVar6 + 1) {
    iVar5 = *piVar4;
    if ((((int)*(short *)(iVar5 + 0x44) == (int)uVar10) &&
        ((uint)*(byte *)(*(int *)(iVar5 + 0x4c) + 0x18) == (uint)((ulonglong)uVar10 >> 0x20))) &&
       (fVar1 = (float)(dVar8 - (double)*(float *)(iVar5 + 0x18)),
       fVar2 = (float)(param_2 - (double)*(float *)(iVar5 + 0x1c)),
       fVar3 = (float)(param_3 - (double)*(float *)(iVar5 + 0x20)),
       dVar7 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2)), dVar7 < dVar9)
       ) {
      dVar9 = dVar7;
    }
    piVar4 = piVar4 + 1;
  }
  FUN_80286888();
  return;
}

