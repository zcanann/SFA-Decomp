// Function: FUN_8003bff4
// Entry: 8003bff4
// Size: 636 bytes

/* WARNING: Removing unreachable block (ram,0x8003c250) */
/* WARNING: Removing unreachable block (ram,0x8003c248) */
/* WARNING: Removing unreachable block (ram,0x8003c240) */
/* WARNING: Removing unreachable block (ram,0x8003c238) */
/* WARNING: Removing unreachable block (ram,0x8003c230) */
/* WARNING: Removing unreachable block (ram,0x8003c024) */
/* WARNING: Removing unreachable block (ram,0x8003c01c) */
/* WARNING: Removing unreachable block (ram,0x8003c014) */
/* WARNING: Removing unreachable block (ram,0x8003c00c) */
/* WARNING: Removing unreachable block (ram,0x8003c004) */

void FUN_8003bff4(void)

{
  int iVar1;
  float *pfVar2;
  float *pfVar3;
  float *pfVar4;
  int *piVar5;
  int iVar6;
  byte *pbVar7;
  int iVar8;
  int iVar9;
  double in_f27;
  double dVar10;
  double in_f28;
  double dVar11;
  double in_f29;
  double dVar12;
  double in_f30;
  double dVar13;
  double in_f31;
  double dVar14;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar15;
  float afStack_118 [12];
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  undefined4 local_88;
  uint uStack_84;
  float local_48;
  float fStack_44;
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
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  uVar15 = FUN_80286830();
  iVar1 = (int)((ulonglong)uVar15 >> 0x20);
  piVar5 = (int *)uVar15;
  iVar9 = 0;
  dVar13 = (double)FLOAT_803df698;
  dVar14 = (double)FLOAT_803df69c;
  dVar12 = DOUBLE_803df6a0;
  for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(iVar1 + 0xf4); iVar8 = iVar8 + 1) {
    pbVar7 = (byte *)(*(int *)(iVar1 + 0x54) + iVar9);
    pfVar2 = (float *)FUN_80028630(piVar5,iVar8 + (uint)*(byte *)(iVar1 + 0xf3));
    pfVar3 = (float *)FUN_80028630(piVar5,(uint)*pbVar7);
    pfVar4 = (float *)FUN_80028630(piVar5,(uint)pbVar7[1]);
    uStack_84 = (uint)pbVar7[2];
    local_88 = 0x43300000;
    dVar11 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_84) - dVar12) *
                            dVar13);
    dVar10 = (double)(float)(dVar14 - dVar11);
    iVar6 = *(int *)(iVar1 + 0x3c) + (uint)*pbVar7 * 0x1c;
    FUN_80247a48(-(double)*(float *)(iVar6 + 0x10),-(double)*(float *)(iVar6 + 0x14),
                 -(double)*(float *)(iVar6 + 0x18),afStack_118);
    FUN_80247618(pfVar3,afStack_118,&local_b8);
    iVar6 = *(int *)(iVar1 + 0x3c) + (uint)pbVar7[1] * 0x1c;
    FUN_80247a48(-(double)*(float *)(iVar6 + 0x10),-(double)*(float *)(iVar6 + 0x14),
                 -(double)*(float *)(iVar6 + 0x18),afStack_118);
    FUN_80247618(pfVar4,afStack_118,&local_e8);
    *pfVar2 = (float)((double)local_b8 * dVar11 + (double)(float)((double)local_e8 * dVar10));
    pfVar2[1] = (float)((double)local_b4 * dVar11 + (double)(float)((double)local_e4 * dVar10));
    pfVar2[2] = (float)((double)local_b0 * dVar11 + (double)(float)((double)local_e0 * dVar10));
    pfVar2[3] = (float)((double)local_ac * dVar11 + (double)(float)((double)local_dc * dVar10));
    pfVar2[4] = (float)((double)local_a8 * dVar11 + (double)(float)((double)local_d8 * dVar10));
    pfVar2[5] = (float)((double)local_a4 * dVar11 + (double)(float)((double)local_d4 * dVar10));
    pfVar2[6] = (float)((double)local_a0 * dVar11 + (double)(float)((double)local_d0 * dVar10));
    pfVar2[7] = (float)((double)local_9c * dVar11 + (double)(float)((double)local_cc * dVar10));
    pfVar2[8] = (float)((double)local_98 * dVar11 + (double)(float)((double)local_c8 * dVar10));
    pfVar2[9] = (float)((double)local_94 * dVar11 + (double)(float)((double)local_c4 * dVar10));
    pfVar2[10] = (float)((double)local_90 * dVar11 + (double)(float)((double)local_c0 * dVar10));
    pfVar2[0xb] = (float)((double)local_8c * dVar11 + (double)(float)((double)local_bc * dVar10));
    iVar9 = iVar9 + 4;
  }
  FUN_8028687c();
  return;
}

