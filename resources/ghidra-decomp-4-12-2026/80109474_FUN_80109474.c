// Function: FUN_80109474
// Entry: 80109474
// Size: 1384 bytes

/* WARNING: Removing unreachable block (ram,0x801099b4) */
/* WARNING: Removing unreachable block (ram,0x801099ac) */
/* WARNING: Removing unreachable block (ram,0x801099a4) */
/* WARNING: Removing unreachable block (ram,0x8010999c) */
/* WARNING: Removing unreachable block (ram,0x80109994) */
/* WARNING: Removing unreachable block (ram,0x801094a4) */
/* WARNING: Removing unreachable block (ram,0x8010949c) */
/* WARNING: Removing unreachable block (ram,0x80109494) */
/* WARNING: Removing unreachable block (ram,0x8010948c) */
/* WARNING: Removing unreachable block (ram,0x80109484) */

void FUN_80109474(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  short sVar2;
  ushort uVar3;
  uint uVar4;
  undefined4 extraout_r4;
  int iVar5;
  short *psVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  
  psVar6 = *(short **)(param_9 + 0x52);
  if (DAT_803de1c0 == (undefined4 *)0x0) {
    DAT_803de1c0 = (undefined4 *)FUN_80023d8c(0x134,0xf);
  }
  FUN_800033a8((int)DAT_803de1c0,0,0x134);
  *DAT_803de1c0 = *param_11;
  DAT_803de1c0[0x45] =
       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_11 + 2)) - DOUBLE_803e24b8);
  DAT_803de1c0[1] = param_11[1];
  DAT_803de1c0[0x47] = FLOAT_803e2444;
  iVar5 = (int)*psVar6;
  sVar2 = (-0x8000 - *param_9) - *psVar6;
  uVar4 = (uint)sVar2;
  if ((int)uVar4 < 0) {
    sVar2 = -sVar2;
  }
  dVar10 = (double)((float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e2458) /
                   FLOAT_803e2464);
  dVar9 = (double)((float)((double)CONCAT44(0x43300000,(int)sVar2 ^ 0x80000000) - DOUBLE_803e2458) /
                  FLOAT_803e24b0);
  DAT_803de1c0[0x3f] = DAT_803de1c0 + 4;
  DAT_803de1c0[0x40] = DAT_803de1c0 + 8;
  DAT_803de1c0[0x41] = DAT_803de1c0 + 0xc;
  DAT_803de1c0[0x42] = 4;
  DAT_803de1c0[0x3e] = 0;
  DAT_803de1c0[0x43] = FUN_80010de0;
  DAT_803de1c0[0x44] = &LAB_80010d74;
  dVar12 = (double)(*(float *)(param_9 + 0xc) - *(float *)(psVar6 + 0xc));
  dVar11 = (double)(*(float *)(param_9 + 0x10) - *(float *)(psVar6 + 0x10));
  dVar7 = FUN_80293900((double)(float)(dVar12 * dVar12 + (double)(float)(dVar11 * dVar11)));
  if ((double)FLOAT_803e2444 != dVar7) {
    dVar12 = (double)(float)(dVar12 / dVar7);
    dVar11 = (double)(float)(dVar11 / dVar7);
  }
  FUN_801082ac((int)psVar6,1);
  dVar7 = (double)FUN_802945e0();
  dVar7 = -dVar7;
  dVar8 = (double)FUN_80294964();
  DAT_803de1c0[4] = *(undefined4 *)(param_9 + 0xc);
  DAT_803de1c0[5] = DAT_803de1c0[0x48];
  DAT_803de1c0[6] = (float)(-dVar11 * dVar10);
  DAT_803de1c0[7] = (float)(dVar7 * dVar9);
  DAT_803de1c0[8] = *(undefined4 *)(param_9 + 0xe);
  DAT_803de1c0[9] = DAT_803de1c0[0x49];
  fVar1 = FLOAT_803e2444;
  dVar7 = (double)FLOAT_803e2444;
  DAT_803de1c0[10] = FLOAT_803e2444;
  DAT_803de1c0[0xb] = fVar1;
  DAT_803de1c0[0xc] = *(undefined4 *)(param_9 + 0x10);
  DAT_803de1c0[0xd] = DAT_803de1c0[0x4a];
  DAT_803de1c0[0xe] = (float)(dVar12 * dVar10);
  DAT_803de1c0[0xf] = (float)(-dVar8 * dVar9);
  DAT_803de1c0[6] = fVar1;
  DAT_803de1c0[7] = fVar1;
  DAT_803de1c0[10] = fVar1;
  DAT_803de1c0[0xb] = fVar1;
  DAT_803de1c0[0xe] = fVar1;
  DAT_803de1c0[0xf] = fVar1;
  FUN_80010a8c(dVar7,-dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
               (float *)(DAT_803de1c0 + 0x1e),extraout_r4,iVar5,param_12,param_13,param_14,param_15,
               param_16);
  iVar5 = FUN_80021884();
  sVar2 = *param_9 - (-0x8000 - (short)iVar5);
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  DAT_803de1c0[0x10] =
       (float)((double)CONCAT44(0x43300000,(int)sVar2 ^ 0x80000000) - DOUBLE_803e2458);
  fVar1 = FLOAT_803e2444;
  DAT_803de1c0[0x11] = FLOAT_803e2444;
  DAT_803de1c0[0x12] = fVar1;
  DAT_803de1c0[0x13] = fVar1;
  fVar1 = (float)DAT_803de1c0[0x10] - (float)DAT_803de1c0[0x11];
  if ((FLOAT_803e2448 < fVar1) || (fVar1 < FLOAT_803e244c)) {
    if (FLOAT_803e2444 <= (float)DAT_803de1c0[0x10]) {
      if ((float)DAT_803de1c0[0x11] < FLOAT_803e2444) {
        DAT_803de1c0[0x11] = (float)DAT_803de1c0[0x11] + FLOAT_803e2450;
      }
    }
    else {
      DAT_803de1c0[0x10] = (float)DAT_803de1c0[0x10] + FLOAT_803e2450;
    }
  }
  DAT_803de1c0[0x14] =
       (float)((double)CONCAT44(0x43300000,(int)param_9[1] ^ 0x80000000) - DOUBLE_803e2458);
  fVar1 = FLOAT_803e2444;
  DAT_803de1c0[0x15] = FLOAT_803e2444;
  DAT_803de1c0[0x16] = fVar1;
  DAT_803de1c0[0x17] = fVar1;
  *(undefined *)(param_9 + 0x9f) = 1;
  uVar4 = FUN_80020078(0xc64);
  if (uVar4 != 0) {
    *(byte *)((int)DAT_803de1c0 + 0x12d) = *(byte *)((int)DAT_803de1c0 + 0x12d) & 0x7f | 0x80;
  }
  if (param_10 == 1) {
    *(undefined *)(DAT_803de1c0 + 0x4b) = 5;
  }
  else {
    *(undefined *)(DAT_803de1c0 + 0x4b) = 0;
    *(byte *)((int)DAT_803de1c0 + 0x12d) = *(byte *)((int)DAT_803de1c0 + 0x12d) & 0xbf | 0x40;
    if (*(char *)((int)DAT_803de1c0 + 0x12d) < '\0') {
      uVar3 = 0x3f4;
    }
    else {
      uVar3 = 0x28b;
    }
    FUN_8000bb38(0,uVar3);
  }
  *(byte *)((int)DAT_803de1c0 + 0x12d) = *(byte *)((int)DAT_803de1c0 + 0x12d) & 0xdf;
  DAT_803de1c0[0x4c] = DAT_803de1c0[0x49];
  return;
}

