// Function: FUN_80107020
// Entry: 80107020
// Size: 500 bytes

/* WARNING: Removing unreachable block (ram,0x801071f4) */
/* WARNING: Removing unreachable block (ram,0x801071ec) */
/* WARNING: Removing unreachable block (ram,0x801071e4) */
/* WARNING: Removing unreachable block (ram,0x801071dc) */
/* WARNING: Removing unreachable block (ram,0x801071d4) */
/* WARNING: Removing unreachable block (ram,0x801071cc) */
/* WARNING: Removing unreachable block (ram,0x801071c4) */
/* WARNING: Removing unreachable block (ram,0x80107060) */
/* WARNING: Removing unreachable block (ram,0x80107058) */
/* WARNING: Removing unreachable block (ram,0x80107050) */
/* WARNING: Removing unreachable block (ram,0x80107048) */
/* WARNING: Removing unreachable block (ram,0x80107040) */
/* WARNING: Removing unreachable block (ram,0x80107038) */
/* WARNING: Removing unreachable block (ram,0x80107030) */

void FUN_80107020(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined4 param_7,undefined4 param_8,int *param_9)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  ushort *puVar5;
  double extraout_f1;
  double in_f25;
  double dVar6;
  double in_f26;
  double dVar7;
  double in_f27;
  double dVar8;
  double in_f28;
  double dVar9;
  double in_f29;
  double dVar10;
  double in_f30;
  double in_f31;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int6 iVar11;
  ushort local_e8 [2];
  ushort local_e4 [4];
  float local_dc;
  float local_d8;
  float local_d4;
  undefined auStack_d0 [2];
  ushort local_ce [19];
  undefined4 local_a8;
  uint uStack_a4;
  undefined4 local_a0;
  uint uStack_9c;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
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
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  iVar11 = FUN_80286834();
  sVar1 = (short)((uint6)iVar11 >> 0x20);
  if (iVar11 < 0) {
    sVar1 = -sVar1;
  }
  local_e8[0] = 0;
  dVar10 = extraout_f1;
  FUN_80106ae8(auStack_d0,local_e8,0,sVar1,(int)iVar11);
  dVar8 = (double)(float)(param_3 - dVar10);
  dVar7 = (double)(float)(param_6 - param_4);
  dVar6 = (double)(float)(param_5 - param_2);
  iVar2 = 3;
  puVar5 = local_ce;
  iVar4 = 0xc;
  dVar9 = DOUBLE_803e23d0;
  for (iVar3 = 1; iVar3 < (int)(uint)local_e8[0]; iVar3 = iVar3 + 1) {
    local_dc = (float)dVar8;
    local_d8 = (float)dVar7;
    local_d4 = (float)dVar6;
    if (iVar11 < 0) {
      local_e4[0] = *puVar5;
    }
    else {
      local_e4[0] = -*puVar5;
    }
    local_e4[1] = 0;
    local_e4[2] = 0;
    FUN_80021b8c(local_e4,&local_dc);
    *(float *)(DAT_803de1b0 + iVar4 + 0x1c) = (float)(dVar10 + (double)local_dc);
    uStack_a4 = (int)(short)*puVar5 ^ 0x80000000U;
    local_a8 = 0x43300000;
    uStack_9c = (int)sVar1 ^ 0x80000000U;
    local_a0 = 0x43300000;
    *(float *)(DAT_803de1b0 + iVar4 + 0x6c) =
         (float)(dVar7 * (double)((float)((double)CONCAT44(0x43300000,
                                                           (int)(short)*puVar5 ^ 0x80000000U) -
                                         dVar9) /
                                 (float)((double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000U) -
                                        dVar9)) + param_4);
    *(float *)(DAT_803de1b0 + iVar4 + 0xbc) = (float)(param_2 + (double)local_d4);
    puVar5 = puVar5 + 1;
    iVar4 = iVar4 + 4;
    iVar2 = iVar2 + 1;
  }
  *param_9 = iVar2;
  FUN_80286880();
  return;
}

