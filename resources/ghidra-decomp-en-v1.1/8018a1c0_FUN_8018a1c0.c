// Function: FUN_8018a1c0
// Entry: 8018a1c0
// Size: 732 bytes

/* WARNING: Removing unreachable block (ram,0x8018a47c) */
/* WARNING: Removing unreachable block (ram,0x8018a474) */
/* WARNING: Removing unreachable block (ram,0x8018a46c) */
/* WARNING: Removing unreachable block (ram,0x8018a464) */
/* WARNING: Removing unreachable block (ram,0x8018a45c) */
/* WARNING: Removing unreachable block (ram,0x8018a1f0) */
/* WARNING: Removing unreachable block (ram,0x8018a1e8) */
/* WARNING: Removing unreachable block (ram,0x8018a1e0) */
/* WARNING: Removing unreachable block (ram,0x8018a1d8) */
/* WARNING: Removing unreachable block (ram,0x8018a1d0) */

void FUN_8018a1c0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined2 *puVar6;
  short *psVar7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 *puVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  double in_f27;
  double dVar12;
  double in_f28;
  double dVar13;
  double in_f29;
  double dVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  ushort local_98 [4];
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
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
  iVar1 = FUN_80286834();
  iVar9 = *(int *)(iVar1 + 0x4c);
  iVar2 = FUN_8002bac4();
  iVar3 = FUN_8002ba84();
  puVar8 = *(undefined4 **)(iVar1 + 0xb8);
  iVar4 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar9 + 0x14));
  if ((iVar4 != 0) && (uVar5 = FUN_8002e144(), (uVar5 & 0xff) != 0)) {
    dVar11 = (double)FLOAT_803e4870;
    uStack_7c = (uint)*(byte *)(iVar9 + 0x20);
    local_80 = 0x43300000;
    dVar10 = (double)(**(code **)(*DAT_803dd72c + 100))
                               ((double)(float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000
                                                                                          ,uStack_7c
                                                                                         ) -
                                                                        DOUBLE_803e4880)),
                                *(undefined4 *)(iVar9 + 0x14));
    if (iVar3 != 0) {
      dVar10 = (double)FUN_80139280(iVar3);
    }
    dVar16 = (double)FLOAT_803e4874;
    dVar13 = (double)FLOAT_803e485c;
    dVar14 = (double)FLOAT_803e4854;
    dVar15 = (double)FLOAT_803e4878;
    dVar12 = DOUBLE_803e4868;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(iVar9 + 0x1f); iVar3 = iVar3 + 1) {
      puVar6 = FUN_8002becc(0x24,*(undefined2 *)(&DAT_803dca48 + (uint)*(byte *)(iVar9 + 0x1e) * 2))
      ;
      *(undefined4 *)(puVar6 + 4) = *puVar8;
      *(undefined4 *)(puVar6 + 6) = *(undefined4 *)(iVar1 + 0x10);
      *(undefined4 *)(puVar6 + 8) = puVar8[1];
      puVar6[0xd] = 400;
      psVar7 = (short *)FUN_8002e088(dVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar6,5,*(undefined *)(iVar1 + 0xac),0xffffffff,
                                     *(uint **)(iVar1 + 0x30),in_r8,in_r9,in_r10);
      *(float *)(psVar7 + 0x12) = *(float *)(iVar1 + 0xc) - *(float *)(iVar2 + 0xc);
      *(float *)(psVar7 + 0x16) = *(float *)(iVar1 + 0x14) - *(float *)(iVar2 + 0x14);
      dVar10 = (double)(*(float *)(psVar7 + 0x12) * *(float *)(psVar7 + 0x12) +
                       *(float *)(psVar7 + 0x16) * *(float *)(psVar7 + 0x16));
      if (dVar10 != dVar16) {
        dVar10 = FUN_80293900(dVar10);
        *(float *)(psVar7 + 0x12) = (float)((double)*(float *)(psVar7 + 0x12) / dVar10);
        *(float *)(psVar7 + 0x16) = (float)((double)*(float *)(psVar7 + 0x16) / dVar10);
      }
      uStack_7c = FUN_80022264(0,0x19);
      uStack_7c = uStack_7c ^ 0x80000000;
      local_80 = 0x43300000;
      *(float *)(psVar7 + 0x12) =
           *(float *)(psVar7 + 0x12) *
           -(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack_7c) - dVar12) -
                   dVar14);
      uStack_74 = FUN_80022264(0,0x19);
      uStack_74 = uStack_74 ^ 0x80000000;
      local_78 = 0x43300000;
      *(float *)(psVar7 + 0x16) =
           *(float *)(psVar7 + 0x16) *
           -(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack_74) - dVar12) -
                   dVar14);
      *(float *)(psVar7 + 0x14) = (float)dVar15;
      local_8c = (float)dVar16;
      local_88 = (float)dVar16;
      local_84 = (float)dVar16;
      local_90 = (float)dVar14;
      local_98[2] = 0;
      local_98[1] = 0;
      uVar5 = FUN_80022264(0xffffd8f0,10000);
      local_98[0] = (ushort)uVar5;
      FUN_80021b8c(local_98,(float *)(psVar7 + 0x12));
      dVar10 = (double)*(float *)(psVar7 + 0x12);
      dVar11 = -(double)*(float *)(psVar7 + 0x16);
      uVar5 = FUN_80021884();
      iVar4 = (int)*psVar7 - (uVar5 & 0xffff);
      if (0x8000 < iVar4) {
        iVar4 = iVar4 + -0xffff;
      }
      if (iVar4 < -0x8000) {
        iVar4 = iVar4 + 0xffff;
      }
      *psVar7 = (short)iVar4;
    }
  }
  FUN_80286880();
  return;
}

