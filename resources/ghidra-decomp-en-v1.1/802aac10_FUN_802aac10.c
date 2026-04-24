// Function: FUN_802aac10
// Entry: 802aac10
// Size: 1056 bytes

/* WARNING: Removing unreachable block (ram,0x802ab010) */
/* WARNING: Removing unreachable block (ram,0x802ab008) */
/* WARNING: Removing unreachable block (ram,0x802aac28) */
/* WARNING: Removing unreachable block (ram,0x802aac20) */

void FUN_802aac10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  float fVar2;
  short *psVar3;
  uint uVar4;
  undefined2 *puVar5;
  undefined uVar9;
  short *psVar6;
  float *pfVar7;
  uint uVar8;
  int iVar10;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar11;
  int iVar12;
  undefined8 extraout_f1;
  double dVar13;
  double dVar14;
  double in_f30;
  double in_f31;
  double dVar15;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar16;
  float local_c8;
  float local_c4;
  float local_c0;
  ushort local_bc;
  undefined2 local_ba;
  undefined2 local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float afStack_a4 [17];
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar16 = FUN_8028683c();
  uVar8 = (uint)((ulonglong)uVar16 >> 0x20);
  iVar10 = (int)uVar16;
  iVar12 = 0;
  iVar11 = *(int *)(uVar8 + 0xb8);
  psVar3 = FUN_8000facc();
  uVar4 = FUN_8002e144();
  if ((uVar4 & 0xff) != 0) {
    FUN_8000bb38(uVar8,0x20a);
    puVar5 = FUN_8002becc(0x24,0x14b);
    *(undefined *)(puVar5 + 2) = 2;
    *(undefined *)((int)puVar5 + 5) = 1;
    *(undefined *)(puVar5 + 3) = 0xff;
    *(undefined *)((int)puVar5 + 7) = 0xff;
    if (*(int *)(iVar10 + 0x2d0) == 0) {
      *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(psVar3 + 6);
      *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(psVar3 + 8);
      *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(psVar3 + 10);
    }
    else {
      in_r8 = 0;
      FUN_80038524(DAT_803df0cc,0,(float *)(puVar5 + 4),(undefined4 *)(puVar5 + 6),
                   (float *)(puVar5 + 8),0);
    }
    uVar9 = (**(code **)(**(int **)(DAT_803df0cc + 0x68) + 0x44))();
    *(undefined *)((int)puVar5 + 0x19) = uVar9;
    if (*(int *)(iVar10 + 0x2d0) == 0) {
      puVar5[0xd] = 1;
    }
    psVar6 = (short *)FUN_8002e088(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,
                                   param_8,puVar5,5,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (psVar6 != (short *)0x0) {
      psVar6[3] = psVar6[3] | 0x2000;
      iVar10 = *(int *)(iVar10 + 0x2d0);
      if (iVar10 == 0) {
        uVar8 = FUN_80070050();
        *psVar6 = *psVar3;
        FUN_8000fc54();
        dVar13 = (double)FUN_802945e0();
        dVar14 = (double)FUN_80294964();
        dVar15 = (double)(FLOAT_803e8bf4 * (float)(dVar13 / dVar14));
        dVar13 = FUN_8000fc44();
        uStack_5c = (int)(uVar8 & 0xffff) >> 1 ^ 0x80000000;
        local_60 = 0x43300000;
        local_58 = 0x43300000;
        dVar14 = (double)(float)(dVar15 * -(double)(float)((double)((*(float *)(iVar11 + 0x788) -
                                                                    (float)((double)CONCAT44(
                                                  0x43300000,uStack_5c) - DOUBLE_803e8b58)) /
                                                  (float)((double)CONCAT44(0x43300000,uStack_5c) -
                                                         DOUBLE_803e8b58)) * dVar13));
        uStack_4c = (int)uVar8 >> 0x11 ^ 0x80000000;
        local_50 = 0x43300000;
        local_48 = 0x43300000;
        dVar15 = (double)(float)(dVar15 * (double)((*(float *)(iVar11 + 0x78c) -
                                                   (float)((double)CONCAT44(0x43300000,uStack_4c) -
                                                          DOUBLE_803e8b58)) /
                                                  (float)((double)CONCAT44(0x43300000,uStack_4c) -
                                                         DOUBLE_803e8b58)));
        uStack_54 = uStack_5c;
        uStack_44 = uStack_4c;
        dVar13 = FUN_80293900((double)(FLOAT_803e8d44 +
                                      (float)(dVar14 * dVar14 + (double)(float)(dVar15 * dVar15))));
        local_c8 = (float)(dVar14 / dVar13);
        local_c4 = (float)(dVar15 / dVar13);
        local_c0 = (float)((double)FLOAT_803e8bf4 / dVar13);
        pfVar7 = (float *)FUN_8000e834();
        FUN_80022714(pfVar7,&local_c8,&local_c8);
        fVar1 = FLOAT_803e8d74;
        *(float *)(psVar6 + 0x12) = FLOAT_803e8d74 * local_c8;
        *(float *)(psVar6 + 0x14) = fVar1 * local_c4;
        *(float *)(psVar6 + 0x16) = fVar1 * local_c0;
        fVar2 = FLOAT_803e8b6c;
        fVar1 = FLOAT_803e8b6c * *(float *)(psVar6 + 0x12) + *(float *)(psVar3 + 6);
        *(float *)(psVar6 + 0xc) = fVar1;
        *(float *)(psVar6 + 6) = fVar1;
        fVar1 = fVar2 * *(float *)(psVar6 + 0x14) + *(float *)(psVar3 + 8);
        *(float *)(psVar6 + 0xe) = fVar1;
        *(float *)(psVar6 + 8) = fVar1;
        fVar1 = fVar2 * *(float *)(psVar6 + 0x16) + *(float *)(psVar3 + 10);
        *(float *)(psVar6 + 0x10) = fVar1;
        *(float *)(psVar6 + 10) = fVar1;
        psVar6[1] = psVar3[1] / 2;
        *psVar6 = -*psVar3;
      }
      else {
        pfVar7 = (float *)(*(int *)(iVar10 + 0x74) + (uint)*(byte *)(iVar10 + 0xe4) * 0x18);
        fVar1 = *pfVar7 - *(float *)(DAT_803df0cc + 0xc);
        fVar2 = pfVar7[2] - *(float *)(DAT_803df0cc + 0x14);
        local_b0 = FLOAT_803e8b3c;
        local_ac = FLOAT_803e8b3c;
        local_a8 = FLOAT_803e8b3c;
        local_b4 = FLOAT_803e8b78;
        local_bc = *(ushort *)(iVar11 + 0x478);
        FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
        iVar12 = FUN_80021884();
        local_ba = (undefined2)iVar12;
        local_b8 = 0;
        if (*(short **)(uVar8 + 0x30) != (short *)0x0) {
          local_bc = local_bc + **(short **)(uVar8 + 0x30);
        }
        FUN_80021fac(afStack_a4,&local_bc);
        FUN_80022790((double)FLOAT_803e8b3c,(double)FLOAT_803e8b3c,(double)FLOAT_803e8d74,afStack_a4
                     ,(float *)(psVar6 + 0x12),(float *)(psVar6 + 0x14),(float *)(psVar6 + 0x16));
        *(undefined4 *)(psVar6 + 0xc) = *(undefined4 *)(psVar6 + 6);
        *(undefined4 *)(psVar6 + 0xe) = *(undefined4 *)(psVar6 + 8);
        *(undefined4 *)(psVar6 + 0x10) = *(undefined4 *)(psVar6 + 10);
        *psVar6 = *(short *)(iVar11 + 0x478);
        psVar6[1] = psVar3[1] / 2;
        iVar12 = iVar10;
      }
      psVar6[0x7a] = 0;
      psVar6[0x7b] = 0x5f;
      *(int *)(psVar6 + 0x7c) = iVar12;
    }
  }
  FUN_80286888();
  return;
}

