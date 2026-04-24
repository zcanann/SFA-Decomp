// Function: FUN_802aa774
// Entry: 802aa774
// Size: 668 bytes

/* WARNING: Removing unreachable block (ram,0x802aa9f0) */
/* WARNING: Removing unreachable block (ram,0x802aa9e8) */
/* WARNING: Removing unreachable block (ram,0x802aa78c) */
/* WARNING: Removing unreachable block (ram,0x802aa784) */

void FUN_802aa774(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  short *psVar4;
  uint uVar5;
  undefined2 *puVar6;
  short *psVar7;
  float *pfVar8;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar9;
  undefined8 uVar10;
  double dVar11;
  double dVar12;
  double in_f30;
  double in_f31;
  double dVar13;
  double in_ps30_1;
  double in_ps31_1;
  float local_68;
  float local_64;
  float local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar3 = FUN_80286840();
  iVar9 = *(int *)(uVar3 + 0xb8);
  psVar4 = FUN_8000facc();
  uVar5 = FUN_8002e144();
  if ((uVar5 & 0xff) != 0) {
    puVar6 = FUN_8002becc(0x24,0x14b);
    *(undefined *)(puVar6 + 2) = 2;
    *(undefined *)((int)puVar6 + 5) = 1;
    *(undefined *)(puVar6 + 3) = 0xff;
    *(undefined *)((int)puVar6 + 7) = 0xff;
    *(undefined4 *)(puVar6 + 4) = *(undefined4 *)(psVar4 + 6);
    *(undefined4 *)(puVar6 + 6) = *(undefined4 *)(psVar4 + 8);
    *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(psVar4 + 10);
    uVar10 = FUN_8000bb38(uVar3,0x20b);
    psVar7 = (short *)FUN_8002e088(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                   puVar6,5,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (psVar7 != (short *)0x0) {
      psVar7[3] = psVar7[3] | 0x2000;
      uVar3 = FUN_80070050();
      *psVar7 = *psVar4;
      FUN_8000fc54();
      dVar11 = (double)FUN_802945e0();
      dVar12 = (double)FUN_80294964();
      dVar13 = (double)(FLOAT_803e8bf4 * (float)(dVar11 / dVar12));
      dVar11 = FUN_8000fc44();
      uStack_54 = (int)(uVar3 & 0xffff) >> 1 ^ 0x80000000;
      local_58 = 0x43300000;
      local_50 = 0x43300000;
      dVar12 = (double)(float)(dVar13 * -(double)(float)((double)((*(float *)(iVar9 + 0x788) -
                                                                  (float)((double)CONCAT44(
                                                  0x43300000,uStack_54) - DOUBLE_803e8b58)) /
                                                  (float)((double)CONCAT44(0x43300000,uStack_54) -
                                                         DOUBLE_803e8b58)) * dVar11));
      uStack_44 = (int)uVar3 >> 0x11 ^ 0x80000000;
      local_48 = 0x43300000;
      local_40 = 0x43300000;
      dVar13 = (double)(float)(dVar13 * (double)((*(float *)(iVar9 + 0x78c) -
                                                 (float)((double)CONCAT44(0x43300000,uStack_44) -
                                                        DOUBLE_803e8b58)) /
                                                (float)((double)CONCAT44(0x43300000,uStack_44) -
                                                       DOUBLE_803e8b58)));
      uStack_4c = uStack_54;
      uStack_3c = uStack_44;
      dVar11 = FUN_80293900((double)(FLOAT_803e8d44 +
                                    (float)(dVar12 * dVar12 + (double)(float)(dVar13 * dVar13))));
      local_68 = (float)(dVar12 / dVar11);
      local_64 = (float)(dVar13 / dVar11);
      local_60 = (float)((double)FLOAT_803e8bf4 / dVar11);
      pfVar8 = (float *)FUN_8000e834();
      FUN_80022714(pfVar8,&local_68,&local_68);
      fVar1 = FLOAT_803e8d70;
      *(float *)(psVar7 + 0x12) = local_68 * FLOAT_803e8d70;
      *(float *)(psVar7 + 0x14) = local_64 * fVar1;
      *(float *)(psVar7 + 0x16) = local_60 * fVar1;
      fVar2 = FLOAT_803e8b6c;
      fVar1 = FLOAT_803e8b6c * *(float *)(psVar7 + 0x12) + *(float *)(psVar4 + 6);
      *(float *)(psVar7 + 0xc) = fVar1;
      *(float *)(psVar7 + 6) = fVar1;
      fVar1 = fVar2 * *(float *)(psVar7 + 0x14) + *(float *)(psVar4 + 8);
      *(float *)(psVar7 + 0xe) = fVar1;
      *(float *)(psVar7 + 8) = fVar1;
      fVar1 = fVar2 * *(float *)(psVar7 + 0x16) + *(float *)(psVar4 + 10);
      *(float *)(psVar7 + 0x10) = fVar1;
      *(float *)(psVar7 + 10) = fVar1;
      psVar7[1] = psVar4[1] / 2;
      *psVar7 = -*psVar4;
      psVar7[0x7a] = 0;
      psVar7[0x7b] = 100;
    }
  }
  FUN_8028688c();
  return;
}

