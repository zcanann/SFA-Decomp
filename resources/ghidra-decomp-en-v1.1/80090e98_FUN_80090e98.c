// Function: FUN_80090e98
// Entry: 80090e98
// Size: 892 bytes

/* WARNING: Removing unreachable block (ram,0x800911f4) */
/* WARNING: Removing unreachable block (ram,0x800911ec) */
/* WARNING: Removing unreachable block (ram,0x800911e4) */
/* WARNING: Removing unreachable block (ram,0x800911dc) */
/* WARNING: Removing unreachable block (ram,0x80090ec0) */
/* WARNING: Removing unreachable block (ram,0x80090eb8) */
/* WARNING: Removing unreachable block (ram,0x80090eb0) */
/* WARNING: Removing unreachable block (ram,0x80090ea8) */

void FUN_80090e98(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short *psVar5;
  float *pfVar6;
  float *pfVar7;
  int iVar8;
  double in_f28;
  double dVar9;
  double in_f29;
  double dVar10;
  double in_f30;
  double dVar11;
  double in_f31;
  double dVar12;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94 [2];
  uint uStack_8c;
  undefined4 local_88;
  uint uStack_84;
  longlong local_80;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  longlong local_68;
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
  iVar4 = FUN_80286840();
  psVar5 = FUN_8000facc();
  pfVar7 = (float *)(iVar4 + 0x1008);
  if (*(int *)(iVar4 + 0x13f4) == 0) {
    iVar4 = 0;
    dVar10 = (double)FLOAT_803dfe68;
    dVar9 = -dVar10;
    dVar11 = (double)FLOAT_803dfe20;
    dVar12 = DOUBLE_803dfe30;
    do {
      *pfVar7 = (float)dVar9;
      pfVar7[3] = (float)dVar9;
      pfVar7[6] = (float)dVar11;
      pfVar7[1] = (float)dVar10;
      pfVar7[4] = (float)dVar9;
      pfVar7[7] = (float)dVar11;
      pfVar7[2] = (float)dVar11;
      pfVar7[5] = (float)dVar10;
      pfVar7[8] = (float)dVar11;
      uStack_8c = (uint)*(ushort *)(pfVar7 + 9);
      local_94[1] = 176.0;
      uStack_84 = (uint)*(ushort *)(pfVar7 + 10);
      local_88 = 0x43300000;
      iVar8 = (int)(FLOAT_803dc074 * (float)((double)CONCAT44(0x43300000,uStack_8c) - dVar12) +
                   (float)((double)CONCAT44(0x43300000,uStack_84) - dVar12));
      local_80 = (longlong)iVar8;
      *(short *)(pfVar7 + 10) = (short)iVar8;
      uStack_74 = (uint)*(ushort *)((int)pfVar7 + 0x26);
      local_78 = 0x43300000;
      uStack_6c = (uint)*(ushort *)((int)pfVar7 + 0x2a);
      local_70 = 0x43300000;
      iVar8 = (int)(FLOAT_803dc074 * (float)((double)CONCAT44(0x43300000,uStack_74) - dVar12) +
                   (float)((double)CONCAT44(0x43300000,uStack_6c) - dVar12));
      local_68 = (longlong)iVar8;
      *(short *)((int)pfVar7 + 0x2a) = (short)iVar8;
      FUN_80293674(0xffffU - (int)*psVar5 & 0xffff,local_94,&local_98);
      FUN_80293674((uint)*(ushort *)(pfVar7 + 10),&local_9c,&local_a0);
      FUN_80293674((uint)*(ushort *)((int)pfVar7 + 0x2a),&local_a4,&local_a8);
      iVar8 = 3;
      pfVar6 = pfVar7;
      do {
        fVar1 = pfVar6[6];
        fVar3 = *pfVar6 * local_a8 - pfVar6[3] * local_a4;
        fVar2 = *pfVar6 * local_a4 + pfVar6[3] * local_a8;
        *pfVar6 = local_94[0] * fVar1 * local_a0 + fVar3 * local_98 + local_94[0] * fVar2 * local_9c
        ;
        pfVar6[3] = fVar2 * local_a0 + -fVar1 * local_9c;
        pfVar6[6] = local_98 * fVar1 * local_a0 + -fVar3 * local_94[0] + local_98 * fVar2 * local_9c
        ;
        pfVar6 = pfVar6 + 1;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
      pfVar7 = pfVar7 + 0xb;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 0x14);
  }
  else {
    FUN_80293674(0xffffU - (int)*psVar5 & 0xffff,local_94,&local_98);
    fVar2 = FLOAT_803dfe64;
    fVar1 = -FLOAT_803dfe64;
    iVar4 = 4;
    do {
      *pfVar7 = fVar1 * local_98;
      pfVar7[6] = fVar2 * local_94[0];
      pfVar7[1] = fVar2 * local_98;
      pfVar7[7] = fVar2 * -local_94[0];
      pfVar7[0xb] = fVar1 * local_98;
      pfVar7[0x11] = fVar2 * local_94[0];
      pfVar7[0xc] = fVar2 * local_98;
      pfVar7[0x12] = fVar2 * -local_94[0];
      pfVar7[0x16] = fVar1 * local_98;
      pfVar7[0x1c] = fVar2 * local_94[0];
      pfVar7[0x17] = fVar2 * local_98;
      pfVar7[0x1d] = fVar2 * -local_94[0];
      pfVar7[0x21] = fVar1 * local_98;
      pfVar7[0x27] = fVar2 * local_94[0];
      pfVar7[0x22] = fVar2 * local_98;
      pfVar7[0x28] = fVar2 * -local_94[0];
      pfVar7[0x2c] = fVar1 * local_98;
      pfVar7[0x32] = fVar2 * local_94[0];
      pfVar7[0x2d] = fVar2 * local_98;
      pfVar7[0x33] = fVar2 * -local_94[0];
      pfVar7 = pfVar7 + 0x37;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  FUN_8028688c();
  return;
}

