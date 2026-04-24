// Function: FUN_80090c0c
// Entry: 80090c0c
// Size: 892 bytes

/* WARNING: Removing unreachable block (ram,0x80090f60) */
/* WARNING: Removing unreachable block (ram,0x80090f50) */
/* WARNING: Removing unreachable block (ram,0x80090f58) */
/* WARNING: Removing unreachable block (ram,0x80090f68) */

void FUN_80090c0c(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short *psVar5;
  float *pfVar6;
  float *pfVar7;
  int iVar8;
  undefined4 uVar9;
  undefined8 in_f28;
  double dVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  undefined4 local_90;
  uint uStack140;
  undefined4 local_88;
  uint uStack132;
  longlong local_80;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  longlong local_68;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  iVar4 = FUN_802860dc();
  psVar5 = (short *)FUN_8000faac();
  pfVar7 = (float *)(iVar4 + 0x1008);
  if (*(int *)(iVar4 + 0x13f4) == 0) {
    iVar4 = 0;
    dVar11 = (double)FLOAT_803df1e8;
    dVar10 = -dVar11;
    dVar12 = (double)FLOAT_803df1a0;
    dVar13 = DOUBLE_803df1b0;
    do {
      *pfVar7 = (float)dVar10;
      pfVar7[3] = (float)dVar10;
      pfVar7[6] = (float)dVar12;
      pfVar7[1] = (float)dVar11;
      pfVar7[4] = (float)dVar10;
      pfVar7[7] = (float)dVar12;
      pfVar7[2] = (float)dVar12;
      pfVar7[5] = (float)dVar11;
      pfVar7[8] = (float)dVar12;
      uStack140 = (uint)*(ushort *)(pfVar7 + 9);
      local_90 = 0x43300000;
      uStack132 = (uint)*(ushort *)(pfVar7 + 10);
      local_88 = 0x43300000;
      iVar8 = (int)(FLOAT_803db414 * (float)((double)CONCAT44(0x43300000,uStack140) - dVar13) +
                   (float)((double)CONCAT44(0x43300000,uStack132) - dVar13));
      local_80 = (longlong)iVar8;
      *(short *)(pfVar7 + 10) = (short)iVar8;
      uStack116 = (uint)*(ushort *)((int)pfVar7 + 0x26);
      local_78 = 0x43300000;
      uStack108 = (uint)*(ushort *)((int)pfVar7 + 0x2a);
      local_70 = 0x43300000;
      iVar8 = (int)(FLOAT_803db414 * (float)((double)CONCAT44(0x43300000,uStack116) - dVar13) +
                   (float)((double)CONCAT44(0x43300000,uStack108) - dVar13));
      local_68 = (longlong)iVar8;
      *(short *)((int)pfVar7 + 0x2a) = (short)iVar8;
      FUN_80292f14(-1 - *psVar5,&local_94,&local_98);
      FUN_80292f14(*(undefined2 *)(pfVar7 + 10),&local_9c,&local_a0);
      FUN_80292f14(*(undefined2 *)((int)pfVar7 + 0x2a),&local_a4,&local_a8);
      iVar8 = 3;
      pfVar6 = pfVar7;
      do {
        fVar1 = pfVar6[6];
        fVar3 = *pfVar6 * local_a8 - pfVar6[3] * local_a4;
        fVar2 = *pfVar6 * local_a4 + pfVar6[3] * local_a8;
        *pfVar6 = local_94 * fVar1 * local_a0 + fVar3 * local_98 + local_94 * fVar2 * local_9c;
        pfVar6[3] = fVar2 * local_a0 + -fVar1 * local_9c;
        pfVar6[6] = local_98 * fVar1 * local_a0 + -fVar3 * local_94 + local_98 * fVar2 * local_9c;
        pfVar6 = pfVar6 + 1;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
      pfVar7 = pfVar7 + 0xb;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 0x14);
  }
  else {
    FUN_80292f14(-1 - *psVar5,&local_94,&local_98);
    fVar2 = FLOAT_803df1e4;
    fVar1 = -FLOAT_803df1e4;
    iVar4 = 4;
    do {
      *pfVar7 = fVar1 * local_98;
      pfVar7[6] = fVar2 * local_94;
      pfVar7[1] = fVar2 * local_98;
      pfVar7[7] = fVar2 * -local_94;
      pfVar7[0xb] = fVar1 * local_98;
      pfVar7[0x11] = fVar2 * local_94;
      pfVar7[0xc] = fVar2 * local_98;
      pfVar7[0x12] = fVar2 * -local_94;
      pfVar7[0x16] = fVar1 * local_98;
      pfVar7[0x1c] = fVar2 * local_94;
      pfVar7[0x17] = fVar2 * local_98;
      pfVar7[0x1d] = fVar2 * -local_94;
      pfVar7[0x21] = fVar1 * local_98;
      pfVar7[0x27] = fVar2 * local_94;
      pfVar7[0x22] = fVar2 * local_98;
      pfVar7[0x28] = fVar2 * -local_94;
      pfVar7[0x2c] = fVar1 * local_98;
      pfVar7[0x32] = fVar2 * local_94;
      pfVar7[0x2d] = fVar2 * local_98;
      pfVar7[0x33] = fVar2 * -local_94;
      pfVar7 = pfVar7 + 0x37;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  __psq_l0(auStack56,uVar9);
  __psq_l1(auStack56,uVar9);
  FUN_80286128();
  return;
}

