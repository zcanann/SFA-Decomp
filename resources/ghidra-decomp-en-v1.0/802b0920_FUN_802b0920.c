// Function: FUN_802b0920
// Entry: 802b0920
// Size: 1412 bytes

/* WARNING: Removing unreachable block (ram,0x802b0e7c) */
/* WARNING: Removing unreachable block (ram,0x802b0e84) */

void FUN_802b0920(void)

{
  ushort uVar1;
  bool bVar2;
  byte bVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  uint uVar10;
  undefined2 *puVar11;
  int iVar12;
  uint uVar13;
  int iVar14;
  undefined4 uVar15;
  double dVar16;
  double in_f30;
  double in_f31;
  double dVar17;
  undefined8 uVar18;
  double local_78;
  double local_70;
  double local_58;
  double local_50;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,SUB84(in_f30,0),0);
  uVar18 = FUN_802860d4();
  iVar5 = (int)((ulonglong)uVar18 >> 0x20);
  iVar12 = (int)uVar18;
  iVar6 = FUN_800395d8(iVar5,9);
  psVar7 = (short *)FUN_800395d8(iVar5,0);
  bVar2 = false;
  iVar14 = *(int *)(iVar5 + 0xb8);
  if (**(char **)(iVar12 + 0x35c) < '\x01') {
    puVar8 = (undefined4 *)FUN_800394ac(iVar5,5,0);
    puVar9 = (undefined4 *)FUN_800394ac(iVar5,4,0);
    if (puVar8 != (undefined4 *)0x0) {
      *puVar8 = 0x200;
    }
    if (puVar9 != (undefined4 *)0x0) {
      *puVar9 = 0x200;
    }
  }
  else {
    FUN_8003b310(iVar5,iVar12 + 0x364);
  }
  if ((*(uint *)(iVar12 + 0x360) & 0x2000000) == 0) {
    dVar16 = (double)FUN_80292b44((double)FLOAT_803e7ff4,(double)FLOAT_803db414);
    *(short *)(iVar12 + 0x4d0) =
         (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)(iVar12 + 0x4d0) ^ 0x80000000)
                                     - DOUBLE_803e7ec0) * dVar16);
    dVar16 = (double)FUN_80292b44((double)FLOAT_803e7f1c,(double)FLOAT_803db414);
    local_78 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x4d6) ^ 0x80000000);
    *(short *)(iVar12 + 0x4d6) = (short)(int)((double)(float)(local_78 - DOUBLE_803e7ec0) * dVar16);
    dVar16 = (double)FUN_80292b44((double)FLOAT_803e7f1c,(double)FLOAT_803db414);
    *(short *)(iVar12 + 0x4d4) =
         (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)(iVar12 + 0x4d4) ^ 0x80000000)
                                     - DOUBLE_803e7ec0) * dVar16);
    dVar16 = (double)FUN_80292b44((double)FLOAT_803e7f1c,(double)FLOAT_803db414);
    local_58 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x4d2) ^ 0x80000000);
    *(short *)(iVar12 + 0x4d2) = (short)(int)((double)(float)(local_58 - DOUBLE_803e7ec0) * dVar16);
  }
  dVar16 = DOUBLE_803e7ec0;
  fVar4 = FLOAT_803e7e98;
  bVar3 = *(byte *)(iVar12 + 0x3f0) >> 5 & 1;
  if (bVar3 != 0) {
    dVar17 = (double)(*(float *)(iVar14 + 0x294) / *(float *)(*(int *)(iVar12 + 0x400) + 0x18));
    in_f31 = (double)FLOAT_803e7ea4;
    if ((in_f31 <= dVar17) && (in_f31 = dVar17, (double)FLOAT_803e7ee0 < dVar17)) {
      in_f31 = (double)FLOAT_803e7ee0;
    }
    in_f30 = (double)(float)((double)FLOAT_803e7ee0 - in_f31);
  }
  if (iVar6 != 0) {
    if (bVar3 == 0) {
      *(undefined2 *)(iVar6 + 4) = *(undefined2 *)(iVar12 + 0x4d0);
      *(undefined2 *)(iVar6 + 2) = *(undefined2 *)(iVar12 + 0x4d2);
    }
    else {
      local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x4d0) ^ 0x80000000);
      local_58 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x4d2) ^ 0x80000000);
      *(short *)(iVar6 + 4) =
           (short)(int)(FLOAT_803e7e98 *
                       (float)((double)(float)(local_50 - DOUBLE_803e7ec0) * in_f30 +
                              (double)(float)((double)(float)(local_58 - DOUBLE_803e7ec0) * in_f31))
                       );
      local_70 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x4d0) ^ 0x80000000);
      *(short *)(iVar6 + 2) =
           (short)(int)(fVar4 * (float)((double)(float)((double)CONCAT44(0x43300000,
                                                                         (int)*(short *)(iVar12 + 
                                                  0x4d2) ^ 0x80000000) - dVar16) * in_f30 +
                                       (double)(float)((double)(float)(local_70 - dVar16) * in_f31))
                       );
    }
  }
  if (psVar7 != (short *)0x0) {
    *psVar7 = -*(short *)(iVar12 + 0x4d6);
    dVar16 = DOUBLE_803e7ec0;
    fVar4 = FLOAT_803e7e98;
    if ((*(byte *)(iVar12 + 0x3f0) >> 5 & 1) == 0) {
      psVar7[1] = *(short *)(iVar12 + 0x4d4) / 2;
      psVar7[2] = -(*(short *)(iVar12 + 0x4d0) / 2);
    }
    else {
      uVar13 = (int)*(short *)(iVar12 + 0x4d4) / 2 ^ 0x80000000;
      local_50 = (double)CONCAT44(0x43300000,uVar13);
      uVar10 = -((int)*(short *)(iVar12 + 0x4d0) / 2) ^ 0x80000000;
      local_58 = (double)CONCAT44(0x43300000,uVar10);
      psVar7[1] = (short)(int)(FLOAT_803e7e98 *
                              (float)((double)(float)(local_50 - DOUBLE_803e7ec0) * in_f30 +
                                     (double)(float)((double)(float)(local_58 - DOUBLE_803e7ec0) *
                                                    in_f31)));
      local_70 = (double)CONCAT44(0x43300000,uVar13);
      psVar7[2] = (short)(int)(fVar4 * (float)((double)(float)((double)CONCAT44(0x43300000,uVar10) -
                                                              dVar16) * in_f30 +
                                              (double)(float)((double)(float)(local_70 - dVar16) *
                                                             in_f31)));
    }
  }
  if ((*(byte *)(iVar12 + 0x3f0) >> 5 & 1) == 0) {
    uVar1 = *(ushort *)(iVar12 + 0x4d0);
    *(ushort *)(iVar5 + 4) = ((short)uVar1 >> 2) + (ushort)((short)uVar1 < 0 && (uVar1 & 3) != 0);
  }
  else {
    dVar16 = (double)FUN_80292b44((double)FLOAT_803e7ff4,(double)FLOAT_803db414);
    local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 4) ^ 0x80000000);
    *(short *)(iVar5 + 4) = (short)(int)((double)(float)(local_50 - DOUBLE_803e7ec0) * dVar16);
  }
  FUN_80038988(iVar5,iVar12 + 0x364,*(short *)(iVar12 + 0x274) == 1);
  if ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0) {
    if ((*(byte *)(iVar12 + 0x3f1) >> 5 & 1) == 0) {
      iVar6 = FUN_80295a04(iVar5,2);
      if ((((iVar6 == 0) && ('\x04' < **(char **)(iVar12 + 0x35c))) && (DAT_803dc66c == '\x01')) &&
         (iVar6 = FUN_800221a0(0,300), iVar6 == 1)) {
        DAT_803dc66c = '\x02';
        bVar2 = true;
      }
      if (((!bVar2) && (DAT_803dc66c == '\x02')) && (iVar6 = FUN_800221a0(0,5), iVar6 == 1)) {
        DAT_803dc66c = '\x01';
      }
    }
    else {
      DAT_803dc66c = '\x05';
    }
    puVar11 = (undefined2 *)FUN_800395d8(iVar5,1);
    if (puVar11 != (undefined2 *)0x0) {
      *puVar11 = 0x1c2;
      puVar11[1] = 0;
      puVar11[2] = 0;
    }
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  FUN_80286120();
  return;
}

