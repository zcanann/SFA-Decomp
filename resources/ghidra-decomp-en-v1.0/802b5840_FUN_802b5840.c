// Function: FUN_802b5840
// Entry: 802b5840
// Size: 2244 bytes

/* WARNING: Removing unreachable block (ram,0x802b60d8) */
/* WARNING: Removing unreachable block (ram,0x802b60e0) */

void FUN_802b5840(undefined2 *param_1)

{
  char cVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  uint *puVar8;
  undefined4 uVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar12;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  puVar8 = *(uint **)(param_1 + 0x5c);
  dVar12 = (double)FLOAT_803db414;
  puVar8[0xd8] = puVar8[0xd8] & 0xf7ffffff;
  if (((*(byte *)((int)puVar8 + 0x3f2) >> 5 & 1) != 0) && ((param_1[0x58] & 0x1000) != 0)) {
    *(undefined *)((int)puVar8 + 0x25f) = 0;
  }
  (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1,puVar8 + 1);
  (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,puVar8 + 1);
  (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,puVar8 + 1);
  FUN_80026c54(DAT_803de420);
  if ((float)puVar8[0x208] < FLOAT_803e7ef0) {
    (**(code **)(*DAT_803dca8c + 0xc))(param_1,puVar8,&DAT_803dafc8);
    if (*(char *)((int)puVar8 + 0x34d) == '\x01') {
      if (((DAT_803de44c != 0) && ((*(byte *)(puVar8 + 0xfd) >> 6 & 1) != 0)) &&
         ((iVar4 = *(int *)(DAT_803de44c + 0x54), *(int *)(iVar4 + 0x50) != 0 ||
          ((*(char *)(iVar4 + 0xad) != '\0' && (*(char *)(iVar4 + 0xac) != '\x0e')))))) {
        *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 1;
        puVar8[0x1f6] = (uint)FLOAT_803e7ea4;
        *(undefined *)((int)puVar8 + 0x8ce) = *(undefined *)((int)puVar8 + 0x8cd);
        if ((*(byte *)(puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0 + 0x88) & 1) != 0)
        {
          puVar8[0x208] = (uint)FLOAT_803e80a8;
        }
        iVar6 = puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0;
        if ((*(byte *)(iVar6 + 0x88) & 2) != 0) {
          *(undefined *)((int)puVar8 + 0x8ad) =
               *(undefined *)(iVar6 + *(char *)((int)puVar8 + 0x8cd) + 0xa8);
          *(undefined *)(puVar8 + 0x22b) =
               *(undefined *)
                (puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0 +
                 (int)*(char *)((int)puVar8 + 0x8cd) + 0xab);
          uStack68 = (uint)*(byte *)((int)puVar8 + 0x8ad);
          local_48 = 0x43300000;
          puVar8[0x20a] = (uint)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e7f38);
          *(char *)((int)puVar8 + 0x8ab) = *(char *)((int)puVar8 + 0x8ab) + '\x01';
          puVar8[0x130] = *(uint *)(iVar4 + 0x50);
        }
        iVar6 = *(int *)(iVar4 + 0x50);
        if (iVar6 == 0) {
          if (*(char *)(iVar4 + 0xad) != '\0') {
            FUN_80014aa0((double)FLOAT_803e7ed8);
            DAT_803de459 = 1;
          }
        }
        else {
          if ((*(byte *)(*(int *)(iVar6 + 0x50) + 0x76) & 4) != 0) {
            FUN_80014aa0((double)FLOAT_803e7ed8);
          }
          if ((*(byte *)(*(int *)(iVar6 + 0x50) + 0x76) & 8) != 0) {
            DAT_803de459 = 1;
          }
        }
        cVar1 = *(char *)((int)puVar8 + 0x8a9);
        if (cVar1 == '\x0f') {
          *(undefined *)((int)puVar8 + 0x8c1) = 1;
        }
        else if (cVar1 == '\x1b') {
          *(undefined *)((int)puVar8 + 0x8c1) = 2;
        }
        else if (cVar1 == '\x11') {
          *(undefined *)((int)puVar8 + 0x8c1) = 0;
        }
        else {
          *(undefined *)((int)puVar8 + 0x8c1) = 1;
        }
      }
      if (*(int *)(*(int *)(param_1 + 0x2a) + 0x50) != 0) {
        *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 1;
        puVar8[0x1f6] = (uint)FLOAT_803e7ea4;
        *(undefined *)((int)puVar8 + 0x8ce) = *(undefined *)((int)puVar8 + 0x8cd);
        if ((*(byte *)(puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0 + 0x88) & 1) != 0)
        {
          puVar8[0x208] = (uint)FLOAT_803e80a8;
        }
        iVar4 = puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0;
        if ((*(byte *)(iVar4 + 0x88) & 2) != 0) {
          *(undefined *)((int)puVar8 + 0x8ad) =
               *(undefined *)(iVar4 + *(char *)((int)puVar8 + 0x8cd) + 0xa8);
          *(undefined *)(puVar8 + 0x22b) =
               *(undefined *)
                (puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0 +
                 (int)*(char *)((int)puVar8 + 0x8cd) + 0xab);
          uStack68 = (uint)*(byte *)((int)puVar8 + 0x8ad);
          local_48 = 0x43300000;
          puVar8[0x20a] = (uint)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e7f38);
          *(char *)((int)puVar8 + 0x8ab) = *(char *)((int)puVar8 + 0x8ab) + '\x01';
          puVar8[0x130] = *(uint *)(*(int *)(param_1 + 0x2a) + 0x50);
        }
      }
    }
    if ((puVar8[0xd8] & 2) != 0) {
      uVar7 = puVar8[0x37];
      if (((uVar7 == 0) || (uVar5 = *(uint *)(*(int *)(uVar7 + 0x50) + 0x44), (uVar5 & 0x40) == 0))
         || ((uVar5 & 0x8000) != 0)) {
        if ((*(int *)(param_1 + 0x18) != 0) && (uVar7 == 0)) {
          FUN_80062e84(param_1,0,1);
        }
      }
      else {
        FUN_80062e84(param_1,uVar7,1);
      }
    }
    puVar8[0xd8] = puVar8[0xd8] | 2;
    if ((puVar8[0x1fc] != 0) &&
       (((param_1[0x58] & 0x1000) != 0 ||
        (iVar4 = FUN_8007fe74(&DAT_803dc6c4,2,(int)*(short *)(puVar8 + 0x9d)), iVar4 != -1)))) {
      (**(code **)(**(int **)(puVar8[0x1fc] + 0x68) + 0x34))
                (puVar8[0x1fc],local_50,&local_54,&local_58);
      (**(code **)(*DAT_803dca50 + 0x2c))((double)local_50[0],(double)local_54,(double)local_58);
      FUN_802a9d0c(param_1,puVar8,puVar8[0x1fc],0,0,0,0,0);
    }
    if ((*(char *)((int)puVar8 + 0x25f) == '\x01') && ((puVar8[1] & 0x100000) == 0)) {
      if (((puVar8[0xd8] & 0x2000) == 0) && ((*(byte *)(puVar8 + 0x99) & 0x33) != 0)) {
        *(float *)(param_1 + 0x14) =
             (float)((double)(*(float *)(param_1 + 0xe) - *(float *)(param_1 + 0x48)) / dVar12);
        if (*(float *)(param_1 + 0x14) < FLOAT_803e811c) {
          *(float *)(param_1 + 0x14) = FLOAT_803e811c;
        }
        if (FLOAT_803e7ea4 < *(float *)(param_1 + 0x14)) {
          *(float *)(param_1 + 0x14) = FLOAT_803e7ea4;
        }
      }
      if ((((*puVar8 & 0x800000) != 0) && (FLOAT_803e7ea4 == (float)puVar8[0x224])) &&
         (FLOAT_803e7ea4 == (float)puVar8[0x225])) {
        dVar10 = (double)FUN_802931a0((double)(*(float *)(param_1 + 0x12) *
                                               *(float *)(param_1 + 0x12) +
                                              *(float *)(param_1 + 0x16) *
                                              *(float *)(param_1 + 0x16)));
        if (*(int *)(param_1 + 0x18) == 0) {
          *(float *)(param_1 + 0x12) =
               (float)((double)(*(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x46)) / dVar12);
          *(float *)(param_1 + 0x16) =
               (float)((double)(*(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x4a)) / dVar12);
        }
        else {
          *(float *)(param_1 + 0x12) =
               (float)((double)(*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40)) / dVar12);
          *(float *)(param_1 + 0x16) =
               (float)((double)(*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44)) / dVar12);
        }
        if ((((*(byte *)(puVar8 + 0x99) & 2) != 0) && ((*(byte *)(puVar8 + 0x99) & 0x20) == 0)) ||
           ((*(char *)((int)puVar8 + 0x262) != '\0' ||
            ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 8) != 0)))) {
          if (((float)puVar8[0x104] <= FLOAT_803e7ea4) && (FLOAT_803e8160 < (float)puVar8[0xa0])) {
            FUN_80014aa0((double)FLOAT_803e7f10);
            puVar8[0x104] = (uint)FLOAT_803e7f30;
            FUN_8000bb18(param_1,0x404);
          }
          uStack68 = (int)*(short *)(puVar8 + 0x121) ^ 0x80000000;
          local_48 = 0x43300000;
          dVar12 = (double)FUN_80293e80((double)((FLOAT_803e7f94 *
                                                 (float)((double)CONCAT44(0x43300000,uStack68) -
                                                        DOUBLE_803e7ec0)) / FLOAT_803e7f98));
          uStack60 = (int)*(short *)(puVar8 + 0x121) ^ 0x80000000;
          local_40 = 0x43300000;
          dVar11 = (double)FUN_80294204((double)((FLOAT_803e7f94 *
                                                 (float)((double)CONCAT44(0x43300000,uStack60) -
                                                        DOUBLE_803e7ec0)) / FLOAT_803e7f98));
          puVar8[0xa0] = (uint)(float)(-(double)*(float *)(param_1 + 0x16) * dVar11 -
                                      (double)(float)((double)*(float *)(param_1 + 0x12) * dVar12));
          puVar8[0xa0] = (uint)((float)puVar8[0xa0] * FLOAT_803e7fc4);
          fVar2 = (float)puVar8[0xa0];
          fVar3 = FLOAT_803e8110 * (float)puVar8[0xa6];
          if ((fVar3 <= fVar2) && (fVar3 = fVar2, (float)puVar8[0x101] < fVar2)) {
            fVar3 = (float)puVar8[0x101];
          }
          puVar8[0xa0] = (uint)fVar3;
          dVar11 = (double)(float)puVar8[0xa0];
          dVar12 = (double)FLOAT_803e7ea4;
          if ((dVar12 <= dVar11) && (dVar12 = dVar11, dVar10 < dVar11)) {
            dVar12 = dVar10;
          }
          puVar8[0xa0] = (uint)(float)dVar12;
          if ((*(byte *)(puVar8 + 0xfc) >> 6 & 1) == 0) {
            puVar8[0xa5] = puVar8[0xa0];
          }
        }
        *puVar8 = *puVar8 & 0xff7fffff;
      }
    }
    if ((param_1[0x58] & 0x1000) == 0) {
      *param_1 = *(undefined2 *)(puVar8 + 0x11e);
    }
    iVar4 = FUN_801e1da8();
    if ((iVar4 != 0) && (iVar6 = FUN_801e12dc(), iVar6 == 2)) {
      *(float *)(*(int *)(param_1 + 0x32) + 0x20) =
           *(float *)(param_1 + 6) - *(float *)(iVar4 + 0xc);
      *(float *)(*(int *)(param_1 + 0x32) + 0x24) =
           *(float *)(param_1 + 8) - *(float *)(iVar4 + 0x10);
      *(float *)(*(int *)(param_1 + 0x32) + 0x28) =
           *(float *)(param_1 + 10) - *(float *)(iVar4 + 0x14);
      FUN_80021ac8(iVar4,*(int *)(param_1 + 0x32) + 0x20);
      *(float *)(*(int *)(param_1 + 0x32) + 0x20) =
           *(float *)(*(int *)(param_1 + 0x32) + 0x20) + *(float *)(iVar4 + 0xc);
      *(float *)(*(int *)(param_1 + 0x32) + 0x24) =
           *(float *)(*(int *)(param_1 + 0x32) + 0x24) + *(float *)(iVar4 + 0x10);
      *(float *)(*(int *)(param_1 + 0x32) + 0x28) =
           *(float *)(*(int *)(param_1 + 0x32) + 0x28) + *(float *)(iVar4 + 0x14);
      *(uint *)(*(int *)(param_1 + 0x32) + 0x30) =
           *(uint *)(*(int *)(param_1 + 0x32) + 0x30) | 0x2020;
      param_1[2] = *(undefined2 *)(iVar4 + 4);
      puVar8[0xd8] = puVar8[0xd8] | 0x8000000;
    }
    puVar8[0xd8] = puVar8[0xd8] & 0xffbfffff;
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  return;
}

