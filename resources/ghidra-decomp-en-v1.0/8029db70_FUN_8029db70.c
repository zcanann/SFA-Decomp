// Function: FUN_8029db70
// Entry: 8029db70
// Size: 2180 bytes

/* WARNING: Removing unreachable block (ram,0x8029e3cc) */
/* WARNING: Removing unreachable block (ram,0x8029e3d4) */

void FUN_8029db70(void)

{
  byte bVar1;
  bool bVar2;
  bool bVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  undefined2 *puVar7;
  undefined2 uVar10;
  char cVar11;
  int iVar8;
  undefined4 uVar9;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  undefined4 uVar16;
  double dVar17;
  double dVar18;
  undefined8 extraout_f1;
  undefined8 in_f30;
  double dVar19;
  undefined8 in_f31;
  undefined8 uVar20;
  undefined auStack104 [4];
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar16 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar20 = FUN_802860cc();
  puVar7 = (undefined2 *)((ulonglong)uVar20 >> 0x20);
  iVar12 = (int)uVar20;
  iVar15 = *(int *)(puVar7 + 0x5c);
  iVar13 = -1;
  bVar3 = true;
  bVar2 = false;
  local_64 = DAT_803e7e78;
  local_60 = DAT_803e7e7c;
  uVar20 = extraout_f1;
  FUN_8011f3ec(0xf);
  if (*(char *)(iVar12 + 0x27a) != '\0') {
    *(byte *)(iVar15 + 0x3f3) =
         *(byte *)(iVar15 + 0x3f3) >> 3 & 1 | *(byte *)(iVar15 + 0x3f3) & 0xfe;
    *(undefined2 *)(iVar12 + 0x278) = 0x1d;
    *(code **)(iVar15 + 0x898) = FUN_8029dae0;
  }
  if (*(char *)(iVar12 + 0x27a) != '\0') {
    if ((DAT_803de44c != 0) && ((*(byte *)(iVar15 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar15 + 0x8b4) = 1;
      *(byte *)(iVar15 + 0x3f4) = *(byte *)(iVar15 + 0x3f4) & 0xf7 | 8;
    }
    if ((*(char *)(iVar15 + 0x8c8) != 'H') && (*(char *)(iVar15 + 0x8c8) != 'G')) {
      FUN_80101974(2);
      (**(code **)(*DAT_803dca50 + 0x1c))(0x52,1,0,8,&local_64,0x1e,0xff);
    }
    *(undefined *)(iVar15 + 0x86d) = 0;
    *(undefined *)(iVar15 + 0x86e) = 0;
    uVar10 = FUN_800217c0((double)*(float *)(iVar15 + 0x654),(double)*(float *)(iVar15 + 0x65c));
    *(undefined2 *)(iVar15 + 0x478) = uVar10;
    *(undefined2 *)(iVar15 + 0x484) = *(undefined2 *)(iVar15 + 0x478);
    *puVar7 = *(undefined2 *)(iVar15 + 0x478);
    *(byte *)(iVar15 + 0x3f2) = *(byte *)(iVar15 + 0x3f2) & 0xfe | 1;
    FUN_80030334((double)FLOAT_803e7ea4,puVar7,0x5f,0);
    FUN_8002f574(puVar7,8);
    *(float *)(iVar12 + 0x2a0) = FLOAT_803e7ef8;
    fVar5 = FLOAT_803e7ea4;
    *(float *)(iVar15 + 0x444) = FLOAT_803e7ea4;
    *(float *)(iVar15 + 0x448) = fVar5;
    *(byte *)(iVar15 + 0x3f3) = *(byte *)(iVar15 + 0x3f3) & 0x7f;
    FUN_80035e8c(puVar7);
  }
  *(float *)(iVar15 + 0x7bc) = FLOAT_803e7f2c;
  fVar5 = FLOAT_803e7ea4;
  *(float *)(iVar15 + 0x7b8) = FLOAT_803e7ea4;
  *(float *)(iVar12 + 0x280) = fVar5;
  *(float *)(iVar12 + 0x284) = fVar5;
  iVar14 = *(int *)(iVar15 + 0x67c);
  switch(puVar7[0x50]) {
  case 0x4d:
  case 0x4e:
  case 0x5a:
  case 0x65:
    if (*(char *)(iVar12 + 0x346) != '\0') {
      *(uint *)(iVar15 + 0x360) = *(uint *)(iVar15 + 0x360) | 0x800000;
      *(code **)(iVar12 + 0x308) = FUN_802a514c;
      uVar9 = 2;
      goto LAB_8029e3cc;
    }
    bVar2 = true;
    bVar3 = false;
    break;
  case 0x5f:
    if ((*(uint *)(iVar12 + 0x318) & 0x100) == 0) {
      *(uint *)(iVar15 + 0x360) = *(uint *)(iVar15 + 0x360) | 0x800000;
      *(code **)(iVar12 + 0x308) = FUN_802a514c;
      uVar9 = 2;
      goto LAB_8029e3cc;
    }
  }
  bVar1 = *(byte *)(iVar15 + 0x86d);
  cVar11 = FUN_80014cc0(0);
  uStack84 = (int)cVar11 ^ 0x80000000;
  local_58 = 0x43300000;
  dVar17 = (double)((float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e7ec0) /
                   FLOAT_803e7fa8);
  dVar19 = (double)FLOAT_803e7ecc;
  if ((dVar19 <= dVar17) && (dVar19 = dVar17, (double)FLOAT_803e7ee0 < dVar17)) {
    dVar19 = (double)FLOAT_803e7ee0;
  }
  cVar11 = FUN_80014c6c(0);
  fVar5 = FLOAT_803e7ea4;
  uStack76 = (int)cVar11 ^ 0x80000000;
  local_50 = 0x43300000;
  dVar18 = (double)((float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e7ec0) /
                   FLOAT_803e7fa8);
  dVar17 = (double)FLOAT_803e7ecc;
  if ((dVar17 <= dVar18) && (dVar17 = dVar18, (double)FLOAT_803e7ee0 < dVar18)) {
    dVar17 = (double)FLOAT_803e7ee0;
  }
  if (-1 < *(char *)(iVar15 + 0x3f3)) {
    if (dVar17 <= (double)FLOAT_803e7f14) {
      if ((double)FLOAT_803e7fe0 <= dVar17) {
        fVar4 = fVar5;
        if (dVar19 <= (double)FLOAT_803e7f14) {
          if ((double)FLOAT_803e7fe0 <= dVar19) {
            if ((((*(float *)(iVar15 + 0x444) <= FLOAT_803e7f6c) &&
                 (FLOAT_803e7fdc <= *(float *)(iVar15 + 0x444))) &&
                (*(float *)(iVar15 + 0x448) <= FLOAT_803e7f6c)) &&
               (FLOAT_803e7fdc <= *(float *)(iVar15 + 0x448))) {
              *(undefined *)(iVar15 + 0x86d) = 0;
              iVar13 = 0x5f;
              *(float *)(iVar12 + 0x2a0) = FLOAT_803e7ef8;
              fVar4 = FLOAT_803e7ea4;
              fVar5 = FLOAT_803e7ea4;
            }
          }
          else {
            *(float *)(iVar15 + 0x444) = FLOAT_803e7ea4;
            dVar18 = (double)FLOAT_803e7eac;
            dVar17 = (double)FLOAT_803e7fdc;
            *(undefined *)(iVar15 + 0x86d) = 4;
            fVar5 = (float)(dVar18 * dVar19 + dVar17);
          }
        }
        else {
          *(float *)(iVar15 + 0x444) = FLOAT_803e7ea4;
          dVar18 = (double)FLOAT_803e7eac;
          dVar17 = (double)FLOAT_803e7f6c;
          *(undefined *)(iVar15 + 0x86d) = 3;
          fVar5 = (float)(dVar18 * dVar19 + dVar17);
        }
      }
      else {
        dVar18 = (double)FLOAT_803e7f48;
        dVar19 = (double)FLOAT_803e7f6c;
        *(float *)(iVar15 + 0x448) = FLOAT_803e7ea4;
        *(undefined *)(iVar15 + 0x86d) = 2;
        fVar4 = -(float)(dVar18 * dVar17 - dVar19);
      }
    }
    else {
      dVar18 = (double)FLOAT_803e7f48;
      dVar19 = (double)FLOAT_803e7fdc;
      *(float *)(iVar15 + 0x448) = FLOAT_803e7ea4;
      *(undefined *)(iVar15 + 0x86d) = 1;
      fVar4 = -(float)(dVar18 * dVar17 - dVar19);
    }
    fVar6 = FLOAT_803e7efc;
    *(float *)(iVar15 + 0x444) =
         FLOAT_803e7efc * (fVar4 - *(float *)(iVar15 + 0x444)) + *(float *)(iVar15 + 0x444);
    *(float *)(iVar15 + 0x448) =
         fVar6 * (fVar5 - *(float *)(iVar15 + 0x448)) + *(float *)(iVar15 + 0x448);
  }
  if ((-1 < *(char *)(iVar15 + 0x3f3)) &&
     ((((*(uint *)(iVar12 + 0x318) & 0x100) == 0 || (*(char *)(iVar15 + 0x681) != '\0')) ||
      (((*(byte *)(iVar15 + 0x3f1) & 1) == 0 && (FLOAT_803e7f58 <= *(float *)(iVar12 + 0x1b0)))))))
  {
    if (*(char *)(iVar15 + 0x86d) == 0) {
      *(uint *)(iVar15 + 0x360) = *(uint *)(iVar15 + 0x360) | 0x800000;
      *(code **)(iVar12 + 0x308) = FUN_802a514c;
      uVar9 = 2;
      goto LAB_8029e3cc;
    }
    FUN_80030334((double)FLOAT_803e7e98,puVar7,
                 *(undefined4 *)(&DAT_80334a68 + *(char *)(iVar15 + 0x86d) * 4),0);
    *(float *)(iVar12 + 0x2a0) = FLOAT_803e7f20;
    *(undefined *)(iVar15 + 0x86d) = 0;
    *(byte *)(iVar15 + 0x3f3) = *(byte *)(iVar15 + 0x3f3) & 0x7f | 0x80;
  }
  if (-1 < *(char *)(iVar15 + 0x3f3)) {
    if (*(char *)(iVar15 + 0x86d) != '\0') {
      DAT_803de484 = DAT_803de484 - (uint)DAT_803db410;
      if (DAT_803de484 < 1) {
        DAT_803de484 = FUN_800221a0(0xb4,0xf0);
        FUN_8000bb18(puVar7,0x2b);
      }
      *(uint *)(iVar15 + 0x360) = *(uint *)(iVar15 + 0x360) | 0x200;
      if (((int)*(char *)(iVar15 + 0x86d) == (uint)bVar1) && ((int)*(char *)(iVar15 + 0x86e) != 0))
      {
        if ((int)*(char *)(iVar15 + 0x86d) == (int)*(char *)(iVar15 + 0x86e)) {
          if (((*(byte *)(iVar15 + 0x3f3) >> 3 & 1) == 0) || ((*(byte *)(iVar15 + 0x3f3) & 1) != 0))
          {
            *(byte *)(iVar15 + 0x3f2) = *(byte *)(iVar15 + 0x3f2) & 0xfe;
          }
          else {
            *(byte *)(iVar15 + 0x3f2) = *(byte *)(iVar15 + 0x3f2) & 0xfe | 1;
            *(undefined *)(iVar15 + 0x86e) = 0;
          }
        }
      }
      else {
        *(byte *)(iVar15 + 0x3f2) = *(byte *)(iVar15 + 0x3f2) & 0xfe | 1;
        *(undefined *)(iVar15 + 0x86e) = 0;
      }
      if ((*(byte *)(iVar15 + 0x3f2) & 1) == 0) {
        if (((int)(short)puVar7[0x50] != *(int *)(&DAT_80334a78 + *(char *)(iVar15 + 0x86d) * 4)) ||
           (FLOAT_803e7fe4 <= *(float *)(puVar7 + 0x4c))) {
          uStack76 = FUN_800221a0(0,100);
          uStack76 = uStack76 ^ 0x80000000;
          local_50 = 0x43300000;
          *(float *)(iVar12 + 0x2a0) =
               FLOAT_803e7f78 *
               ((float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e7ec0) / FLOAT_803e7f5c) +
               *(float *)(&DAT_80334aa8 + *(char *)(iVar15 + 0x86d) * 4);
        }
        iVar13 = *(int *)(&DAT_80334a78 + *(char *)(iVar15 + 0x86d) * 4);
      }
      else {
        *(float *)(iVar12 + 0x2a0) =
             FLOAT_803e7ef8 * *(float *)(iVar12 + 0x298) +
             *(float *)(&DAT_80334a98 + *(char *)(iVar15 + 0x86d) * 4);
        iVar13 = *(int *)(&DAT_80334a88 + *(char *)(iVar15 + 0x86d) * 4);
      }
    }
    if (*(char *)(iVar15 + 0x86d) == '\0') {
      dVar17 = (double)FLOAT_803e7ea4;
      dVar19 = dVar17;
    }
    else {
      dVar17 = (double)*(float *)(iVar15 + 0x444);
      dVar19 = (double)*(float *)(iVar15 + 0x448);
    }
    cVar11 = (**(code **)(**(int **)(iVar14 + 0x68) + 0x20))
                       (dVar17,dVar19,iVar14,puVar7,(int)*(char *)(iVar15 + 0x86d));
    if (cVar11 == '\x01') {
      *(undefined *)(iVar15 + 0x86e) = 1;
    }
    else if (cVar11 == '\x02') {
      *(undefined *)(iVar15 + 0x86e) = 2;
    }
    else if (cVar11 == '\x03') {
      *(undefined *)(iVar15 + 0x86e) = 4;
    }
    else if (cVar11 == '\x04') {
      *(undefined *)(iVar15 + 0x86e) = 3;
    }
    else if (cVar11 == '\x05') {
      *(undefined *)(iVar15 + 0x681) = 1;
    }
    else {
      *(undefined *)(iVar15 + 0x86e) = 0;
    }
  }
  if (((iVar13 != -1) && ((short)puVar7[0x50] != iVar13)) &&
     (iVar8 = FUN_8002f50c(puVar7), iVar8 == 0)) {
    FUN_80030334((double)FLOAT_803e7ea4,puVar7,iVar13,0);
    FUN_8002f574(puVar7,10);
  }
  if (bVar2) {
    (**(code **)(*DAT_803dca8c + 0x20))(uVar20,puVar7,iVar12,3);
  }
  if (bVar3) {
    FUN_8000e0a0((double)*(float *)(iVar15 + 0x664),(double)*(float *)(iVar15 + 0x668),
                 (double)*(float *)(iVar15 + 0x66c),puVar7 + 6,auStack104,puVar7 + 10,iVar14);
    fVar5 = FLOAT_803e7fb8;
    *(float *)(puVar7 + 6) = FLOAT_803e7fb8 * *(float *)(iVar15 + 0x654) + *(float *)(puVar7 + 6);
    *(float *)(puVar7 + 10) = fVar5 * *(float *)(iVar15 + 0x65c) + *(float *)(puVar7 + 10);
  }
  *(byte *)(iVar15 + 0x3f3) = *(byte *)(iVar15 + 0x3f3) >> 3 & 1 | *(byte *)(iVar15 + 0x3f3) & 0xfe;
  uVar9 = 0;
LAB_8029e3cc:
  __psq_l0(auStack8,uVar16);
  __psq_l1(auStack8,uVar16);
  __psq_l0(auStack24,uVar16);
  __psq_l1(auStack24,uVar16);
  FUN_80286118(uVar9);
  return;
}

