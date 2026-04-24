// Function: FUN_8029bdb4
// Entry: 8029bdb4
// Size: 2836 bytes

/* WARNING: Removing unreachable block (ram,0x8029c8a0) */
/* WARNING: Removing unreachable block (ram,0x8029c8a8) */

void FUN_8029bdb4(void)

{
  float fVar1;
  char cVar2;
  bool bVar3;
  undefined4 uVar4;
  undefined2 uVar5;
  undefined2 *puVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined4 uVar15;
  undefined8 extraout_f1;
  undefined8 in_f30;
  double in_f31;
  undefined8 uVar16;
  double local_50;
  double local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar16 = FUN_802860dc();
  puVar6 = (undefined2 *)((ulonglong)uVar16 >> 0x20);
  iVar11 = (int)uVar16;
  iVar13 = *(int *)(puVar6 + 0x5c);
  uVar16 = extraout_f1;
  iVar7 = FUN_8029b9fc();
  iVar9 = DAT_803de44c;
  if (iVar7 == 0) {
    *(undefined *)(iVar11 + 0x34d) = 1;
    DAT_803dc66c = 5;
    if (*(char *)(iVar11 + 0x27a) == '\0') {
      if (DAT_803de459 != '\0') {
        FUN_80014aa0((double)FLOAT_803e7ed8);
        *(undefined4 *)(iVar11 + 0x308) = 0;
        iVar7 = 0x28;
        goto LAB_8029c8a0;
      }
      bVar3 = false;
      if (FLOAT_803e7ea4 < *(float *)(iVar11 + 0x2a0)) {
        if ((*(uint *)(iVar11 + 0x314) & 0x200) != 0) {
          FUN_80014aa0((double)FLOAT_803e7f10);
          FUN_8000bb18(puVar6,0x3cd);
          *(ushort *)(iVar13 + 0x8d8) = *(ushort *)(iVar13 + 0x8d8) | 4;
        }
        if ((*(uint *)(iVar11 + 0x314) & 0x400) != 0) {
          FUN_80014aa0((double)FLOAT_803e7f10);
          FUN_8000bb18(puVar6,0x3cd);
          *(ushort *)(iVar13 + 0x8d8) = *(ushort *)(iVar13 + 0x8d8) | 4;
        }
        if (((*(byte *)(iVar11 + 0x356) & 1) == 0) &&
           (*(float *)(*(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0 + 0x50) <
            *(float *)(puVar6 + 0x4c))) {
          if (*(short *)(iVar13 + 0x81a) == 0) {
            uVar4 = 0x2de;
          }
          else {
            uVar4 = 0x1c;
          }
          FUN_8000bb18(puVar6,uVar4);
          *(byte *)(iVar11 + 0x356) = *(byte *)(iVar11 + 0x356) | 1;
        }
        if (((*(byte *)(iVar11 + 0x356) & 2) == 0) &&
           (*(float *)(*(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0 + 0x54) <
            *(float *)(puVar6 + 0x4c))) {
          FUN_8000bb18(puVar6,0x1a);
          *(byte *)(iVar11 + 0x356) = *(byte *)(iVar11 + 0x356) | 2;
        }
      }
      iVar7 = *(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0;
      if (-1 < *(char *)(iVar7 + 0x15)) {
        if ((*(float *)(iVar7 + 0x28) < *(float *)(puVar6 + 0x4c)) &&
           (*(byte *)(iVar11 + 0x34a) = *(byte *)(iVar11 + 0x34a) | 2,
           *(char *)(*(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0 + 0x6c) !=
           '\0')) {
          *(byte *)(iVar11 + 0x34a) = *(byte *)(iVar11 + 0x34a) | 4;
          *(undefined *)(iVar13 + 0x8c0) = 0;
        }
        if (*(float *)(*(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0 + 0x20) <
            *(float *)(puVar6 + 0x4c)) {
          *(byte *)(iVar11 + 0x34a) = *(byte *)(iVar11 + 0x34a) | 1;
        }
        if (*(float *)(*(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0 + 0x24) <
            *(float *)(puVar6 + 0x4c)) {
          *(byte *)(iVar11 + 0x34a) = *(byte *)(iVar11 + 0x34a) & 0xfe;
        }
        if (((*(uint *)(iVar11 + 0x31c) & 0x100) != 0) && ((*(byte *)(iVar11 + 0x34a) & 1) != 0)) {
          *(byte *)(iVar11 + 0x34a) = *(byte *)(iVar11 + 0x34a) | 4;
          *(uint *)(iVar11 + 0x31c) = *(uint *)(iVar11 + 0x31c) & 0xfffffeff;
          FUN_80014b3c(0,0x100);
          *(undefined *)(iVar13 + 0x8c0) = *(undefined *)(iVar11 + 0x34b);
        }
        if (((*(byte *)(iVar11 + 0x34a) & 4) != 0) && ((*(byte *)(iVar11 + 0x34a) & 2) != 0)) {
          uVar8 = FUN_8014c4d8(*(undefined4 *)(iVar11 + 0x2d0));
          iVar7 = *(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0;
          if ((float)((double)CONCAT44(0x43300000,uVar8 & 0xff) - DOUBLE_803e7f38) <
              *(float *)(iVar7 + 0x8c)) {
            *(undefined *)(iVar13 + 0x8a9) = *(undefined *)(iVar7 + 0x90);
          }
          else {
            *(undefined *)(iVar13 + 0x8a9) =
                 *(undefined *)(iVar7 + (uint)*(byte *)(iVar13 + 0x8c0) + 0x15);
          }
          bVar3 = true;
        }
      }
    }
    else {
      DAT_803de459 = '\0';
      bVar3 = true;
      *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) & 0xffffffbf;
      *(undefined *)(*(int *)(puVar6 + 0x2a) + 0x70) = 0;
      fVar1 = FLOAT_803e7ea4;
      *(float *)(iVar13 + 0x828) = FLOAT_803e7ea4;
      *(undefined *)(iVar13 + 0x8ab) = 0;
      *(undefined4 *)(iVar13 + 0x4c0) = 0;
      *(undefined *)(iVar13 + 0x8cd) = 0xff;
      *(float *)(iVar11 + 0x294) = fVar1;
      *(float *)(iVar11 + 0x284) = fVar1;
      *(float *)(iVar11 + 0x280) = fVar1;
      *(float *)(puVar6 + 0x12) = fVar1;
      *(float *)(puVar6 + 0x14) = fVar1;
      *(float *)(puVar6 + 0x16) = fVar1;
    }
    if (*(int *)(iVar11 + 0x2d0) == 0) {
      if (((*(char *)(iVar11 + 0x27a) == '\0') || (*(int *)(iVar13 + 0x4b8) == 0)) ||
         (*(short *)(iVar13 + 0x4b4) != 1)) {
        if (*(char *)(iVar11 + 0x27a) != '\0') {
          uVar5 = (undefined2)*(undefined4 *)(iVar13 + 0x474);
          *(undefined2 *)(iVar13 + 0x478) = uVar5;
          *(undefined2 *)(iVar13 + 0x484) = uVar5;
        }
      }
      else {
        if (*(int *)(iVar13 + 0x4a8) < 0x4000) {
          local_50 = (double)CONCAT44(0x43300000,*(uint *)(iVar13 + 0x4a4) ^ 0x80000000);
          in_f31 = (double)(float)(local_50 - DOUBLE_803e7ec0);
        }
        *(short *)(iVar13 + 0x478) =
             (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                           (int)*(short *)(iVar13 + 0x478) ^
                                                           0x80000000) - DOUBLE_803e7ec0) + in_f31);
        *(undefined2 *)(iVar13 + 0x484) = *(undefined2 *)(iVar13 + 0x478);
      }
    }
    else {
      if ((*(byte *)(iVar13 + 0x8a9) < 5) || (9 < *(byte *)(iVar13 + 0x8a9))) {
        fVar1 = (float)((double)CONCAT44(0x43300000,*(uint *)(iVar13 + 0x4a4) ^ 0x80000000) -
                       DOUBLE_803e7ec0) / FLOAT_803e7fb8;
      }
      else {
        fVar1 = (float)((double)CONCAT44(0x43300000,*(uint *)(iVar13 + 0x4a4) ^ 0x80000000) -
                       DOUBLE_803e7ec0);
      }
      *(short *)(iVar13 + 0x478) =
           (short)(int)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(iVar13 + 0x478) ^ 0x80000000) -
                               DOUBLE_803e7ec0) + fVar1);
      *(undefined2 *)(iVar13 + 0x484) = *(undefined2 *)(iVar13 + 0x478);
    }
    if (bVar3) {
      *(uint *)(puVar6 + 0x2e) =
           *(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0 + 0x60;
      iVar7 = *(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0;
      if ((int)(short)puVar6[0x50] != (int)*(short *)(&DAT_803336bc + *(short *)(iVar7 + 2) * 2)) {
        FUN_80030334((double)*(float *)(iVar7 + 0x68),puVar6,
                     (int)*(short *)(&DAT_803336bc + *(short *)(iVar7 + 2) * 2),0);
        FUN_8002f574(puVar6,2);
      }
      *(byte *)(iVar11 + 0x34a) = *(byte *)(iVar11 + 0x34a) & 0x10;
      *(undefined4 *)(iVar11 + 0x2a0) =
           *(undefined4 *)(*(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0 + 0x1c)
      ;
      *(undefined4 *)(iVar13 + 0x824) = *(undefined4 *)(iVar11 + 0x2a0);
      *(undefined *)(iVar13 + 0x8cf) = 0;
      *(float *)(iVar11 + 0x284) = FLOAT_803e7ea4;
      *(undefined *)(iVar11 + 0x356) = 0;
      if (*(int *)(iVar11 + 0x2d0) != 0) {
        if ((*(byte *)(iVar13 + 0x8a9) < 5) || (9 < *(byte *)(iVar13 + 0x8a9))) {
          (**(code **)(*DAT_803dca8c + 0x30))(uVar16,puVar6,iVar11,2);
        }
        else {
          (**(code **)(*DAT_803dca8c + 0x30))(uVar16,puVar6,iVar11,1);
        }
        uVar5 = *puVar6;
        *(undefined2 *)(iVar13 + 0x484) = uVar5;
        *(undefined2 *)(iVar13 + 0x478) = uVar5;
      }
      if (*(int *)(puVar6 + 0x2a) != 0) {
        *(undefined *)(*(int *)(puVar6 + 0x2a) + 0x70) = 0;
      }
      *(undefined *)(iVar13 + 0x8cd) = 0xff;
      if (*(short *)(iVar9 + 0x44) == 0x2d) {
        FUN_8016e81c(iVar9);
        (**(code **)(**(int **)(iVar9 + 0x68) + 0x38))
                  (iVar9,*(undefined *)
                          (*(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0 + 0x5c)
                  );
        iVar7 = *(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0;
        (**(code **)(**(int **)(iVar9 + 0x68) + 0x4c))
                  ((double)*(float *)(iVar7 + 0x48),(double)*(float *)(iVar7 + 0x4c),iVar9);
      }
      fVar1 = FLOAT_803e7ea4;
      *(float *)(iVar13 + 0x7d8) = FLOAT_803e7ea4;
      *(float *)(iVar13 + 0x828) = fVar1;
      *(undefined *)(iVar13 + 0x8ab) = 0;
      *(undefined4 *)(iVar13 + 0x4c0) = 0;
    }
    *(undefined *)(*(int *)(puVar6 + 0x2a) + 0x6e) = 0xb;
    *(undefined *)(*(int *)(puVar6 + 0x2a) + 0x6f) =
         *(undefined *)(*(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0 + 0x14);
    iVar9 = *(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0;
    fVar1 = *(float *)(iVar9 + 0xa0);
    if (FLOAT_803e7ea4 <= fVar1) {
      if ((*(float *)(puVar6 + 0x4c) <= fVar1) ||
         (*(float *)(iVar9 + 0xa4) <= *(float *)(puVar6 + 0x4c))) {
        *(float *)(iVar13 + 0x7d8) = FLOAT_803e7ea4;
      }
      else {
        if (FLOAT_803e7ea4 == *(float *)(iVar13 + 0x7d8)) {
          FUN_8000bb18(puVar6,0x21b);
        }
        *(float *)(iVar13 + 0x7d8) = FLOAT_803e7ed4 * FLOAT_803db414 + *(float *)(iVar13 + 0x7d8);
        if (FLOAT_803e7fbc < *(float *)(iVar13 + 0x7d8)) {
          *(float *)(iVar13 + 0x7d8) = FLOAT_803e7fbc;
        }
      }
    }
    if (((*(byte *)(*(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0 + 0x88) & 2)
         != 0) && (*(int *)(iVar13 + 0x4c0) != 0)) {
      if (*(byte *)(iVar13 + 0x8ab) < *(byte *)(iVar13 + 0x8ac)) {
        fVar1 = *(float *)(iVar13 + 0x828) - FLOAT_803e7ee0;
        *(float *)(iVar13 + 0x828) = fVar1;
        if (fVar1 <= FLOAT_803e7ea4) {
          FUN_80036450(*(undefined4 *)(iVar13 + 0x4c0),puVar6,0xb,1,0);
          *(char *)(iVar13 + 0x8ab) = *(char *)(iVar13 + 0x8ab) + '\x01';
          local_48 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar13 + 0x8ad));
          *(float *)(iVar13 + 0x828) = (float)(local_48 - DOUBLE_803e7f38);
        }
      }
      else {
        *(undefined4 *)(iVar13 + 0x4c0) = 0;
      }
    }
    iVar9 = 0;
    *(undefined4 *)(*(int *)(puVar6 + 0x2a) + 0x48) = 0;
    iVar7 = 0;
    iVar14 = 3;
    do {
      iVar12 = (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0;
      iVar10 = *(int *)(iVar13 + 0x3dc) + iVar12 + iVar9;
      if ((*(float *)(iVar10 + 0x30) <= *(float *)(puVar6 + 0x4c)) &&
         (*(float *)(puVar6 + 0x4c) <= *(float *)(iVar10 + 0x3c))) {
        if (*(char *)(*(int *)(puVar6 + 0x2a) + 0x70) == '\0') {
          cVar2 = *(char *)(*(int *)(iVar13 + 0x3dc) + iVar12 + iVar7 + 0x5d);
          if (cVar2 == '\x02') {
            uVar4 = 0x100000;
          }
          else if (cVar2 < '\x02') {
            if (cVar2 == '\0') {
              uVar4 = 0xc;
            }
            else if (cVar2 < '\0') {
              if (cVar2 < -1) goto LAB_8029c6c8;
              uVar4 = 0;
            }
            else {
              uVar4 = 3;
            }
          }
          else if (cVar2 == '\x04') {
            uVar4 = 0xf;
          }
          else if (cVar2 < '\x04') {
            uVar4 = 0x10000;
          }
          else {
LAB_8029c6c8:
            uVar4 = 0;
          }
          *(undefined4 *)(*(int *)(puVar6 + 0x2a) + 0x48) = uVar4;
        }
        if (iVar7 != *(char *)(iVar13 + 0x8cd)) {
          *(undefined *)(*(int *)(puVar6 + 0x2a) + 0x70) = 0;
          *(char *)(iVar13 + 0x8cd) = (char)iVar7;
          *(undefined *)(iVar13 + 0x8ab) = 0;
          *(float *)(iVar13 + 0x828) = FLOAT_803e7ea4;
          *(undefined4 *)(iVar13 + 0x4c0) = 0;
        }
        break;
      }
      iVar9 = iVar9 + 4;
      iVar7 = iVar7 + 1;
      iVar14 = iVar14 + -1;
    } while (iVar14 != 0);
    (**(code **)(*DAT_803dca8c + 0x20))(uVar16,puVar6,iVar11,3);
    if (*(char *)(iVar11 + 0x346) == '\0') {
      if (*(float *)(*(int *)(iVar13 + 0x3dc) + (uint)*(byte *)(iVar13 + 0x8a9) * 0xb0 + 0x2c) <=
          *(float *)(puVar6 + 0x4c)) {
        if (*(int *)(iVar11 + 0x2d0) == 0) {
          if (((*(uint *)(iVar11 + 0x31c) & 0x100) != 0) &&
             (FLOAT_803e7eac < *(float *)(iVar11 + 0x298))) {
            *(short *)(iVar13 + 0x478) =
                 *(short *)(iVar13 + 0x478) + (short)*(undefined4 *)(iVar13 + 0x480) * 0xb6;
            *(undefined2 *)(iVar13 + 0x484) = *(undefined2 *)(iVar13 + 0x478);
            *(undefined4 *)(iVar13 + 0x47c) = 0;
            *(undefined4 *)(iVar13 + 0x480) = 0;
            *(undefined4 *)(iVar13 + 0x488) = 0;
            *(undefined4 *)(iVar13 + 0x48c) = 0;
            *(undefined4 *)(iVar11 + 0x308) = 0;
            iVar7 = 0x32;
            goto LAB_8029c8a0;
          }
        }
        else if ((*(uint *)(iVar11 + 0x31c) & 0x100) != 0) {
          *(undefined *)(*(int *)(puVar6 + 0x2a) + 0x70) = 0;
          *(undefined *)(iVar13 + 0x8cd) = 0xff;
          (**(code **)(*DAT_803dca8c + 0x30))(uVar16,puVar6,iVar11,2);
          uVar5 = *puVar6;
          *(undefined2 *)(iVar13 + 0x484) = uVar5;
          *(undefined2 *)(iVar13 + 0x478) = uVar5;
          *(undefined4 *)(iVar11 + 0x308) = 0;
          iVar7 = 0x31;
          goto LAB_8029c8a0;
        }
      }
      iVar7 = 0;
    }
    else {
      *(undefined *)(*(int *)(puVar6 + 0x2a) + 0x70) = 0;
      if (*(int *)(iVar11 + 0x2d0) == 0) {
        *(byte *)(iVar13 + 0x3f1) = *(byte *)(iVar13 + 0x3f1) & 0x7f | 0x80;
        *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x800000;
        *(code **)(iVar11 + 0x308) = FUN_802a514c;
        iVar7 = 2;
      }
      else {
        *(code **)(iVar11 + 0x308) = FUN_8029c8c8;
        iVar7 = 0x25;
      }
    }
  }
LAB_8029c8a0:
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  FUN_80286128(iVar7);
  return;
}

