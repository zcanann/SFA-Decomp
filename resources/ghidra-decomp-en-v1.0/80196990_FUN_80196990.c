// Function: FUN_80196990
// Entry: 80196990
// Size: 1752 bytes

/* WARNING: Removing unreachable block (ram,0x80197038) */
/* WARNING: Removing unreachable block (ram,0x80197028) */
/* WARNING: Removing unreachable block (ram,0x80197020) */
/* WARNING: Removing unreachable block (ram,0x80197030) */
/* WARNING: Removing unreachable block (ram,0x80197040) */

void FUN_80196990(short *param_1)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  short sVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar14;
  undefined8 in_f30;
  double dVar15;
  undefined8 in_f31;
  double dVar16;
  undefined auStack168 [12];
  float local_9c;
  float local_98;
  float local_94;
  undefined4 local_90;
  uint uStack140;
  double local_88;
  double local_80;
  longlong local_78;
  undefined4 local_70;
  uint uStack108;
  double local_68;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  iVar9 = *(int *)(param_1 + 0x5c);
  bVar1 = *(byte *)(iVar9 + 0x29e);
  if ((bVar1 & 2) == 0) {
    iVar8 = *(int *)(param_1 + 0x26);
    if ((bVar1 & 1) == 0) {
      if (*(char *)((int)param_1 + 0xad) == '\0') {
        iVar5 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x40));
        if ((iVar5 != 0) || (*(short *)(iVar8 + 0x40) == -1)) {
          *(byte *)(iVar9 + 0x29e) = *(byte *)(iVar9 + 0x29e) | 1;
          FUN_800200e8((int)*(short *)(iVar8 + 0x3e),1);
          DAT_803ddb00 = '\x01';
        }
      }
      else if (DAT_803ddb00 != '\0') {
        *(byte *)(iVar9 + 0x29e) = bVar1 | 1;
      }
      *(undefined *)(param_1 + 0x1b) = 0;
    }
    else {
      *(undefined *)(param_1 + 0x1b) = 0xff;
      sVar4 = *(short *)(iVar9 + 0x29c) + (ushort)DAT_803db410;
      *(short *)(iVar9 + 0x29c) = sVar4;
      if ((int)(uint)*(ushort *)(iVar8 + 0x38) <= (int)sVar4) {
        *(byte *)(iVar9 + 0x29e) = *(byte *)(iVar9 + 0x29e) | 2;
      }
      uVar6 = (uint)*(ushort *)(iVar8 + 0x3a);
      if (((int)uVar6 < (int)*(short *)(iVar9 + 0x29c)) &&
         (uVar7 = *(ushort *)(iVar8 + 0x38) - uVar6, uVar7 != 0)) {
        local_88 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
        iVar5 = (int)(FLOAT_803e404c *
                     (FLOAT_803e4048 -
                     (float)((double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar9 + 0x29c) - uVar6 ^ 0x80000000) -
                            DOUBLE_803e4040) / (float)(local_88 - DOUBLE_803e4040)));
        if (iVar5 < 0x100) {
          if (iVar5 < 0) {
            iVar5 = 0;
          }
        }
        else {
          iVar5 = 0xff;
        }
        *(char *)(param_1 + 0x1b) = (char)iVar5;
      }
      *(float *)(param_1 + 0x12) =
           FLOAT_803db414 * *(float *)(iVar9 + 0x290) + *(float *)(param_1 + 0x12);
      *(float *)(param_1 + 0x14) =
           FLOAT_803db414 * *(float *)(iVar9 + 0x294) + *(float *)(param_1 + 0x14);
      *(float *)(param_1 + 0x16) =
           FLOAT_803db414 * *(float *)(iVar9 + 0x298) + *(float *)(param_1 + 0x16);
      *(float *)(iVar9 + 0x278) =
           FLOAT_803db414 * *(float *)(iVar9 + 0x284) + *(float *)(iVar9 + 0x278);
      *(float *)(iVar9 + 0x27c) =
           FLOAT_803db414 * *(float *)(iVar9 + 0x288) + *(float *)(iVar9 + 0x27c);
      *(float *)(iVar9 + 0x280) =
           FLOAT_803db414 * *(float *)(iVar9 + 0x28c) + *(float *)(iVar9 + 0x280);
      if ((*(byte *)(iVar9 + 0x29f) & 1) == 0) {
        if (FLOAT_803e4034 < *(float *)(param_1 + 0x12)) {
          *(float *)(param_1 + 0x12) = FLOAT_803e4034;
        }
      }
      else if (*(float *)(param_1 + 0x12) < FLOAT_803e4034) {
        *(float *)(param_1 + 0x12) = FLOAT_803e4034;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 2) == 0) {
        if (FLOAT_803e4034 < *(float *)(param_1 + 0x16)) {
          *(float *)(param_1 + 0x16) = FLOAT_803e4034;
        }
      }
      else if (*(float *)(param_1 + 0x16) < FLOAT_803e4034) {
        *(float *)(param_1 + 0x16) = FLOAT_803e4034;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 4) == 0) {
        if (FLOAT_803e4034 < *(float *)(iVar9 + 0x278)) {
          *(float *)(iVar9 + 0x278) = FLOAT_803e4034;
        }
      }
      else if (*(float *)(iVar9 + 0x278) < FLOAT_803e4034) {
        *(float *)(iVar9 + 0x278) = FLOAT_803e4034;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 8) == 0) {
        if (FLOAT_803e4034 < *(float *)(iVar9 + 0x27c)) {
          *(float *)(iVar9 + 0x27c) = FLOAT_803e4034;
        }
      }
      else if (*(float *)(iVar9 + 0x27c) < FLOAT_803e4034) {
        *(float *)(iVar9 + 0x27c) = FLOAT_803e4034;
      }
      if ((*(byte *)(iVar9 + 0x29f) & 0x10) == 0) {
        if (FLOAT_803e4034 < *(float *)(iVar9 + 0x280)) {
          *(float *)(iVar9 + 0x280) = FLOAT_803e4034;
        }
      }
      else if (*(float *)(iVar9 + 0x280) < FLOAT_803e4034) {
        *(float *)(iVar9 + 0x280) = FLOAT_803e4034;
      }
      *(float *)(param_1 + 6) =
           *(float *)(param_1 + 0x12) * FLOAT_803db414 + *(float *)(param_1 + 6);
      *(float *)(param_1 + 8) =
           *(float *)(param_1 + 0x14) * FLOAT_803db414 + *(float *)(param_1 + 8);
      *(float *)(param_1 + 10) =
           *(float *)(param_1 + 0x16) * FLOAT_803db414 + *(float *)(param_1 + 10);
      dVar12 = DOUBLE_803e4040;
      local_80 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
      iVar5 = (int)(*(float *)(iVar9 + 0x278) * FLOAT_803db414 + (float)(local_80 - DOUBLE_803e4040)
                   );
      local_88 = (double)(longlong)iVar5;
      *param_1 = (short)iVar5;
      uStack140 = (int)param_1[1] ^ 0x80000000;
      local_90 = 0x43300000;
      iVar5 = (int)(*(float *)(iVar9 + 0x27c) * FLOAT_803db414 +
                   (float)((double)CONCAT44(0x43300000,uStack140) - dVar12));
      local_78 = (longlong)iVar5;
      param_1[1] = (short)iVar5;
      uStack108 = (int)param_1[2] ^ 0x80000000;
      local_70 = 0x43300000;
      iVar5 = (int)(*(float *)(iVar9 + 0x280) * FLOAT_803db414 +
                   (float)((double)CONCAT44(0x43300000,uStack108) - dVar12));
      local_68 = (double)(longlong)iVar5;
      param_1[2] = (short)iVar5;
      if ((*(byte *)(iVar8 + 0x3c) & 2) != 0) {
        (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1,iVar9);
        (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,iVar9);
        (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,iVar9);
        if (*(char *)(iVar9 + 0x261) != '\0') {
          dVar15 = -(double)*(float *)(param_1 + 0x12);
          dVar14 = -(double)*(float *)(param_1 + 0x14);
          dVar16 = -(double)*(float *)(param_1 + 0x16);
          dVar12 = (double)FUN_802931a0((double)(float)(dVar16 * dVar16 +
                                                       (double)(float)(dVar15 * dVar15 +
                                                                      (double)(float)(dVar14 * 
                                                  dVar14))));
          if ((double)FLOAT_803e4034 != dVar12) {
            dVar11 = (double)(float)((double)FLOAT_803e4048 / dVar12);
            dVar15 = (double)(float)(dVar15 * dVar11);
            dVar14 = (double)(float)(dVar14 * dVar11);
            dVar16 = (double)(float)(dVar16 * dVar11);
          }
          fVar2 = *(float *)(iVar9 + 0x6c);
          fVar3 = *(float *)(iVar9 + 0x70);
          dVar11 = (double)(FLOAT_803e4050 *
                           (float)(dVar16 * (double)fVar3 +
                                  (double)(float)(dVar15 * (double)*(float *)(iVar9 + 0x68) +
                                                 (double)(float)(dVar14 * (double)fVar2))));
          *(float *)(param_1 + 0x12) = (float)((double)*(float *)(iVar9 + 0x68) * dVar11);
          *(float *)(param_1 + 0x14) = (float)((double)fVar2 * dVar11);
          *(float *)(param_1 + 0x16) = (float)((double)fVar3 * dVar11);
          *(float *)(param_1 + 0x12) = (float)((double)*(float *)(param_1 + 0x12) - dVar15);
          *(float *)(param_1 + 0x14) = (float)((double)*(float *)(param_1 + 0x14) - dVar14);
          *(float *)(param_1 + 0x16) = (float)((double)*(float *)(param_1 + 0x16) - dVar16);
          *(float *)(param_1 + 0x14) = (float)((double)*(float *)(param_1 + 0x14) * dVar12);
          *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * FLOAT_803e4054;
          *(float *)(param_1 + 0x12) = (float)((double)*(float *)(param_1 + 0x12) * dVar12);
          *(float *)(param_1 + 0x16) = (float)((double)*(float *)(param_1 + 0x16) * dVar12);
          fVar2 = FLOAT_803e4058;
          *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e4058;
          *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar2;
        }
      }
      if (((*(byte *)(iVar8 + 0x3c) & 4) != 0) && (*(char *)(param_1 + 0x1b) == -1)) {
        dVar16 = (double)(*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40));
        dVar15 = (double)(*(float *)(param_1 + 8) - *(float *)(param_1 + 0x42));
        dVar14 = (double)(*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44));
        uVar6 = 0;
        dVar11 = (double)FLOAT_803e405c;
        dVar12 = DOUBLE_803e4040;
        do {
          local_68 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          dVar13 = (double)(float)((double)(float)(local_68 - dVar12) * dVar11);
          local_9c = (float)(dVar16 * dVar13 + (double)*(float *)(param_1 + 0x40));
          local_98 = (float)(dVar15 * dVar13 + (double)*(float *)(param_1 + 0x42));
          local_94 = (float)(dVar14 * dVar13 + (double)*(float *)(param_1 + 0x44));
          (**(code **)(*DAT_803dca88 + 8))(param_1,1000,auStack168,0x200001,0xffffffff,0);
          uVar6 = uVar6 + 1;
        } while ((int)uVar6 < 2);
      }
    }
  }
  else {
    if ((param_1[3] & 0x2000U) != 0) {
      FUN_8002cbc4();
    }
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  __psq_l0(auStack56,uVar10);
  __psq_l1(auStack56,uVar10);
  __psq_l0(auStack72,uVar10);
  __psq_l1(auStack72,uVar10);
  return;
}

