// Function: FUN_8009f558
// Entry: 8009f558
// Size: 2576 bytes

void FUN_8009f558(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,short param_11,undefined param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  uint uVar3;
  undefined2 uVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  undefined2 *puVar10;
  char *pcVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  int iVar15;
  undefined4 *puVar16;
  undefined2 *puVar17;
  undefined2 *puVar18;
  double extraout_f1;
  double dVar19;
  double dVar20;
  double dVar21;
  undefined8 uVar22;
  short local_58;
  short local_56 [3];
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  
  uVar22 = FUN_8028682c();
  piVar5 = (int *)((ulonglong)uVar22 >> 0x20);
  local_56[0] = 0;
  local_58 = 0;
  dVar19 = extraout_f1;
  iVar6 = FUN_80020800();
  if ((iVar6 == 0) &&
     (iVar6 = FUN_8009b648(local_56,&local_58,param_11,(int)uVar22,*piVar5), iVar6 != -1)) {
    uVar3 = (uint)local_56[0];
    if ((int)uVar3 < 0x50) {
      (&DAT_8039c688)[uVar3] = *piVar5;
    }
    if (((int)uVar3 < 0x50) && ((piVar5[0x11] & 0x40000U) != 0)) {
      uVar2 = uVar3 & 1;
      uVar12 = (&DAT_8039c7c8)[uVar2 * 2];
      uVar14 = (&DAT_8039c7cc)[uVar2 * 2];
      uVar8 = 1 << ((int)uVar3 >> 1);
      uVar9 = uVar14 | uVar8;
      (&DAT_8039c7cc)[uVar2 * 2] = uVar9;
      (&DAT_8039c7c8)[uVar2 * 2] = uVar12 | (int)uVar8 >> 0x1f;
    }
    else {
      uVar2 = uVar3 & 1;
      uVar12 = (&DAT_8039c7c8)[uVar2 * 2];
      uVar14 = (&DAT_8039c7cc)[uVar2 * 2];
      uVar8 = ~(1 << ((int)uVar3 >> 1));
      uVar9 = uVar14 & uVar8;
      (&DAT_8039c7cc)[uVar2 * 2] = uVar9;
      (&DAT_8039c7c8)[uVar2 * 2] = uVar12 & (int)uVar8 >> 0x1f;
    }
    puVar16 = &DAT_8039b7b8 + (uVar3 & 1) * 2;
    puVar18 = (undefined2 *)((&DAT_8039c9b8)[uVar3] + local_58 * 0xa0);
    DAT_803dded0 = DAT_803dded0 + 1;
    if (30000 < DAT_803dded0) {
      DAT_803dded0 = 0;
    }
    puVar18[0x13] = DAT_803dded0;
    *(int *)(puVar18 + 0x3e) = piVar5[0x11];
    *(int *)(puVar18 + 0x40) = piVar5[0x12];
    *(byte *)((int)puVar18 + 0x8b) = *(byte *)((int)puVar18 + 0x8b) & 0xf3;
    iVar6 = FUN_8009b078(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)*(short *)((int)piVar5 + 0x42),uVar9,uVar12,uVar14,puVar16,param_14,
                         param_15,param_16);
    iVar6 = (int)(short)iVar6;
    if (iVar6 < 0) {
      FUN_8009b36c(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (&DAT_8039c9b8)[local_56[0]],(int)local_56[0],(int)local_58,1,1,param_14,param_15
                   ,param_16);
    }
    else {
      iVar7 = (&DAT_8039b7b8)[iVar6 * 4];
      if (iVar7 == 0) {
        FUN_8009b36c(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (&DAT_8039c9b8)[local_56[0]],(int)local_56[0],(int)local_58,1,1,param_14,
                     param_15,param_16);
      }
      else if (*(short *)(iVar7 + 0xe) == -1) {
        FUN_8009b36c(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (&DAT_8039c9b8)[local_56[0]],(int)local_56[0],(int)local_58,1,1,param_14,
                     param_15,param_16);
      }
      else {
        *(short *)(iVar7 + 0xe) = *(short *)(iVar7 + 0xe) + 1;
        *(ushort *)(iVar7 + 0x14) = (ushort)*(byte *)((int)piVar5 + 0x61);
        puVar17 = (undefined2 *)*piVar5;
        iVar13 = 0;
        if (puVar17 == (undefined2 *)0x0) {
          *(int *)(puVar18 + 0x26) = piVar5[6];
          *(int *)(puVar18 + 0x28) = piVar5[7];
          *(int *)(puVar18 + 0x2a) = piVar5[8];
          *(int *)(puVar18 + 0x24) = piVar5[5];
          puVar18[0x22] = *(undefined2 *)(piVar5 + 4);
          puVar18[0x21] = *(undefined2 *)((int)piVar5 + 0xe);
          puVar18[0x20] = *(undefined2 *)(piVar5 + 3);
        }
        else if ((*(uint *)(puVar18 + 0x3e) & 0x200000) != 0) {
          *(undefined4 *)(puVar18 + 0x26) = *(undefined4 *)(puVar17 + 0xc);
          *(undefined4 *)(puVar18 + 0x28) = *(undefined4 *)(puVar17 + 0xe);
          *(undefined4 *)(puVar18 + 0x2a) = *(undefined4 *)(puVar17 + 0x10);
          *(undefined4 *)(puVar18 + 0x24) = *(undefined4 *)(puVar17 + 4);
          puVar18[0x22] = puVar17[2];
          puVar18[0x21] = puVar17[1];
          puVar18[0x20] = *puVar17;
          if (((*(uint *)(puVar18 + 0x3e) & 2) != 0) || ((*(uint *)(puVar18 + 0x3e) & 4) != 0)) {
            piVar5[9] = (int)((float)piVar5[9] + *(float *)(puVar17 + 0x12));
            piVar5[10] = (int)((float)piVar5[10] + *(float *)(puVar17 + 0x14));
            dVar19 = (double)(float)piVar5[0xb];
            piVar5[0xb] = (int)(float)(dVar19 + (double)*(float *)(puVar17 + 0x16));
          }
          if (puVar17 != (undefined2 *)0x0) {
            iVar13 = *(int *)(puVar17 + 0x18);
          }
          puVar17 = (undefined2 *)0x0;
        }
        iVar15 = (int)*(short *)((int)piVar5 + 0x42);
        puVar10 = puVar17;
        uVar3 = FUN_8009e078(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7,
                             (int)puVar17,iVar13,iVar15);
        if ((short)uVar3 == -1) {
          uVar22 = FUN_80137c30(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                s_expgfx_c__invalid_tabindex_8031082c,puVar10,iVar13,iVar15,puVar16,
                                param_14,param_15,param_16);
          FUN_8009b36c(uVar22,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (&DAT_8039c9b8)[local_56[0]],(int)local_56[0],(int)local_58,1,1,param_14,
                       param_15,param_16);
        }
        else {
          *(byte *)(puVar18 + 0x45) = (byte)((uVar3 & 0xff) << 1) | *(byte *)(puVar18 + 0x45) & 1;
          iVar7 = piVar5[0xc];
          *(int *)(puVar18 + 0x32) = iVar7;
          *(int *)(puVar18 + 0x2c) = iVar7;
          iVar7 = piVar5[0xd];
          *(int *)(puVar18 + 0x34) = iVar7;
          *(int *)(puVar18 + 0x2e) = iVar7;
          iVar7 = piVar5[0xe];
          *(int *)(puVar18 + 0x36) = iVar7;
          *(int *)(puVar18 + 0x30) = iVar7;
          *(int *)(puVar18 + 0x38) = piVar5[9];
          *(int *)(puVar18 + 0x3a) = piVar5[10];
          *(int *)(puVar18 + 0x3c) = piVar5[0xb];
          *(undefined *)((int)puVar18 + 0xf) = *(undefined *)(piVar5 + 0x18);
          puVar18[0x1b] = (short)piVar5[1];
          puVar18[3] = (short)piVar5[2];
          puVar18[0xb] = (short)piVar5[2];
          if ((double)FLOAT_803dffd4 < (double)(float)piVar5[0xf]) {
            FUN_80137c30((double)(float)piVar5[0xf],param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,s_expgfx_c__scale_overflow_80310848,puVar10,iVar13,iVar15,puVar16,
                         param_14,param_15,param_16);
          }
          dVar20 = (double)FLOAT_803dffd0;
          dVar19 = dVar20 * (double)(float)piVar5[0xf];
          dVar21 = (double)(float)dVar19;
          if ((*(uint *)(puVar18 + 0x3e) & 0x100000) == 0) {
            if ((*(uint *)(puVar18 + 0x40) & 0x2000) == 0) {
              local_38 = (double)(longlong)(int)dVar19;
              puVar18[0x42] = (short)(int)dVar19;
              puVar18[0x43] = puVar18[0x42];
              puVar18[0x44] = 0;
            }
            else {
              param_2 = (double)(longlong)(int)dVar19;
              uVar4 = (undefined2)(int)dVar19;
              puVar18[0x42] = uVar4;
              dVar20 = DOUBLE_803dffe0;
              local_48 = (double)CONCAT44(0x43300000,(int)(short)puVar18[0xb] ^ 0x80000000);
              iVar7 = (int)(dVar21 / (double)(float)(local_48 - DOUBLE_803dffe0));
              local_50 = (double)(longlong)iVar7;
              puVar18[0x44] = (short)iVar7;
              puVar18[0x43] = uVar4;
              local_40 = param_2;
              local_38 = param_2;
            }
          }
          else {
            puVar18[0x42] = 0;
            dVar20 = DOUBLE_803dffe0;
            local_50 = (double)CONCAT44(0x43300000,(int)(short)puVar18[0xb] ^ 0x80000000);
            iVar7 = (int)(dVar21 / (double)(float)(local_50 - DOUBLE_803dffe0));
            local_48 = (double)(longlong)iVar7;
            puVar18[0x44] = (short)iVar7;
            local_40 = (double)(longlong)(int)dVar19;
            puVar18[0x43] = (short)(int)dVar19;
          }
          if (((*(uint *)(puVar18 + 0x3e) & 0x20000) != 0) ||
             ((*(uint *)(puVar18 + 0x3e) & 0x4000000) != 0)) {
            *(int *)(puVar18 + 0x26) = piVar5[6];
            *(int *)(puVar18 + 0x28) = piVar5[7];
            *(int *)(puVar18 + 0x2a) = piVar5[8];
            *(int *)(puVar18 + 0x24) = piVar5[5];
            puVar18[0x22] = *(undefined2 *)(piVar5 + 4);
            puVar18[0x21] = *(undefined2 *)((int)piVar5 + 0xe);
            puVar18[0x20] = *(undefined2 *)(piVar5 + 3);
          }
          *(byte *)((int)puVar18 + 0x8b) = DAT_803dded2 & 1 | *(byte *)((int)puVar18 + 0x8b) & 0xfe;
          if ((*(uint *)(puVar18 + 0x40) & 8) != 0) {
            *(uint *)(puVar18 + 0x40) = *(uint *)(puVar18 + 0x40) ^ 8;
            dVar21 = DOUBLE_803dffe0;
            param_4 = (double)FLOAT_803e009c;
            local_38 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] ^ 0x80000000);
            *(float *)(puVar18 + 0x2c) =
                 *(float *)(puVar18 + 0x38) *
                 (float)(param_4 * (double)(float)(local_38 - DOUBLE_803dffe0)) +
                 *(float *)(puVar18 + 0x2c);
            local_40 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] ^ 0x80000000);
            *(float *)(puVar18 + 0x2e) =
                 *(float *)(puVar18 + 0x3a) * (float)(param_4 * (double)(float)(local_40 - dVar21))
                 + *(float *)(puVar18 + 0x2e);
            param_2 = (double)*(float *)(puVar18 + 0x3c);
            local_48 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] ^ 0x80000000);
            *(float *)(puVar18 + 0x30) =
                 (float)(param_2 * (double)(float)(param_4 * (double)(float)(local_48 - dVar21)) +
                        (double)*(float *)(puVar18 + 0x30));
            dVar20 = (double)FLOAT_803e00a0;
            *(float *)(puVar18 + 0x38) = (float)((double)*(float *)(puVar18 + 0x38) * dVar20);
            *(float *)(puVar18 + 0x3a) = (float)((double)*(float *)(puVar18 + 0x3a) * dVar20);
            *(float *)(puVar18 + 0x3c) = (float)((double)*(float *)(puVar18 + 0x3c) * dVar20);
          }
          if ((*(uint *)(puVar18 + 0x40) & 0x10) != 0) {
            iVar7 = FUN_8002bac4();
            *(uint *)(puVar18 + 0x40) = *(uint *)(puVar18 + 0x40) ^ 0x10;
            dVar19 = DOUBLE_803dffe0;
            if ((*(uint *)(puVar18 + 0x3e) & 1) == 0) {
              dVar21 = (double)(*(float *)(iVar7 + 0x18) -
                               (*(float *)(puVar18 + 0x32) + *(float *)(puVar17 + 6)));
              param_2 = (double)*(float *)(iVar7 + 0x20);
              fVar1 = (float)(param_2 -
                             (double)(*(float *)(puVar18 + 0x36) + *(float *)(puVar17 + 10)));
              dVar20 = (double)(float)(dVar21 * dVar21 + (double)(fVar1 * fVar1));
              if (((dVar20 < (double)FLOAT_803e00a4) &&
                  (dVar20 = (double)FLOAT_803dffdc, dVar20 != (double)*(float *)(iVar7 + 0x24))) &&
                 (dVar20 != (double)*(float *)(iVar7 + 0x2c))) {
                local_38 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x38) =
                     *(float *)(puVar18 + 0x38) -
                     (float)(dVar21 / (double)(float)(local_38 - DOUBLE_803dffe0));
                local_40 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x3a) =
                     *(float *)(puVar18 + 0x3a) -
                     ((FLOAT_803e00a8 + *(float *)(iVar7 + 0x1c)) -
                     (*(float *)(puVar18 + 0x34) + *(float *)(puVar17 + 8))) /
                     (float)(local_40 - dVar19);
                dVar21 = (double)*(float *)(puVar18 + 0x3c);
                param_2 = (double)*(float *)(iVar7 + 0x20);
                dVar20 = (double)(float)(param_2 -
                                        (double)(*(float *)(puVar18 + 0x36) +
                                                *(float *)(puVar17 + 10)));
                local_48 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x3c) =
                     (float)(dVar21 - (double)(float)(dVar20 / (double)(float)(local_48 - dVar19)));
                param_4 = dVar19;
              }
            }
            else {
              param_2 = (double)(*(float *)(iVar7 + 0x18) - *(float *)(puVar18 + 0x32));
              fVar1 = *(float *)(iVar7 + 0x20) - *(float *)(puVar18 + 0x36);
              dVar20 = (double)(float)(param_2 * param_2 + (double)(fVar1 * fVar1));
              if (((dVar20 < (double)FLOAT_803e00a4) &&
                  (dVar20 = (double)FLOAT_803dffdc, dVar20 != (double)*(float *)(iVar7 + 0x24))) &&
                 (dVar20 != (double)*(float *)(iVar7 + 0x2c))) {
                local_38 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x38) =
                     *(float *)(puVar18 + 0x38) +
                     (float)(param_2 / (double)(float)(local_38 - DOUBLE_803dffe0));
                local_40 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x3a) =
                     *(float *)(puVar18 + 0x3a) +
                     ((FLOAT_803e00a8 + *(float *)(iVar7 + 0x1c)) - *(float *)(puVar18 + 0x34)) /
                     (float)(local_40 - dVar19);
                param_2 = (double)*(float *)(puVar18 + 0x3c);
                dVar20 = (double)(*(float *)(iVar7 + 0x20) - *(float *)(puVar18 + 0x36));
                local_48 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x3c) =
                     (float)(param_2 + (double)(float)(dVar20 / (double)(float)(local_48 - dVar19)))
                ;
                dVar21 = dVar19;
              }
            }
          }
          if (iVar6 == 1) {
            DAT_803ddef0 = DAT_803ddef0 + 1;
            DAT_803ddef8 = DAT_803ddef4 / DAT_803ddef0;
          }
          *(char *)(puVar18 + 0x46) = (char)((ushort)*(undefined2 *)(piVar5 + 0x16) >> 8);
          *(char *)((int)puVar18 + 0x8d) = (char)((ushort)*(undefined2 *)((int)piVar5 + 0x5a) >> 8);
          *(char *)(puVar18 + 0x47) = (char)((ushort)*(undefined2 *)(piVar5 + 0x17) >> 8);
          if ((piVar5[0x12] & 0x20U) != 0) {
            *(char *)((int)puVar18 + 0x1f) = (char)((uint)piVar5[0x13] >> 8);
            *(char *)((int)puVar18 + 0x2f) = (char)((uint)piVar5[0x14] >> 8);
            *(char *)((int)puVar18 + 0x3f) = (char)((uint)piVar5[0x15] >> 8);
          }
          *(undefined *)(puVar18 + 6) = 0xff;
          *(undefined *)((int)puVar18 + 0xd) = 0xff;
          *(undefined *)(puVar18 + 7) = 0xff;
          puVar18[4] = 0;
          puVar18[5] = 0;
          puVar18[0xc] = 0;
          puVar18[0xd] = 0;
          puVar18[0x14] = 0;
          puVar18[0x15] = 0;
          puVar18[0x1c] = 0;
          puVar18[0x1d] = 0;
          if ((*(uint *)(puVar18 + 0x40) & 2) != 0) {
            FUN_8009b960(dVar20,param_2,dVar21,param_4,param_5,param_6,param_7,param_8,puVar18);
          }
          pcVar11 = &DAT_8039c638 + local_56[0];
          *pcVar11 = (piVar5[0x11] & 0x20000000U) != 0;
          if ((*pcVar11 != '\0') && ((piVar5[0x11] & 0x40000U) == 0)) {
            *pcVar11 = *pcVar11 + '\x01';
          }
          (&DAT_8039c7d8)[local_56[0]] = param_12;
          FUN_802420e0((uint)puVar18,0xa0);
          DAT_803ddeec = puVar18;
        }
      }
    }
  }
  FUN_80286878();
  return;
}

