// Function: FUN_8009f2cc
// Entry: 8009f2cc
// Size: 2576 bytes

void FUN_8009f2cc(undefined4 param_1,undefined4 param_2,short param_3,undefined param_4)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  double dVar4;
  uint uVar5;
  undefined2 uVar6;
  undefined4 *puVar7;
  int iVar8;
  int iVar9;
  short sVar11;
  int iVar10;
  uint uVar12;
  char *pcVar13;
  undefined4 uVar14;
  undefined2 *puVar15;
  undefined8 uVar16;
  short local_58;
  short local_56 [3];
  double local_50;
  double local_48;
  double local_40;
  double local_38;
  
  uVar16 = FUN_802860c8();
  puVar7 = (undefined4 *)((ulonglong)uVar16 >> 0x20);
  local_56[0] = 0;
  local_58 = 0;
  iVar8 = FUN_8002073c();
  if (iVar8 == 0) {
    iVar8 = FUN_8009b3bc(local_56,&local_58,(int)param_3,(int)uVar16,*puVar7);
    if (iVar8 == -1) {
      iVar9 = -1;
    }
    else {
      uVar5 = (uint)local_56[0];
      if ((int)uVar5 < 0x50) {
        (&DAT_8039ba28)[uVar5] = *puVar7;
      }
      if (((int)uVar5 < 0x50) && ((puVar7[0x11] & 0x40000) != 0)) {
        uVar3 = uVar5 & 1;
        uVar12 = 1 << ((int)uVar5 >> 1);
        (&DAT_8039bb6c)[uVar3 * 2] = (&DAT_8039bb6c)[uVar3 * 2] | uVar12;
        (&DAT_8039bb68)[uVar3 * 2] = (&DAT_8039bb68)[uVar3 * 2] | (int)uVar12 >> 0x1f;
      }
      else {
        uVar3 = uVar5 & 1;
        uVar12 = ~(1 << ((int)uVar5 >> 1));
        (&DAT_8039bb6c)[uVar3 * 2] = (&DAT_8039bb6c)[uVar3 * 2] & uVar12;
        (&DAT_8039bb68)[uVar3 * 2] = (&DAT_8039bb68)[uVar3 * 2] & (int)uVar12 >> 0x1f;
      }
      iVar8 = (&DAT_8039bd58)[uVar5] + local_58 * 0xa0;
      DAT_803dd250 = DAT_803dd250 + 1;
      if (30000 < DAT_803dd250) {
        DAT_803dd250 = 0;
      }
      *(short *)(iVar8 + 0x26) = DAT_803dd250;
      *(undefined4 *)(iVar8 + 0x7c) = puVar7[0x11];
      *(undefined4 *)(iVar8 + 0x80) = puVar7[0x12];
      *(byte *)(iVar8 + 0x8b) = *(byte *)(iVar8 + 0x8b) & 0xf3;
      sVar11 = FUN_8009adec((int)*(short *)((int)puVar7 + 0x42));
      iVar9 = (int)sVar11;
      if (iVar9 < 0) {
        FUN_8009b0e0((&DAT_8039bd58)[local_56[0]],(int)local_56[0],(int)local_58,1,1);
        iVar9 = -1;
      }
      else {
        iVar10 = (&DAT_8039ab58)[iVar9 * 4];
        if (iVar10 == 0) {
          FUN_8009b0e0((&DAT_8039bd58)[local_56[0]],(int)local_56[0],(int)local_58,1,1);
          iVar9 = -1;
        }
        else if (*(short *)(iVar10 + 0xe) == -1) {
          FUN_8009b0e0((&DAT_8039bd58)[local_56[0]],(int)local_56[0],(int)local_58,1,1);
          iVar9 = -1;
        }
        else {
          *(short *)(iVar10 + 0xe) = *(short *)(iVar10 + 0xe) + 1;
          *(ushort *)(iVar10 + 0x14) = (ushort)*(byte *)((int)puVar7 + 0x61);
          puVar15 = (undefined2 *)*puVar7;
          uVar14 = 0;
          if (puVar15 == (undefined2 *)0x0) {
            *(undefined4 *)(iVar8 + 0x4c) = puVar7[6];
            *(undefined4 *)(iVar8 + 0x50) = puVar7[7];
            *(undefined4 *)(iVar8 + 0x54) = puVar7[8];
            *(undefined4 *)(iVar8 + 0x48) = puVar7[5];
            *(undefined2 *)(iVar8 + 0x44) = *(undefined2 *)(puVar7 + 4);
            *(undefined2 *)(iVar8 + 0x42) = *(undefined2 *)((int)puVar7 + 0xe);
            *(undefined2 *)(iVar8 + 0x40) = *(undefined2 *)(puVar7 + 3);
          }
          else if ((*(uint *)(iVar8 + 0x7c) & 0x200000) != 0) {
            *(undefined4 *)(iVar8 + 0x4c) = *(undefined4 *)(puVar15 + 0xc);
            *(undefined4 *)(iVar8 + 0x50) = *(undefined4 *)(puVar15 + 0xe);
            *(undefined4 *)(iVar8 + 0x54) = *(undefined4 *)(puVar15 + 0x10);
            *(undefined4 *)(iVar8 + 0x48) = *(undefined4 *)(puVar15 + 4);
            *(undefined2 *)(iVar8 + 0x44) = puVar15[2];
            *(undefined2 *)(iVar8 + 0x42) = puVar15[1];
            *(undefined2 *)(iVar8 + 0x40) = *puVar15;
            if (((*(uint *)(iVar8 + 0x7c) & 2) != 0) || ((*(uint *)(iVar8 + 0x7c) & 4) != 0)) {
              puVar7[9] = (float)puVar7[9] + *(float *)(puVar15 + 0x12);
              puVar7[10] = (float)puVar7[10] + *(float *)(puVar15 + 0x14);
              puVar7[0xb] = (float)puVar7[0xb] + *(float *)(puVar15 + 0x16);
            }
            if (puVar15 != (undefined2 *)0x0) {
              uVar14 = *(undefined4 *)(puVar15 + 0x18);
            }
            puVar15 = (undefined2 *)0x0;
          }
          uVar5 = FUN_8009ddec(iVar10,puVar15,uVar14,(int)*(short *)((int)puVar7 + 0x42));
          if ((short)uVar5 == -1) {
            FUN_801378a8(s_expgfx_c__invalid_tabindex_8030fc6c);
            FUN_8009b0e0((&DAT_8039bd58)[local_56[0]],(int)local_56[0],(int)local_58,1,1);
            iVar9 = -1;
          }
          else {
            *(byte *)(iVar8 + 0x8a) = (byte)((uVar5 & 0xff) << 1) | *(byte *)(iVar8 + 0x8a) & 1;
            uVar14 = puVar7[0xc];
            *(undefined4 *)(iVar8 + 100) = uVar14;
            *(undefined4 *)(iVar8 + 0x58) = uVar14;
            uVar14 = puVar7[0xd];
            *(undefined4 *)(iVar8 + 0x68) = uVar14;
            *(undefined4 *)(iVar8 + 0x5c) = uVar14;
            uVar14 = puVar7[0xe];
            *(undefined4 *)(iVar8 + 0x6c) = uVar14;
            *(undefined4 *)(iVar8 + 0x60) = uVar14;
            *(undefined4 *)(iVar8 + 0x70) = puVar7[9];
            *(undefined4 *)(iVar8 + 0x74) = puVar7[10];
            *(undefined4 *)(iVar8 + 0x78) = puVar7[0xb];
            *(undefined *)(iVar8 + 0xf) = *(undefined *)(puVar7 + 0x18);
            *(short *)(iVar8 + 0x36) = (short)puVar7[1];
            *(short *)(iVar8 + 6) = (short)puVar7[2];
            *(short *)(iVar8 + 0x16) = (short)puVar7[2];
            if (FLOAT_803df354 < (float)puVar7[0xf]) {
              FUN_801378a8(s_expgfx_c__scale_overflow_8030fc88);
            }
            fVar1 = FLOAT_803df350 * (float)puVar7[0xf];
            if ((*(uint *)(iVar8 + 0x7c) & 0x100000) == 0) {
              if ((*(uint *)(iVar8 + 0x80) & 0x2000) == 0) {
                local_38 = (double)(longlong)(int)fVar1;
                *(short *)(iVar8 + 0x84) = (short)(int)fVar1;
                *(undefined2 *)(iVar8 + 0x86) = *(undefined2 *)(iVar8 + 0x84);
                *(undefined2 *)(iVar8 + 0x88) = 0;
              }
              else {
                local_40 = (double)(longlong)(int)fVar1;
                uVar6 = (undefined2)(int)fVar1;
                *(undefined2 *)(iVar8 + 0x84) = uVar6;
                local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + 0x16) ^ 0x80000000);
                iVar10 = (int)(fVar1 / (float)(local_48 - DOUBLE_803df360));
                local_50 = (double)(longlong)iVar10;
                *(short *)(iVar8 + 0x88) = (short)iVar10;
                *(undefined2 *)(iVar8 + 0x86) = uVar6;
                local_38 = local_40;
              }
            }
            else {
              *(undefined2 *)(iVar8 + 0x84) = 0;
              local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + 0x16) ^ 0x80000000);
              iVar10 = (int)(fVar1 / (float)(local_50 - DOUBLE_803df360));
              local_48 = (double)(longlong)iVar10;
              *(short *)(iVar8 + 0x88) = (short)iVar10;
              local_40 = (double)(longlong)(int)fVar1;
              *(short *)(iVar8 + 0x86) = (short)(int)fVar1;
            }
            if (((*(uint *)(iVar8 + 0x7c) & 0x20000) != 0) ||
               ((*(uint *)(iVar8 + 0x7c) & 0x4000000) != 0)) {
              *(undefined4 *)(iVar8 + 0x4c) = puVar7[6];
              *(undefined4 *)(iVar8 + 0x50) = puVar7[7];
              *(undefined4 *)(iVar8 + 0x54) = puVar7[8];
              *(undefined4 *)(iVar8 + 0x48) = puVar7[5];
              *(undefined2 *)(iVar8 + 0x44) = *(undefined2 *)(puVar7 + 4);
              *(undefined2 *)(iVar8 + 0x42) = *(undefined2 *)((int)puVar7 + 0xe);
              *(undefined2 *)(iVar8 + 0x40) = *(undefined2 *)(puVar7 + 3);
            }
            *(byte *)(iVar8 + 0x8b) = DAT_803dd252 & 1 | *(byte *)(iVar8 + 0x8b) & 0xfe;
            if ((*(uint *)(iVar8 + 0x80) & 8) != 0) {
              *(uint *)(iVar8 + 0x80) = *(uint *)(iVar8 + 0x80) ^ 8;
              fVar1 = FLOAT_803df41c;
              dVar4 = DOUBLE_803df360;
              local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + 6) ^ 0x80000000);
              *(float *)(iVar8 + 0x58) =
                   *(float *)(iVar8 + 0x70) * FLOAT_803df41c * (float)(local_38 - DOUBLE_803df360) +
                   *(float *)(iVar8 + 0x58);
              local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + 6) ^ 0x80000000);
              *(float *)(iVar8 + 0x5c) =
                   *(float *)(iVar8 + 0x74) * fVar1 * (float)(local_40 - dVar4) +
                   *(float *)(iVar8 + 0x5c);
              local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + 6) ^ 0x80000000);
              *(float *)(iVar8 + 0x60) =
                   *(float *)(iVar8 + 0x78) * fVar1 * (float)(local_48 - dVar4) +
                   *(float *)(iVar8 + 0x60);
              fVar1 = FLOAT_803df420;
              *(float *)(iVar8 + 0x70) = *(float *)(iVar8 + 0x70) * FLOAT_803df420;
              *(float *)(iVar8 + 0x74) = *(float *)(iVar8 + 0x74) * fVar1;
              *(float *)(iVar8 + 0x78) = *(float *)(iVar8 + 0x78) * fVar1;
            }
            if ((*(uint *)(iVar8 + 0x80) & 0x10) != 0) {
              iVar10 = FUN_8002b9ec();
              *(uint *)(iVar8 + 0x80) = *(uint *)(iVar8 + 0x80) ^ 0x10;
              dVar4 = DOUBLE_803df360;
              if ((*(uint *)(iVar8 + 0x7c) & 1) == 0) {
                fVar1 = *(float *)(iVar10 + 0x18) -
                        (*(float *)(iVar8 + 100) + *(float *)(puVar15 + 6));
                fVar2 = *(float *)(iVar10 + 0x20) -
                        (*(float *)(iVar8 + 0x6c) + *(float *)(puVar15 + 10));
                if (((fVar1 * fVar1 + fVar2 * fVar2 < FLOAT_803df424) &&
                    (FLOAT_803df35c != *(float *)(iVar10 + 0x24))) &&
                   (FLOAT_803df35c != *(float *)(iVar10 + 0x2c))) {
                  local_38 = (double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar8 + 6) << 1 ^ 0x80000000);
                  *(float *)(iVar8 + 0x70) =
                       *(float *)(iVar8 + 0x70) - fVar1 / (float)(local_38 - DOUBLE_803df360);
                  local_40 = (double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar8 + 6) << 1 ^ 0x80000000);
                  *(float *)(iVar8 + 0x74) =
                       *(float *)(iVar8 + 0x74) -
                       ((FLOAT_803df428 + *(float *)(iVar10 + 0x1c)) -
                       (*(float *)(iVar8 + 0x68) + *(float *)(puVar15 + 8))) /
                       (float)(local_40 - dVar4);
                  local_48 = (double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar8 + 6) << 1 ^ 0x80000000);
                  *(float *)(iVar8 + 0x78) =
                       *(float *)(iVar8 + 0x78) -
                       (*(float *)(iVar10 + 0x20) -
                       (*(float *)(iVar8 + 0x6c) + *(float *)(puVar15 + 10))) /
                       (float)(local_48 - dVar4);
                }
              }
              else {
                fVar1 = *(float *)(iVar10 + 0x18) - *(float *)(iVar8 + 100);
                fVar2 = *(float *)(iVar10 + 0x20) - *(float *)(iVar8 + 0x6c);
                if (((fVar1 * fVar1 + fVar2 * fVar2 < FLOAT_803df424) &&
                    (FLOAT_803df35c != *(float *)(iVar10 + 0x24))) &&
                   (FLOAT_803df35c != *(float *)(iVar10 + 0x2c))) {
                  local_38 = (double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar8 + 6) << 1 ^ 0x80000000);
                  *(float *)(iVar8 + 0x70) =
                       *(float *)(iVar8 + 0x70) + fVar1 / (float)(local_38 - DOUBLE_803df360);
                  local_40 = (double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar8 + 6) << 1 ^ 0x80000000);
                  *(float *)(iVar8 + 0x74) =
                       *(float *)(iVar8 + 0x74) +
                       ((FLOAT_803df428 + *(float *)(iVar10 + 0x1c)) - *(float *)(iVar8 + 0x68)) /
                       (float)(local_40 - dVar4);
                  local_48 = (double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar8 + 6) << 1 ^ 0x80000000);
                  *(float *)(iVar8 + 0x78) =
                       *(float *)(iVar8 + 0x78) +
                       (*(float *)(iVar10 + 0x20) - *(float *)(iVar8 + 0x6c)) /
                       (float)(local_48 - dVar4);
                }
              }
            }
            if (iVar9 == 1) {
              DAT_803dd270 = DAT_803dd270 + 1;
              DAT_803dd278 = DAT_803dd274 / DAT_803dd270;
            }
            *(char *)(iVar8 + 0x8c) = (char)((uint)*(ushort *)(puVar7 + 0x16) >> 8);
            *(char *)(iVar8 + 0x8d) = (char)((uint)*(ushort *)((int)puVar7 + 0x5a) >> 8);
            *(char *)(iVar8 + 0x8e) = (char)((uint)*(ushort *)(puVar7 + 0x17) >> 8);
            if ((puVar7[0x12] & 0x20) != 0) {
              *(char *)(iVar8 + 0x1f) = (char)((uint)puVar7[0x13] >> 8);
              *(char *)(iVar8 + 0x2f) = (char)((uint)puVar7[0x14] >> 8);
              *(char *)(iVar8 + 0x3f) = (char)((uint)puVar7[0x15] >> 8);
            }
            *(undefined *)(iVar8 + 0xc) = 0xff;
            *(undefined *)(iVar8 + 0xd) = 0xff;
            *(undefined *)(iVar8 + 0xe) = 0xff;
            *(undefined2 *)(iVar8 + 8) = 0;
            *(undefined2 *)(iVar8 + 10) = 0;
            *(undefined2 *)(iVar8 + 0x18) = 0;
            *(undefined2 *)(iVar8 + 0x1a) = 0;
            *(undefined2 *)(iVar8 + 0x28) = 0;
            *(undefined2 *)(iVar8 + 0x2a) = 0;
            *(undefined2 *)(iVar8 + 0x38) = 0;
            *(undefined2 *)(iVar8 + 0x3a) = 0;
            if ((*(uint *)(iVar8 + 0x80) & 2) != 0) {
              FUN_8009b6d4(iVar8);
            }
            pcVar13 = &DAT_8039b9d8 + local_56[0];
            *pcVar13 = (puVar7[0x11] & 0x20000000) != 0;
            if ((*pcVar13 != '\0') && ((puVar7[0x11] & 0x40000) == 0)) {
              *pcVar13 = *pcVar13 + '\x01';
            }
            (&DAT_8039bb78)[local_56[0]] = param_4;
            FUN_802419e8(iVar8,0xa0);
            iVar9 = (int)*(short *)(iVar8 + 0x26);
            DAT_803dd26c = iVar8;
          }
        }
      }
    }
  }
  else {
    iVar9 = -1;
  }
  FUN_80286114(iVar9);
  return;
}

