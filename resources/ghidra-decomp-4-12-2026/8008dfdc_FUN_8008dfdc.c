// Function: FUN_8008dfdc
// Entry: 8008dfdc
// Size: 2824 bytes

/* WARNING: Removing unreachable block (ram,0x8008eac4) */
/* WARNING: Removing unreachable block (ram,0x8008eabc) */
/* WARNING: Removing unreachable block (ram,0x8008eab4) */
/* WARNING: Removing unreachable block (ram,0x8008eaac) */
/* WARNING: Removing unreachable block (ram,0x8008eaa4) */
/* WARNING: Removing unreachable block (ram,0x8008ea9c) */
/* WARNING: Removing unreachable block (ram,0x8008ea94) */
/* WARNING: Removing unreachable block (ram,0x8008ea8c) */
/* WARNING: Removing unreachable block (ram,0x8008ea84) */
/* WARNING: Removing unreachable block (ram,0x8008e02c) */
/* WARNING: Removing unreachable block (ram,0x8008e024) */
/* WARNING: Removing unreachable block (ram,0x8008e01c) */
/* WARNING: Removing unreachable block (ram,0x8008e014) */
/* WARNING: Removing unreachable block (ram,0x8008e00c) */
/* WARNING: Removing unreachable block (ram,0x8008e004) */
/* WARNING: Removing unreachable block (ram,0x8008dffc) */
/* WARNING: Removing unreachable block (ram,0x8008dff4) */
/* WARNING: Removing unreachable block (ram,0x8008dfec) */

void FUN_8008dfdc(void)

{
  int iVar1;
  int iVar2;
  float fVar3;
  ushort uVar4;
  short *psVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  int *piVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double in_f23;
  double in_f24;
  double in_f25;
  double in_f26;
  double dVar14;
  double in_f27;
  double in_f28;
  double dVar15;
  double in_f29;
  double dVar16;
  double in_f30;
  double dVar17;
  double in_f31;
  double dVar18;
  double dVar19;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  byte local_108;
  byte local_107;
  byte local_106 [2];
  undefined2 local_104;
  undefined local_102;
  float local_100;
  float local_fc;
  float local_f8;
  undefined4 local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  ushort local_e4 [4];
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
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
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  FUN_8028683c();
  local_fc = DAT_802c2718;
  local_f8 = DAT_802c271c;
  local_f4 = DAT_802c2720;
  dVar18 = (double)FLOAT_803dfd88;
  local_100 = FLOAT_803dfd88;
  local_104 = DAT_803e90e0;
  local_102 = DAT_803e90e2;
  dVar15 = dVar18;
  dVar13 = dVar18;
  dVar12 = dVar18;
  dVar11 = dVar18;
  FUN_80089b54(0,local_106,&local_107,&local_108);
  if (DAT_803dc3b8 != '\0') {
    DAT_8039b418 = FLOAT_803dfd88;
    DAT_8039b41c = FLOAT_803dfd88;
    DAT_8039b420 = FLOAT_803dfd94;
    DAT_8039b424 = FLOAT_803dfdd0;
    DAT_8039b428 = FLOAT_803dfd88;
    DAT_8039b42c = FLOAT_803dfdd4;
    DAT_8039b430 = FLOAT_803dfdd8;
    DAT_8039b434 = FLOAT_803dfd88;
    DAT_8039b438 = FLOAT_803dfd88;
    DAT_8039b43c = FLOAT_803dfdd0;
    DAT_8039b440 = FLOAT_803dfd88;
    DAT_8039b444 = FLOAT_803dfdd0;
    DAT_8039b448 = FLOAT_803dfd88;
    DAT_8039b44c = FLOAT_803dfd88;
    DAT_8039b450 = FLOAT_803dfdd8;
    DAT_8039b454 = FLOAT_803dfdd4;
    DAT_8039b458 = FLOAT_803dfd88;
    DAT_8039b45c = FLOAT_803dfdd0;
    DAT_8039b460 = FLOAT_803dfd94;
    DAT_8039b464 = FLOAT_803dfd88;
    DAT_8039b468 = FLOAT_803dfd88;
    DAT_8039b46c = FLOAT_803dfdd4;
    DAT_8039b470 = FLOAT_803dfd88;
    DAT_8039b474 = FLOAT_803dfdd4;
    DAT_803dc3b8 = '\0';
  }
  psVar5 = FUN_8000facc();
  local_f0 = FLOAT_803dfd88;
  local_ec = FLOAT_803dfd88;
  local_e8 = FLOAT_803dfdd8;
  local_d8 = FLOAT_803dfd88;
  local_d4 = FLOAT_803dfd88;
  local_d0 = FLOAT_803dfd88;
  local_dc = FLOAT_803dfd94;
  local_e4[0] = -*psVar5;
  local_e4[2] = 0;
  local_e4[1] = 0;
  FUN_80021b8c(local_e4,&local_f0);
  iVar9 = 0;
  piVar10 = &DAT_803dde04;
  do {
    fVar3 = FLOAT_803dfd98;
    if ((*piVar10 != 0) && (*(char *)(*piVar10 + 0x317) != '\0')) {
      DAT_803dc3b0 = 0;
      iVar6 = *piVar10;
      if (*(int *)(iVar6 + 0x48) == 0) {
        if (*(int *)(iVar6 + 0x44) != 0) {
          *(float *)(iVar6 + 0x30c) = *(float *)(iVar6 + 0x310) / FLOAT_803dfd98;
          iVar6 = *piVar10;
          if ((*(ushort *)(iVar6 + 4) & 1) == 0) {
            *(float *)(iVar6 + 0x310) =
                 -(FLOAT_803dc074 * *(float *)(iVar6 + 0x58) - *(float *)(iVar6 + 0x310));
            if (*(float *)(*piVar10 + 0x310) < FLOAT_803dfd88) {
              *(float *)(*piVar10 + 0x310) = FLOAT_803dfd88;
            }
          }
        }
      }
      else if ((*(ushort *)(iVar6 + 4) & 1) == 0) {
        *(float *)(iVar6 + 0x310) = FLOAT_803dfd98 * *(float *)(iVar6 + 0x30c);
        if (fVar3 < *(float *)(*piVar10 + 0x310)) {
          *(float *)(*piVar10 + 0x310) = fVar3;
        }
      }
      dVar16 = dVar13;
      dVar17 = dVar12;
      dVar19 = dVar11;
      if ((*(ushort *)(*piVar10 + 4) & 0x100) != 0) {
        FUN_8008d314(iVar9);
        dVar16 = dVar13;
        dVar17 = dVar12;
        dVar19 = dVar11;
      }
      iVar6 = *piVar10;
      if ((*(ushort *)(iVar6 + 4) & 0x10) == 0) {
        if ((*(ushort *)(iVar6 + 6) & 0x20) == 0) {
          iVar6 = 0;
          dVar12 = (double)FLOAT_803dfdf8;
          dVar11 = (double)FLOAT_803dfdf0;
          dVar14 = (double)FLOAT_803dfdc4;
          dVar13 = DOUBLE_803dfdb0;
          do {
            uVar8 = FUN_80021884();
            uVar7 = FUN_80021884();
            uVar8 = (uVar8 & 0xffff) - (uVar7 & 0xffff);
            if ((int)uVar8 < 0) {
              uVar8 = -uVar8;
            }
            if (0x7fff < (int)uVar8) {
              uVar8 = 0xffff - uVar8;
            }
            local_c8 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            fVar3 = (float)((double)(float)((double)(float)((double)(float)(dVar12 - (double)(float)
                                                  (local_c8 - dVar13)) / dVar12) - dVar11) / dVar14)
            ;
            if (fVar3 <= local_fc) {
              if (local_f8 < fVar3) {
                local_104 = CONCAT11(local_104._0_1_,(char)iVar6);
                local_f8 = fVar3;
              }
            }
            else {
              if (local_f8 < local_fc) {
                local_f8 = local_fc;
                local_104 = (ushort)local_104._0_1_;
              }
              local_104 = CONCAT11((char)iVar6,(byte)local_104);
              local_fc = fVar3;
            }
            iVar6 = iVar6 + 1;
          } while (iVar6 < 8);
          dVar13 = (double)local_fc;
          if ((double)FLOAT_803dfd88 < dVar13) {
            iVar6 = *piVar10 + (uint)local_104._0_1_ * 4;
            dVar19 = (double)(float)((double)*(float *)(iVar6 + 0x70) * dVar13 + dVar19);
            dVar17 = (double)(float)((double)*(float *)(iVar6 + 0x9c) * dVar13 + dVar17);
            dVar16 = (double)(float)((double)*(float *)(iVar6 + 200) * dVar13 + dVar16);
            dVar15 = (double)(float)((double)*(float *)(*piVar10 + (uint)local_104._0_1_ * 4 + 0x1fc
                                                       ) * dVar13 + dVar15);
            dVar18 = (double)(float)((double)*(float *)(iVar6 + 0x228) * dVar13 + dVar18);
          }
          dVar13 = (double)local_f8;
          if ((double)FLOAT_803dfd88 < dVar13) {
            iVar6 = *piVar10 + (uint)(byte)local_104 * 4;
            dVar19 = (double)(float)((double)*(float *)(iVar6 + 0x70) * dVar13 + dVar19);
            dVar17 = (double)(float)((double)*(float *)(iVar6 + 0x9c) * dVar13 + dVar17);
            dVar16 = (double)(float)((double)*(float *)(iVar6 + 200) * dVar13 + dVar16);
            dVar15 = (double)(float)((double)*(float *)(*piVar10 + (uint)(byte)local_104 * 4 + 0x1fc
                                                       ) * dVar13 + dVar15);
            dVar18 = (double)(float)((double)*(float *)(iVar6 + 0x228) * dVar13 + dVar18);
          }
        }
        else {
          (**(code **)(*DAT_803dd6d8 + 0x14))(&local_100);
          fVar3 = local_100 / FLOAT_803dfddc;
          if (local_100 / FLOAT_803dfddc < FLOAT_803dfd88) {
            fVar3 = FLOAT_803dfd88;
          }
          if (FLOAT_803dfd94 < fVar3) {
            fVar3 = FLOAT_803dfd94;
          }
          if (FLOAT_803dfde0 < fVar3) {
            if (FLOAT_803dfdc4 < fVar3) {
              if (FLOAT_803dfde4 < fVar3) {
                if (FLOAT_803dfde8 < fVar3) {
                  if (FLOAT_803dfdec < fVar3) {
                    if (FLOAT_803dfdf0 < fVar3) {
                      if (FLOAT_803dfdf4 < fVar3) {
                        dVar18 = (double)((fVar3 - FLOAT_803dfdf4) / FLOAT_803dfde0);
                        iVar6 = 7;
                      }
                      else {
                        dVar18 = (double)((fVar3 - FLOAT_803dfdf0) / FLOAT_803dfde0);
                        iVar6 = 6;
                      }
                    }
                    else {
                      dVar18 = (double)((fVar3 - FLOAT_803dfdec) / FLOAT_803dfde0);
                      iVar6 = 5;
                    }
                  }
                  else {
                    dVar18 = (double)((fVar3 - FLOAT_803dfde8) / FLOAT_803dfde0);
                    iVar6 = 4;
                  }
                }
                else {
                  dVar18 = (double)((fVar3 - FLOAT_803dfde4) / FLOAT_803dfde0);
                  iVar6 = 3;
                }
              }
              else {
                dVar18 = (double)((fVar3 - FLOAT_803dfdc4) / FLOAT_803dfde0);
                iVar6 = 2;
              }
            }
            else {
              dVar18 = (double)((fVar3 - FLOAT_803dfde0) / FLOAT_803dfde0);
              iVar6 = 1;
            }
          }
          else {
            dVar18 = (double)(fVar3 / FLOAT_803dfde0);
            iVar6 = 0;
          }
          dVar19 = FUN_80010c84(dVar18,(float *)(*piVar10 + iVar6 * 4 + 0x70),(float *)0x0);
          iVar1 = (iVar6 + 0xb) * 4;
          dVar17 = FUN_80010c84(dVar18,(float *)(*piVar10 + iVar1 + 0x70),(float *)0x0);
          dVar16 = FUN_80010c84(dVar18,(float *)(*piVar10 + (iVar6 + 0x16) * 4 + 0x70),(float *)0x0)
          ;
          dVar15 = FUN_80010c84(dVar18,(float *)(*piVar10 + iVar6 * 4 + 0x1fc),(float *)0x0);
          dVar18 = FUN_80010c84(dVar18,(float *)(*piVar10 + iVar1 + 0x1fc),(float *)0x0);
        }
      }
      else {
        dVar19 = (double)*(float *)(iVar6 + 0x70);
        dVar17 = (double)*(float *)(iVar6 + 0x9c);
        dVar16 = (double)*(float *)(iVar6 + 200);
        dVar15 = (double)*(float *)(iVar6 + 0x1fc);
        dVar18 = (double)*(float *)(iVar6 + 0x228);
      }
      dVar11 = (double)FLOAT_803dfd98;
      if ((dVar19 <= dVar11) && (dVar11 = dVar19, dVar19 < (double)FLOAT_803dfd88)) {
        dVar11 = (double)FLOAT_803dfd88;
      }
      dVar12 = (double)FLOAT_803dfd98;
      if ((dVar17 <= dVar12) && (dVar12 = dVar17, dVar17 < (double)FLOAT_803dfd88)) {
        dVar12 = (double)FLOAT_803dfd88;
      }
      dVar13 = (double)FLOAT_803dfd98;
      if ((dVar16 <= dVar13) && (dVar13 = dVar16, dVar16 < (double)FLOAT_803dfd88)) {
        dVar13 = (double)FLOAT_803dfd88;
      }
      iVar6 = *piVar10;
      if ((*(ushort *)(iVar6 + 6) & 0x40) != 0) {
        if (*(char *)(iVar6 + 0x314) == -1) {
          *(undefined *)(iVar6 + 0x314) = 1;
          *(float *)(*piVar10 + 0x6c) = FLOAT_803dfd88;
          uVar8 = (uint)(-(float)(dVar18 - dVar15) * FLOAT_803dfde8);
          local_c8 = (double)(longlong)(int)uVar8;
          uVar7 = (uint)((float)(dVar18 - dVar15) * FLOAT_803dfde8);
          local_c0 = (double)(longlong)(int)uVar7;
          uVar8 = FUN_80022264(uVar8,uVar7);
          local_b8 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
          *(float *)(*piVar10 + 0x68) = (float)(local_b8 - DOUBLE_803dfdb0);
          uVar8 = FUN_80022264(1,10);
          local_b0 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
          *(float *)(*piVar10 + 100) = FLOAT_803dfdfc * (float)(local_b0 - DOUBLE_803dfdb0);
        }
        else if (*(char *)(iVar6 + 0x314) == '\x01') {
          dVar15 = (double)(float)(dVar15 + (double)*(float *)(iVar6 + 0x6c));
          *(float *)(iVar6 + 0x6c) =
               (float)((double)*(float *)(iVar6 + 0x6c) + (double)*(float *)(iVar6 + 100));
          iVar6 = *piVar10;
          if (*(float *)(iVar6 + 0x68) < *(float *)(iVar6 + 0x6c)) {
            *(char *)(iVar6 + 0x314) = '\x01' - *(char *)(iVar6 + 0x314);
          }
        }
        else {
          dVar15 = (double)(float)(dVar15 + (double)*(float *)(iVar6 + 0x6c));
          *(float *)(iVar6 + 0x6c) =
               (float)((double)*(float *)(iVar6 + 0x6c) - (double)*(float *)(iVar6 + 100));
          fVar3 = FLOAT_803dfd88;
          iVar6 = *piVar10;
          if (*(float *)(iVar6 + 0x6c) < FLOAT_803dfd88) {
            *(char *)(iVar6 + 0x314) = '\x01' - *(char *)(iVar6 + 0x314);
            *(float *)(*piVar10 + 0x6c) = fVar3;
            local_b0 = (double)(longlong)(int)(dVar18 - dVar15);
            iVar6 = (int)(short)(int)(dVar18 - dVar15);
            uVar8 = FUN_80022264(-iVar6 / 2,iVar6 / 2);
            local_b8 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            *(float *)(*piVar10 + 0x68) = (float)(local_b8 - DOUBLE_803dfdb0);
            uVar8 = FUN_80022264(1,10);
            local_c0 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            *(float *)(*piVar10 + 100) = FLOAT_803dfdfc * (float)(local_c0 - DOUBLE_803dfdb0);
          }
        }
      }
      if ((double)FLOAT_803dfe00 < dVar18) {
        dVar18 = (double)FLOAT_803dfe00;
      }
      if (dVar18 < dVar15) {
        dVar15 = (double)(float)(dVar18 - (double)FLOAT_803dfd94);
      }
      if ((double)FLOAT_803dfd88 < dVar15) {
        FUN_8005d048(0);
      }
      else {
        FUN_8005d048(1);
      }
      iVar6 = *piVar10;
      uVar4 = *(ushort *)(iVar6 + 4);
      if ((uVar4 & 8) == 0) {
        local_b0 = (double)CONCAT44(0x43300000,
                                    (uint)local_106[0] + (uint)local_107 + (uint)local_108 ^
                                    0x80000000);
        dVar16 = (double)((float)(local_b0 - DOUBLE_803dfdb0) / FLOAT_803dfe04);
        dVar11 = (double)(float)(dVar11 * dVar16);
        dVar12 = (double)(float)(dVar12 * dVar16);
        dVar13 = (double)(float)(dVar13 * dVar16);
      }
      if ((uVar4 & 1) == 0) {
        if ((uVar4 & 4) == 0) {
          iVar1 = (int)dVar11;
          local_b0 = (double)(longlong)iVar1;
          *(int *)(iVar6 + 0x24) = iVar1;
          iVar6 = (int)dVar12;
          local_b8 = (double)(longlong)iVar6;
          *(int *)(*piVar10 + 0x28) = iVar6;
          iVar2 = (int)dVar13;
          local_c0 = (double)(longlong)iVar2;
          *(int *)(*piVar10 + 0x2c) = iVar2;
          *(float *)(*piVar10 + 0x14) = (float)dVar15;
          *(float *)(*piVar10 + 0x18) = (float)dVar18;
          *(int *)(*piVar10 + 0x30) = iVar1;
          *(int *)(*piVar10 + 0x34) = iVar6;
          *(int *)(*piVar10 + 0x38) = iVar2;
          *(float *)(*piVar10 + 0x1c) = (float)dVar15;
          *(float *)(*piVar10 + 0x20) = (float)dVar18;
        }
        else {
          local_b0 = (double)(longlong)(int)dVar11;
          *(int *)(iVar6 + 0x30) = (int)dVar11;
          local_b8 = (double)(longlong)(int)dVar12;
          *(int *)(*piVar10 + 0x34) = (int)dVar12;
          local_c0 = (double)(longlong)(int)dVar13;
          *(int *)(*piVar10 + 0x38) = (int)dVar13;
          *(float *)(*piVar10 + 0x1c) = (float)dVar15;
          *(float *)(*piVar10 + 0x20) = (float)dVar18;
          if ((*(ushort *)(*piVar10 + 4) & 0x80) == 0) {
            *(undefined4 *)(*piVar10 + 0x24) = 0xff;
            *(undefined4 *)(*piVar10 + 0x28) = 0xff;
            *(undefined4 *)(*piVar10 + 0x2c) = 0xff;
            *(float *)(*piVar10 + 0x14) = FLOAT_803dfe08;
            *(float *)(*piVar10 + 0x18) = FLOAT_803dfe0c;
          }
        }
      }
      else {
        local_b0 = (double)(longlong)(int)dVar11;
        *(int *)(iVar6 + 0x24) = (int)dVar11;
        local_b8 = (double)(longlong)(int)dVar12;
        *(int *)(*piVar10 + 0x28) = (int)dVar12;
        local_c0 = (double)(longlong)(int)dVar13;
        *(int *)(*piVar10 + 0x2c) = (int)dVar13;
        *(float *)(*piVar10 + 0x14) = (float)dVar15;
        *(float *)(*piVar10 + 0x18) = (float)dVar18;
        if ((*(ushort *)(*piVar10 + 4) & 0x80) == 0) {
          *(undefined4 *)(*piVar10 + 0x30) = 0xff;
          *(undefined4 *)(*piVar10 + 0x34) = 0xff;
          *(undefined4 *)(*piVar10 + 0x38) = 0xff;
          *(float *)(*piVar10 + 0x1c) = FLOAT_803dfe08;
          *(float *)(*piVar10 + 0x20) = FLOAT_803dfe0c;
        }
      }
    }
    piVar10 = piVar10 + 1;
    iVar9 = iVar9 + 1;
  } while (iVar9 < 2);
  FUN_80286888();
  return;
}

