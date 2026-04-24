// Function: FUN_8013e0d0
// Entry: 8013e0d0
// Size: 3508 bytes

/* WARNING: Removing unreachable block (ram,0x8013ee5c) */
/* WARNING: Removing unreachable block (ram,0x8013ee4c) */
/* WARNING: Removing unreachable block (ram,0x8013e140) */
/* WARNING: Removing unreachable block (ram,0x8013ee54) */
/* WARNING: Removing unreachable block (ram,0x8013ee64) */

void FUN_8013e0d0(void)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  char cVar9;
  undefined4 uVar5;
  int iVar6;
  byte *pbVar7;
  byte **ppbVar8;
  byte **ppbVar10;
  bool bVar11;
  byte *pbVar12;
  int iVar13;
  undefined4 uVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  undefined8 in_f28;
  double dVar18;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar19;
  undefined8 uVar20;
  char local_78 [4];
  int local_74;
  undefined4 local_70;
  uint uStack108;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar20 = FUN_802860d4();
  iVar4 = (int)((ulonglong)uVar20 >> 0x20);
  ppbVar10 = (byte **)uVar20;
  pbVar12 = (byte *)0x0;
  dVar18 = (double)FLOAT_803e23dc;
  bVar1 = *(byte *)((int)ppbVar10 + 10);
  if (bVar1 == 3) {
    if ((*(short *)(iVar4 + 0xa0) == 0x34) && (FLOAT_803e24e8 < *(float *)(iVar4 + 0x98))) {
      cVar9 = FUN_8002e04c();
      if (cVar9 != '\0') {
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] | 0x800);
        iVar13 = 0;
        ppbVar8 = ppbVar10;
        do {
          iVar6 = FUN_8002bdf4(0x24,0x4f0);
          *(undefined *)(iVar6 + 4) = 2;
          *(undefined *)(iVar6 + 5) = 1;
          *(short *)(iVar6 + 0x1a) = (short)iVar13;
          pbVar12 = (byte *)FUN_8002df90(iVar6,5,(int)*(char *)(iVar4 + 0xac),0xffffffff,
                                         *(undefined4 *)(iVar4 + 0x30));
          ppbVar8[0x1c0] = pbVar12;
          ppbVar8 = ppbVar8 + 1;
          iVar13 = iVar13 + 1;
        } while (iVar13 < 7);
        FUN_8000bb18(iVar4,0x3db);
        FUN_8000dcbc(iVar4,0x3dc);
      }
      **ppbVar10 = **ppbVar10 - 2;
      *(undefined *)((int)ppbVar10 + 10) = 4;
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      FUN_80148bc8(s_BADDIEALERT_BARK__d__d_8031d89c,**ppbVar10,ppbVar10[0x1ca]);
      cVar9 = FUN_8013b368((double)FLOAT_803e24d4,iVar4,ppbVar10);
      pbVar12 = (byte *)FUN_80138fa8((double)FLOAT_803e24d8,ppbVar10[1],0);
      ppbVar10[9] = pbVar12;
      if (pbVar12 == (byte *)0x0) {
        *(undefined *)(ppbVar10 + 2) = 1;
        bVar11 = false;
        *(undefined *)((int)ppbVar10 + 10) = 0;
        fVar2 = FLOAT_803e23dc;
        ppbVar10[0x1c7] = (byte *)FLOAT_803e23dc;
        ppbVar10[0x1c8] = (byte *)fVar2;
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xffffffef);
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffeffff);
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffdffff);
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffbffff);
        *(undefined *)((int)ppbVar10 + 0xd) = 0xff;
      }
      else {
        if (ppbVar10[10] != ppbVar10[9] + 0x18) {
          ppbVar10[10] = ppbVar10[9] + 0x18;
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffffbff);
          *(undefined2 *)((int)ppbVar10 + 0xd2) = 0;
        }
        bVar11 = true;
      }
      if (bVar11) {
        if (ppbVar10[0x1ca] == (byte *)0x0) {
          pbVar12 = (byte *)FUN_8013ee84(iVar4,ppbVar10);
          ppbVar10[0x1c8] = pbVar12;
          if (pbVar12 != (byte *)0x0) {
            ppbVar10[9] = ppbVar10[0x1c8];
            ppbVar10[0x1c9] = (byte *)0x0;
            *(undefined *)((int)ppbVar10 + 10) = 5;
            goto LAB_8013ee4c;
          }
        }
        if (cVar9 == '\x02') {
          *(undefined *)(ppbVar10 + 2) = 1;
          *(undefined *)((int)ppbVar10 + 10) = 0;
          fVar2 = FLOAT_803e23dc;
          ppbVar10[0x1c7] = (byte *)FLOAT_803e23dc;
          ppbVar10[0x1c8] = (byte *)fVar2;
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xffffffef);
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffeffff);
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffdffff);
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffbffff);
          *(undefined *)((int)ppbVar10 + 0xd) = 0xff;
        }
        else {
          if (cVar9 == '\0') {
            FUN_8013a3f0((double)FLOAT_803e243c,iVar4,0x33,0);
          }
          if (ppbVar10[0x1ca] != (byte *)0x0) {
            if (1 < **ppbVar10) {
              *(undefined *)((int)ppbVar10 + 10) = 2;
              goto LAB_8013ee4c;
            }
            ppbVar10[0x1ca] = (byte *)0x0;
            cVar9 = FUN_8002e04c();
            if (cVar9 != '\0') {
              ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] | 4);
              *(undefined *)(ppbVar10 + 2) = 1;
              *(undefined *)((int)ppbVar10 + 10) = 0;
              fVar2 = FLOAT_803e23dc;
              ppbVar10[0x1c7] = (byte *)FLOAT_803e23dc;
              ppbVar10[0x1c8] = (byte *)fVar2;
              ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xffffffef);
              ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffeffff);
              ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffdffff);
              ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffbffff);
              *(undefined *)((int)ppbVar10 + 0xd) = 0xff;
              if (ppbVar10[0x1ee] == (byte *)0x0) {
                uVar5 = FUN_8002bdf4(0x20,0x17b);
                local_78[0] = -1;
                local_78[1] = -1;
                local_78[2] = -1;
                if (ppbVar10[0x1ea] != (byte *)0x0) {
                  local_78[*(byte *)(ppbVar10 + 0x1ef) >> 6] = '\x01';
                }
                if (ppbVar10[0x1ec] != (byte *)0x0) {
                  local_78[*(byte *)(ppbVar10 + 0x1ef) >> 4 & 3] = '\x01';
                }
                if (ppbVar10[0x1ee] != (byte *)0x0) {
                  local_78[*(byte *)(ppbVar10 + 0x1ef) >> 2 & 3] = '\x01';
                }
                if (local_78[0] == -1) {
                  uVar3 = 0;
                }
                else if (local_78[1] == -1) {
                  uVar3 = 1;
                }
                else if (local_78[2] == -1) {
                  uVar3 = 2;
                }
                else if (local_78[3] == -1) {
                  uVar3 = 3;
                }
                else {
                  uVar3 = 0xffffffff;
                }
                *(byte *)(ppbVar10 + 0x1ef) =
                     (byte)((uVar3 & 0xff) << 2) & 0xc | *(byte *)(ppbVar10 + 0x1ef) & 0xf3;
                pbVar12 = (byte *)FUN_8002df90(uVar5,4,0xffffffff,0xffffffff,
                                               *(undefined4 *)(iVar4 + 0x30));
                ppbVar10[0x1ee] = pbVar12;
                FUN_80037d2c(iVar4,ppbVar10[0x1ee],*(byte *)(ppbVar10 + 0x1ef) >> 2 & 3);
                fVar2 = FLOAT_803e23dc;
                ppbVar10[0x1f0] = (byte *)FLOAT_803e23dc;
                ppbVar10[0x1f1] = (byte *)fVar2;
                ppbVar10[0x1f2] = (byte *)fVar2;
              }
            }
          }
          dVar18 = (double)FUN_8002166c(iVar4 + 0x18,ppbVar10[9] + 0x18);
          if (dVar18 <= (double)FLOAT_803e24e0) {
            ppbVar10[0x1c7] = (byte *)((float)ppbVar10[0x1c7] - FLOAT_803db414);
            if ((float)ppbVar10[0x1c7] < FLOAT_803e23dc) {
              uStack108 = FUN_800221a0(200,600);
              uStack108 = uStack108 ^ 0x80000000;
              local_70 = 0x43300000;
              ppbVar10[0x1c7] =
                   (byte *)((float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e2460) *
                           FLOAT_803e24a8);
              iVar13 = *(int *)(iVar4 + 0xb8);
              if ((((*(byte *)(iVar13 + 0x58) >> 6 & 1) == 0) &&
                  ((0x2f < *(short *)(iVar4 + 0xa0) || (*(short *)(iVar4 + 0xa0) < 0x29)))) &&
                 (iVar6 = FUN_8000b578(iVar4,0x10), iVar6 == 0)) {
                FUN_800393f8(iVar4,iVar13 + 0x3a8,0x29b,0x1000,0xffffffff,0);
              }
            }
          }
          else {
            *(undefined *)((int)ppbVar10 + 10) = 0;
          }
        }
      }
    }
    else if (bVar1 == 0) {
      FUN_80148bc8(s_BADDIEALERT_GOTO_8031d888);
      cVar9 = FUN_8013b368((double)FLOAT_803e24d4,iVar4,ppbVar10);
      pbVar12 = (byte *)FUN_80138fa8((double)FLOAT_803e24d8,ppbVar10[1],0);
      ppbVar10[9] = pbVar12;
      if (pbVar12 == (byte *)0x0) {
        *(undefined *)(ppbVar10 + 2) = 1;
        bVar11 = false;
        *(undefined *)((int)ppbVar10 + 10) = 0;
        fVar2 = FLOAT_803e23dc;
        ppbVar10[0x1c7] = (byte *)FLOAT_803e23dc;
        ppbVar10[0x1c8] = (byte *)fVar2;
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xffffffef);
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffeffff);
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffdffff);
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffbffff);
        *(undefined *)((int)ppbVar10 + 0xd) = 0xff;
      }
      else {
        if (ppbVar10[10] != ppbVar10[9] + 0x18) {
          ppbVar10[10] = ppbVar10[9] + 0x18;
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffffbff);
          *(undefined2 *)((int)ppbVar10 + 0xd2) = 0;
        }
        bVar11 = true;
      }
      if (bVar11) {
        if (ppbVar10[0x1ca] == (byte *)0x0) {
          pbVar12 = (byte *)FUN_8013ee84(iVar4,ppbVar10);
          ppbVar10[0x1c8] = pbVar12;
          if (pbVar12 != (byte *)0x0) {
            ppbVar10[9] = ppbVar10[0x1c8];
            ppbVar10[0x1c9] = (byte *)0x0;
            *(undefined *)((int)ppbVar10 + 10) = 5;
            goto LAB_8013ee4c;
          }
        }
        if (cVar9 == '\x02') {
          *(undefined *)(ppbVar10 + 2) = 1;
          *(undefined *)((int)ppbVar10 + 10) = 0;
          fVar2 = FLOAT_803e23dc;
          ppbVar10[0x1c7] = (byte *)FLOAT_803e23dc;
          ppbVar10[0x1c8] = (byte *)fVar2;
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xffffffef);
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffeffff);
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffdffff);
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffbffff);
          *(undefined *)((int)ppbVar10 + 0xd) = 0xff;
        }
        else {
          dVar18 = (double)FUN_8002166c(iVar4 + 0x18,ppbVar10[9] + 0x18);
          if (dVar18 < (double)FLOAT_803e24dc) {
            bVar11 = true;
            *(undefined *)((int)ppbVar10 + 10) = 1;
            fVar2 = FLOAT_803e23dc;
            ppbVar10[0x1c7] = (byte *)FLOAT_803e23dc;
            if (fVar2 == (float)ppbVar10[0xab]) {
              bVar11 = false;
            }
            else if ((FLOAT_803e2410 != (float)ppbVar10[0xac]) &&
                    ((float)ppbVar10[0xad] - (float)ppbVar10[0xac] <= FLOAT_803e2414)) {
              bVar11 = false;
            }
            if (bVar11) {
              FUN_8013a3f0((double)FLOAT_803e243c,iVar4,8,0);
              ppbVar10[0x1e7] = (byte *)FLOAT_803e2440;
              ppbVar10[0x20e] = (byte *)FLOAT_803e23dc;
              FUN_80148bc8(s_in_water_8031d46c);
            }
            else {
              FUN_8013a3f0((double)FLOAT_803e2444,iVar4,0,0);
              FUN_80148bc8(s_out_of_water_8031d478);
            }
          }
        }
      }
    }
    else {
      FUN_80148bc8(s_BADDIEALLERT_GOTOFLAME_8031d8b4);
      cVar9 = FUN_8013b368((double)FLOAT_803e24e4,iVar4,ppbVar10);
      pbVar12 = (byte *)FUN_80138fa8((double)FLOAT_803e24d8,ppbVar10[1],0);
      ppbVar10[9] = pbVar12;
      if (pbVar12 == (byte *)0x0) {
        *(undefined *)(ppbVar10 + 2) = 1;
        bVar11 = false;
        *(undefined *)((int)ppbVar10 + 10) = 0;
        fVar2 = FLOAT_803e23dc;
        ppbVar10[0x1c7] = (byte *)FLOAT_803e23dc;
        ppbVar10[0x1c8] = (byte *)fVar2;
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xffffffef);
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffeffff);
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffdffff);
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffbffff);
        *(undefined *)((int)ppbVar10 + 0xd) = 0xff;
      }
      else {
        if (ppbVar10[10] != ppbVar10[9] + 0x18) {
          ppbVar10[10] = ppbVar10[9] + 0x18;
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffffbff);
          *(undefined2 *)((int)ppbVar10 + 0xd2) = 0;
        }
        bVar11 = true;
      }
      if ((bVar11) && (cVar9 != '\x01')) {
        FUN_8013a3f0((double)FLOAT_803e2444,iVar4,0x34,0x4000000);
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] | 0x10);
        *(undefined *)((int)ppbVar10 + 10) = 3;
        ppbVar10[0x1ca] = (byte *)0x0;
      }
    }
  }
  else if (bVar1 == 5) {
    pbVar7 = (byte *)FUN_80138fa8((double)FLOAT_803e24d8,ppbVar10[1],0);
    if ((pbVar7 == (byte *)0x0) || (*(short *)(pbVar7 + 0x46) != 0x6a3)) {
      pbVar7 = (byte *)FUN_80296118(ppbVar10[1]);
    }
    if ((pbVar7 == ppbVar10[0x1c8]) && (ppbVar10[0x1ca] == (byte *)0x0)) {
      ppbVar8 = (byte **)FUN_80036f50(0x4b,&local_74);
      dVar19 = (double)FLOAT_803e23f8;
      for (iVar13 = 0; iVar13 < local_74; iVar13 = iVar13 + 1) {
        dVar15 = (double)FUN_80021690(*ppbVar8 + 0x18,pbVar7 + 0x18);
        dVar16 = (double)FUN_80021690(*ppbVar8 + 0x18,ppbVar10[1] + 0x18);
        dVar17 = (double)FUN_80021690(pbVar7 + 0x18,ppbVar10[1] + 0x18);
        if ((float)(dVar19 * dVar17) < (float)(dVar15 + dVar16)) {
          dVar15 = (double)FUN_80021690(*ppbVar8 + 0x18,iVar4 + 0x18);
          if (dVar18 < (double)(float)(dVar16 - dVar15)) {
            pbVar12 = *ppbVar8;
            dVar18 = (double)(float)(dVar16 - dVar15);
          }
        }
        ppbVar8 = ppbVar8 + 1;
      }
      if ((ppbVar10[0x1c9] != (byte *)0x0) && ((*(ushort *)(ppbVar10[0x1c9] + 0xb0) & 0x40) != 0)) {
        ppbVar10[0x1c9] = (byte *)0x0;
        if (ppbVar10[10] != ppbVar10[1] + 0x18) {
          ppbVar10[10] = ppbVar10[1] + 0x18;
          ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffffbff);
          *(undefined2 *)((int)ppbVar10 + 0xd2) = 0;
        }
      }
      if (pbVar12 != (byte *)0x0) {
        if ((((ppbVar10[0x1c9] == (byte *)0x0) &&
             (iVar13 = *(int *)(iVar4 + 0xb8), (*(byte *)(iVar13 + 0x58) >> 6 & 1) == 0)) &&
            ((0x2f < *(short *)(iVar4 + 0xa0) || (*(short *)(iVar4 + 0xa0) < 0x29)))) &&
           (iVar6 = FUN_8000b578(iVar4,0x10), iVar6 == 0)) {
          FUN_800393f8(iVar4,iVar13 + 0x3a8,0x35b,0x500,0xffffffff,0);
        }
        if ((ppbVar10[0x1c9] == (byte *)0x0) || (ppbVar10[0x1c9] != pbVar12)) {
          ppbVar10[0x1c9] = pbVar12;
          if (ppbVar10[10] != ppbVar10[0x1c9] + 0x18) {
            ppbVar10[10] = ppbVar10[0x1c9] + 0x18;
            ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffffbff);
            *(undefined2 *)((int)ppbVar10 + 0xd2) = 0;
          }
        }
      }
    }
    else {
      if (ppbVar10[10] != ppbVar10[9] + 0x18) {
        ppbVar10[10] = ppbVar10[9] + 0x18;
        ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffffbff);
        *(undefined2 *)((int)ppbVar10 + 0xd2) = 0;
      }
      *(undefined *)((int)ppbVar10 + 10) = 0;
    }
    if (ppbVar10[0x1c9] == (byte *)0x0) {
      cVar9 = FUN_8013b368((double)FLOAT_803e2418,iVar4,ppbVar10);
    }
    else {
      cVar9 = FUN_8013b368((double)FLOAT_803e2488,iVar4,ppbVar10);
    }
    if (cVar9 != '\x01') {
      if (FLOAT_803e23dc == (float)ppbVar10[0xab]) {
        bVar11 = false;
      }
      else if (FLOAT_803e2410 == (float)ppbVar10[0xac]) {
        bVar11 = true;
      }
      else if ((float)ppbVar10[0xad] - (float)ppbVar10[0xac] <= FLOAT_803e2414) {
        bVar11 = false;
      }
      else {
        bVar11 = true;
      }
      if (bVar11) {
        FUN_8013a3f0((double)FLOAT_803e243c,iVar4,8,0);
        ppbVar10[0x1e7] = (byte *)FLOAT_803e2440;
        ppbVar10[0x20e] = (byte *)FLOAT_803e23dc;
        FUN_80148bc8(s_in_water_8031d46c);
      }
      else {
        FUN_8013a3f0((double)FLOAT_803e2444,iVar4,0,0);
        FUN_80148bc8(s_out_of_water_8031d478);
      }
    }
  }
  else if (bVar1 < 5) {
    FUN_80148bc8(s_BADDIEALLERT_FLAME_8031d8cc);
    if (((uint)ppbVar10[0x15] & 0x8000000) != 0) {
      ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xfffff7ff);
      ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] | 0x1000);
      iVar13 = 0;
      ppbVar8 = ppbVar10;
      do {
        FUN_8017804c(ppbVar8[0x1c0]);
        ppbVar8 = ppbVar8 + 1;
        iVar13 = iVar13 + 1;
      } while (iVar13 < 7);
      FUN_8000db90(iVar4,0x3dc);
      iVar13 = *(int *)(iVar4 + 0xb8);
      if (((*(byte *)(iVar13 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(iVar4 + 0xa0) || (*(short *)(iVar4 + 0xa0) < 0x29)) &&
          (iVar6 = FUN_8000b578(iVar4,0x10), iVar6 == 0)))) {
        FUN_800393f8(iVar4,iVar13 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      ppbVar10[0x15] = (byte *)((uint)ppbVar10[0x15] & 0xffffffef);
      *(undefined *)((int)ppbVar10 + 10) = 0;
    }
  }
LAB_8013ee4c:
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  __psq_l0(auStack24,uVar14);
  __psq_l1(auStack24,uVar14);
  __psq_l0(auStack40,uVar14);
  __psq_l1(auStack40,uVar14);
  __psq_l0(auStack56,uVar14);
  __psq_l1(auStack56,uVar14);
  FUN_80286120();
  return;
}

