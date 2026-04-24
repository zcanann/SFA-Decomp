// Function: FUN_801f82a4
// Entry: 801f82a4
// Size: 3860 bytes

/* WARNING: Removing unreachable block (ram,0x801f9190) */
/* WARNING: Removing unreachable block (ram,0x801f9198) */

void FUN_801f82a4(void)

{
  float fVar1;
  float fVar2;
  ushort uVar3;
  float fVar4;
  byte bVar5;
  short *psVar6;
  int iVar7;
  int iVar8;
  char cVar10;
  short sVar9;
  float **ppfVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined4 uVar15;
  double dVar16;
  double dVar17;
  undefined8 in_f30;
  double dVar18;
  undefined8 in_f31;
  float local_48;
  float **local_44;
  undefined4 local_40;
  uint uStack60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  psVar6 = (short *)FUN_802860d8();
  iVar14 = *(int *)(psVar6 + 0x5c);
  iVar13 = 0;
  dVar18 = (double)FLOAT_803e5fb4;
  bVar5 = 0;
  local_44 = (float **)0x0;
  local_48 = FLOAT_803e5fbc;
  if ((*(ushort *)(iVar14 + 0x294) & 0x10) == 0) {
    iVar7 = FUN_8002b9ec();
  }
  else {
    iVar7 = FUN_80036e58(10,psVar6,&local_48);
  }
  if (iVar7 != 0) {
    uStack60 = FUN_8001ffb4(0x789);
    local_40 = 0x43300000;
    FLOAT_803dc130 =
         FLOAT_803e5fc0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e6020) +
         FLOAT_803e5fc0;
    if (*(char *)(iVar14 + 0x296) == '\x06') {
      *(byte *)((int)psVar6 + 0xaf) = *(byte *)((int)psVar6 + 0xaf) | 8;
      if (psVar6[0x50] != 1) {
        FUN_80030334((double)FLOAT_803e5fb0,psVar6,1,0);
        FUN_8000bb18(psVar6,0x73);
      }
      if (FLOAT_803e5fc4 < *(float *)(psVar6 + 0x4c)) {
        *(float *)(psVar6 + 4) = *(float *)(psVar6 + 4) * FLOAT_803e5fc8;
      }
      uStack60 = (uint)DAT_803db410;
      local_40 = 0x43300000;
      iVar13 = FUN_8002fa48((double)FLOAT_803e5fcc,
                            (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e6020)
                            ,psVar6,0);
      if (iVar13 != 0) {
        if ((*(short *)(iVar14 + 0x292) != 0) && (*(short *)(iVar14 + 0x292) != -1)) {
          iVar13 = FUN_8001ffb4();
          FUN_800200e8((int)*(short *)(iVar14 + 0x292),iVar13 + 1);
        }
        if (*(int *)(*(int *)(psVar6 + 0x26) + 0x14) == 0) {
          FUN_80035f00(psVar6);
          FUN_8002cbc4(psVar6);
        }
        else {
          FUN_8002ce88(psVar6);
          FUN_80035f00(psVar6);
          FUN_80036fa4(psVar6,3);
          psVar6[3] = psVar6[3] | 0x4000;
        }
      }
    }
    else {
      if ((*(ushort *)(iVar14 + 0x294) & 8) != 0) {
        iVar8 = FUN_800801a8(iVar14 + 0x28a);
        if (iVar8 != 0) {
          iVar13 = 0;
          do {
            (**(code **)(*DAT_803dca88 + 8))(psVar6,0x1a3,0,0,0xffffffff,0);
            iVar13 = iVar13 + 1;
          } while (iVar13 < 0x1e);
          FUN_80080178(iVar14 + 0x28c,100);
          goto LAB_801f9190;
        }
        iVar8 = FUN_800801a8(iVar14 + 0x28c);
        if (iVar8 != 0) {
          *(byte *)((int)psVar6 + 0xaf) = *(byte *)((int)psVar6 + 0xaf) | 8;
          if (*(int *)(*(int *)(psVar6 + 0x26) + 0x14) == 0) {
            FUN_80035f00(psVar6);
            FUN_8002cbc4(psVar6);
          }
          else {
            FUN_8002ce88(psVar6);
            FUN_80035f00(psVar6);
            FUN_80036fa4(psVar6,3);
            psVar6[3] = psVar6[3] | 0x4000;
          }
          goto LAB_801f9190;
        }
      }
      iVar8 = 0;
      do {
        cVar10 = FUN_8001ffb4(iVar8 + 0x2aa);
        bVar5 = bVar5 + cVar10;
        iVar8 = iVar8 + 1;
      } while (iVar8 < 6);
      if (bVar5 < 6) {
        iVar8 = FUN_80080150(iVar14 + 0x288);
        if (iVar8 == 0) {
          cVar10 = *(char *)(iVar14 + 0x296);
          if ((((cVar10 == '\x03') || (cVar10 == '\x01')) || (cVar10 == '\x05')) &&
             ((*(ushort *)(iVar14 + 0x294) & 0x80) == 0)) {
            if (cVar10 == '\x05') {
              if (FLOAT_803e5fd4 + *(float *)(iVar14 + 0x26c) < FLOAT_803e5fd0) {
                *(undefined *)(iVar14 + 0x296) = 3;
                *(undefined2 *)(iVar14 + 0x288) = 0x14;
              }
            }
            else if (FLOAT_803e5fd0 < *(float *)(iVar14 + 0x26c)) {
              *(ushort *)(iVar14 + 0x290) = *(short *)(iVar14 + 0x290) - (ushort)DAT_803db410;
              iVar8 = FUN_80080100(0x32);
              if (iVar8 != 0) {
                FUN_8000bb18(psVar6,0x74);
              }
              if (*(short *)(iVar14 + 0x290) < 1) {
                if ((*(ushort *)(iVar14 + 0x294) & 0x100) == 0) {
                  if (*(int *)(*(int *)(psVar6 + 0x26) + 0x14) == 0) {
                    FUN_80035f00(psVar6);
                    FUN_8002cbc4(psVar6);
                  }
                  else {
                    FUN_8002ce88(psVar6);
                    FUN_80035f00(psVar6);
                    FUN_80036fa4(psVar6,3);
                    psVar6[3] = psVar6[3] | 0x4000;
                  }
                }
                else {
                  *(undefined *)(iVar14 + 0x296) = 6;
                }
                goto LAB_801f9190;
              }
              if (*(char *)(iVar14 + 0x296) != '\x05') {
                FUN_8000b7bc(psVar6,0x10);
                *(undefined *)(iVar14 + 0x296) = 5;
                fVar1 = FLOAT_803e5fd8;
                *(float *)(psVar6 + 0x12) = -*(float *)(psVar6 + 0x12) * FLOAT_803e5fd8;
                *(float *)(psVar6 + 0x16) = -*(float *)(psVar6 + 0x16) * fVar1;
              }
            }
          }
          if ((((*(ushort *)(iVar14 + 0x294) & 0x200) != 0) && (*(char *)(iVar14 + 0x296) != '\x05')
              ) && ((iVar8 = FUN_8002b9ac(), iVar8 != 0 &&
                    ((dVar16 = (double)FUN_80021704(psVar6 + 0xc,iVar8 + 0x18),
                     dVar16 < (double)FLOAT_803e5fd4 &&
                     (cVar10 = (**(code **)(**(int **)(iVar8 + 0x68) + 0x44))(iVar8), cVar10 != '\0'
                     )))))) {
            *(undefined *)(iVar14 + 0x296) = 5;
            FUN_8000bb18(psVar6,0x74);
          }
          if (*(char *)(iVar14 + 0x296) == '\x05') {
            if ((*(ushort *)(iVar14 + 0x294) & 2) != 0) {
              (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,psVar6,iVar14);
              (**(code **)(*DAT_803dcaa8 + 0x14))(psVar6,iVar14);
              (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,psVar6,iVar14);
            }
            if (FLOAT_803e5fb0 !=
                *(float *)(psVar6 + 0x12) * *(float *)(psVar6 + 0x12) +
                *(float *)(psVar6 + 0x16) * *(float *)(psVar6 + 0x16)) {
              dVar18 = (double)FUN_802931a0();
            }
            *(float *)(iVar14 + 0x284) = (float)((double)FLOAT_803e5fdc * dVar18);
            uStack60 = (uint)DAT_803db410;
            local_40 = 0x43300000;
            FUN_8002fa48((double)*(float *)(iVar14 + 0x284),
                         (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e6020),
                         psVar6,0);
            *(float *)(psVar6 + 6) =
                 *(float *)(psVar6 + 0x12) * FLOAT_803db414 + *(float *)(psVar6 + 6);
            *(float *)(psVar6 + 10) =
                 *(float *)(psVar6 + 0x16) * FLOAT_803db414 + *(float *)(psVar6 + 10);
            *(ushort *)(iVar14 + 0x290) = *(short *)(iVar14 + 0x290) - (ushort)DAT_803db410;
            if ((*(ushort *)(iVar14 + 0x294) & 4) == 0) {
              *(undefined4 *)(psVar6 + 8) = *(undefined4 *)(iVar14 + 0x274);
            }
            else {
              local_48 = FLOAT_803e5fbc;
              iVar7 = FUN_80065e50((double)*(float *)(psVar6 + 6),(double)*(float *)(psVar6 + 8),
                                   (double)*(float *)(psVar6 + 10),psVar6,&local_44,0,0);
              iVar8 = 0;
              ppfVar11 = local_44;
              if (0 < iVar7) {
                do {
                  fVar1 = **ppfVar11 - *(float *)(psVar6 + 8);
                  if (fVar1 < FLOAT_803e5fb0) {
                    fVar1 = fVar1 * FLOAT_803e5fe0;
                  }
                  if (fVar1 < local_48) {
                    iVar13 = iVar8;
                    local_48 = fVar1;
                  }
                  ppfVar11 = ppfVar11 + 1;
                  iVar8 = iVar8 + 1;
                  iVar7 = iVar7 + -1;
                } while (iVar7 != 0);
              }
              if (local_44 == (float **)0x0) {
                *(undefined4 *)(psVar6 + 8) = *(undefined4 *)(iVar14 + 0x274);
              }
              else {
                *(float *)(psVar6 + 8) = *local_44[iVar13];
                FUN_801f8008(psVar6,local_44[iVar13]);
              }
            }
            uVar3 = *(ushort *)(iVar14 + 0x294);
            if (((uVar3 & 0x80) == 0) && (*(short *)(iVar14 + 0x290) < 1)) {
              if ((uVar3 & 0x100) == 0) {
                *(undefined *)(iVar14 + 0x296) = 0;
                FUN_8000b7bc(psVar6,0x18);
                *(undefined4 *)(psVar6 + 6) = *(undefined4 *)(iVar14 + 0x270);
                uStack60 = (int)*(short *)(iVar14 + 0x28e) ^ 0x80000000;
                local_40 = 0x43300000;
                *(float *)(psVar6 + 8) =
                     *(float *)(iVar14 + 0x274) +
                     (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e6028);
                *(undefined4 *)(psVar6 + 10) = *(undefined4 *)(iVar14 + 0x278);
              }
              else {
                *(undefined *)(iVar14 + 0x296) = 6;
              }
            }
            else if (((uVar3 & 0x200) != 0) && (iVar13 = FUN_800221a0(0,0x14), iVar13 == 0)) {
              *(undefined *)(iVar14 + 0x296) = 3;
              sVar9 = FUN_800221a0(0,0x14);
              FUN_80080178(iVar14 + 0x288,(int)(short)(sVar9 + 0x32));
            }
          }
          else {
            dVar16 = (double)FUN_80021690(iVar7 + 0x18,psVar6 + 0xc);
            if ((dVar16 < (double)*(float *)(iVar14 + 0x268)) ||
               (iVar8 = FUN_8001ffb4(0x1d9), iVar8 != 0)) {
              cVar10 = *(char *)(iVar14 + 0x296);
              if (cVar10 == '\0') {
                *(undefined *)(iVar14 + 0x296) = 1;
                FUN_80080178(iVar14 + 0x288,2);
                psVar6[2] = 0;
              }
              else if (cVar10 == '\x01') {
                if (FLOAT_803e5fe4 < *(float *)(psVar6 + 0x14)) {
                  *(float *)(psVar6 + 0x14) =
                       FLOAT_803e5fe8 * FLOAT_803db414 + *(float *)(psVar6 + 0x14);
                }
                if (*(float *)(psVar6 + 8) < *(float *)(iVar14 + 0x274)) {
                  *(float *)(psVar6 + 8) = *(float *)(iVar14 + 0x274);
                  *(float *)(psVar6 + 0x14) = FLOAT_803e5fb0;
                  *(undefined *)(iVar14 + 0x296) = 3;
                  sVar9 = FUN_800221a0(0,0x14);
                  FUN_80080178(iVar14 + 0x288,(int)(short)(sVar9 + 0x32));
                  *(float *)(iVar14 + 0x268) = *(float *)(iVar14 + 0x268) * FLOAT_803e5fec;
                  FUN_80030334((double)FLOAT_803e5fb0,psVar6,0,0);
                }
              }
              else if (cVar10 == '\x03') {
                FUN_8000bb18(psVar6,0x47);
                if ((*(ushort *)(iVar14 + 0x294) & 2) != 0) {
                  (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,psVar6,iVar14);
                  (**(code **)(*DAT_803dcaa8 + 0x14))(psVar6,iVar14);
                  (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,psVar6,iVar14);
                }
                if ((*(ushort *)(iVar14 + 0x294) & 4) == 0) {
                  *(undefined4 *)(psVar6 + 8) = *(undefined4 *)(iVar14 + 0x274);
                }
                else {
                  local_48 = FLOAT_803e5fbc;
                  iVar8 = FUN_80065e50((double)*(float *)(psVar6 + 6),(double)*(float *)(psVar6 + 8)
                                       ,(double)*(float *)(psVar6 + 10),psVar6,&local_44,0,0);
                  iVar12 = 0;
                  ppfVar11 = local_44;
                  if (0 < iVar8) {
                    do {
                      fVar1 = **ppfVar11 - *(float *)(psVar6 + 8);
                      if (fVar1 < FLOAT_803e5fb0) {
                        fVar1 = fVar1 * FLOAT_803e5fe0;
                      }
                      if (fVar1 < local_48) {
                        iVar13 = iVar12;
                        local_48 = fVar1;
                      }
                      ppfVar11 = ppfVar11 + 1;
                      iVar12 = iVar12 + 1;
                      iVar8 = iVar8 + -1;
                    } while (iVar8 != 0);
                  }
                  if (local_44 == (float **)0x0) {
                    *(undefined4 *)(psVar6 + 8) = *(undefined4 *)(iVar14 + 0x274);
                  }
                  else {
                    *(float *)(psVar6 + 8) = *local_44[iVar13];
                    FUN_801f8008(psVar6,local_44[iVar13]);
                  }
                }
                fVar4 = FLOAT_803e5ff0;
                fVar1 = *(float *)(iVar7 + 0x10);
                fVar2 = *(float *)(iVar7 + 0x14);
                *(float *)(psVar6 + 0x12) =
                     ((*(float *)(iVar7 + 0xc) - *(float *)(psVar6 + 6)) / FLOAT_803e5ff0) *
                     FLOAT_803db414;
                *(float *)(psVar6 + 0x14) =
                     ((fVar1 - *(float *)(psVar6 + 8)) / fVar4) * FLOAT_803db414;
                *(float *)(psVar6 + 0x16) =
                     ((fVar2 - *(float *)(psVar6 + 10)) / fVar4) * FLOAT_803db414;
                if (((*(ushort *)(iVar14 + 0x294) & 0x20) != 0) &&
                   (dVar17 = (double)FUN_802931a0((double)(*(float *)(psVar6 + 0x16) *
                                                           *(float *)(psVar6 + 0x16) +
                                                          *(float *)(psVar6 + 0x12) *
                                                          *(float *)(psVar6 + 0x12) +
                                                          *(float *)(psVar6 + 0x14) *
                                                          *(float *)(psVar6 + 0x14))),
                   (double)FLOAT_803dc130 < dVar17)) {
                  FUN_8002282c(psVar6 + 0x12);
                  *(float *)(psVar6 + 0x12) =
                       *(float *)(psVar6 + 0x12) * FLOAT_803db414 * FLOAT_803dc130;
                  *(float *)(psVar6 + 0x14) =
                       *(float *)(psVar6 + 0x14) * FLOAT_803db414 * FLOAT_803dc130;
                  *(float *)(psVar6 + 0x16) =
                       *(float *)(psVar6 + 0x16) * FLOAT_803db414 * FLOAT_803dc130;
                }
                if (((psVar6[0x50] == 0) && ((*(ushort *)(iVar14 + 0x294) & 0x400) != 0)) &&
                   (dVar16 < (double)FLOAT_803e5ff4)) {
                  FUN_80030334((double)FLOAT_803e5fb0,psVar6,2,0);
                }
                if ((dVar16 < (double)FLOAT_803e5ff8) ||
                   ((((*(ushort *)(iVar14 + 0x294) & 0x10) != 0 &&
                     ((*(ushort *)(*(int *)(psVar6 + 0x2a) + 0x60) & 8) != 0)) &&
                    (dVar16 < (double)FLOAT_803e5ffc)))) {
                  DAT_803ddcb8 = DAT_803ddcb8 + 1;
                  if (((psVar6[0x50] == 2) && (FLOAT_803e6000 < *(float *)(psVar6 + 0x4c))) &&
                     (*(float *)(psVar6 + 0x4c) < FLOAT_803e6004)) {
                    FUN_800378c4(iVar7,0x60004,psVar6,1);
                    DAT_803ddcb8 = 0;
                  }
                  iVar13 = FUN_8001ffb4(0x1d9);
                  if (iVar13 == 0) {
                    if ((2 < DAT_803ddcb8) ||
                       (((*(ushort *)(iVar14 + 0x294) & 0x10) != 0 && (2 < DAT_803ddcb8)))) {
                      FUN_8000bb18(psVar6,0x75);
                      if ((*(ushort *)(iVar14 + 0x294) & 0x10) == 0) {
                        FUN_800378c4(iVar7,0x60004,psVar6,1);
                      }
                      else {
                        *(byte *)(iVar14 + 0x299) = *(byte *)(iVar14 + 0x299) & 0x7f | 0x80;
                      }
                      DAT_803ddcb8 = 0;
                    }
                  }
                  else {
                    DAT_803ddcb8 = 0;
                  }
                  fVar2 = FLOAT_803e600c;
                  fVar1 = FLOAT_803e6008;
                  if ((*(ushort *)(iVar14 + 0x294) & 0x10) == 0) {
                    *(float *)(psVar6 + 6) =
                         FLOAT_803e6008 * -*(float *)(psVar6 + 0x12) + *(float *)(psVar6 + 6);
                    *(float *)(psVar6 + 10) =
                         fVar1 * -*(float *)(psVar6 + 0x16) + *(float *)(psVar6 + 10);
                  }
                  else {
                    *(float *)(psVar6 + 6) =
                         FLOAT_803e600c * -*(float *)(psVar6 + 0x12) + *(float *)(psVar6 + 6);
                    *(float *)(psVar6 + 10) =
                         fVar2 * -*(float *)(psVar6 + 0x16) + *(float *)(psVar6 + 10);
                  }
                  sVar9 = FUN_800221a0(0,0x14);
                  FUN_80080178(iVar14 + 0x288,(int)(short)(sVar9 + 100));
                }
                sVar9 = FUN_800217c0((double)(*(float *)(iVar7 + 0xc) - *(float *)(psVar6 + 6)),
                                     (double)(*(float *)(iVar7 + 0x14) - *(float *)(psVar6 + 10)));
                *psVar6 = sVar9 + 0x7fff;
                if (FLOAT_803e5fb0 !=
                    *(float *)(psVar6 + 0x12) * *(float *)(psVar6 + 0x12) +
                    *(float *)(psVar6 + 0x16) * *(float *)(psVar6 + 0x16)) {
                  dVar18 = (double)FUN_802931a0();
                }
                sVar9 = psVar6[0x50];
                if (sVar9 == 1) {
                  *(float *)(iVar14 + 0x284) = FLOAT_803e5fcc;
                }
                else if (sVar9 < 1) {
                  if (-1 < sVar9) {
                    *(float *)(iVar14 + 0x284) = (float)((double)FLOAT_803e6010 * dVar18);
                  }
                }
                else if (sVar9 < 3) {
                  *(float *)(iVar14 + 0x284) = FLOAT_803e6014;
                }
                uStack60 = (uint)DAT_803db410;
                local_40 = 0x43300000;
                iVar13 = FUN_8002fa48((double)*(float *)(iVar14 + 0x284),
                                      (double)(float)((double)CONCAT44(0x43300000,uStack60) -
                                                     DOUBLE_803e6020),psVar6,0);
                if ((iVar13 != 0) && (psVar6[0x50] != 0)) {
                  FUN_80030334((double)FLOAT_803e5fb0,psVar6,0,0);
                }
                *(float *)(psVar6 + 6) =
                     *(float *)(psVar6 + 0x12) * FLOAT_803db414 + *(float *)(psVar6 + 6);
                *(float *)(psVar6 + 10) =
                     *(float *)(psVar6 + 0x16) * FLOAT_803db414 + *(float *)(psVar6 + 10);
              }
            }
            else if (*(char *)(iVar14 + 0x296) == '\x01') {
              if (FLOAT_803e5fe0 < *(float *)(psVar6 + 0x14)) {
                *(float *)(psVar6 + 0x14) =
                     FLOAT_803e6018 * FLOAT_803db414 + *(float *)(psVar6 + 0x14);
              }
              if (*(float *)(psVar6 + 8) < *(float *)(iVar14 + 0x274)) {
                *(float *)(psVar6 + 8) = *(float *)(iVar14 + 0x274);
                *(float *)(psVar6 + 0x14) = FLOAT_803e5fb0;
                *(undefined *)(iVar14 + 0x296) = 3;
                sVar9 = FUN_800221a0(0,0x14);
                FUN_80080178(iVar14 + 0x288,(int)(short)(sVar9 + 0x32));
                *(float *)(iVar14 + 0x268) = *(float *)(iVar14 + 0x268) * FLOAT_803e5fec;
                FUN_80030334((double)FLOAT_803e5fb0,psVar6,0,0);
              }
              *(float *)(psVar6 + 8) =
                   *(float *)(psVar6 + 0x14) * FLOAT_803db414 + *(float *)(psVar6 + 8);
            }
            if (*(char *)(iVar14 + 0x296) == '\0') {
              *(float *)(psVar6 + 8) =
                   *(float *)(psVar6 + 0x14) * FLOAT_803db414 + *(float *)(psVar6 + 8);
            }
            iVar13 = FUN_80080100(0x32);
            if (iVar13 != 0) {
              FUN_8000bb18(psVar6,0x76);
            }
          }
        }
        else {
          FUN_800801a8(iVar14 + 0x288);
        }
      }
      else if (*(int *)(*(int *)(psVar6 + 0x26) + 0x14) == 0) {
        FUN_80035f00(psVar6);
        FUN_8002cbc4(psVar6);
      }
      else {
        FUN_8002ce88(psVar6);
        FUN_80035f00(psVar6);
        FUN_80036fa4(psVar6,3);
        psVar6[3] = psVar6[3] | 0x4000;
      }
    }
  }
LAB_801f9190:
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  FUN_80286124();
  return;
}

