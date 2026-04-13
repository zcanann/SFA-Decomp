// Function: FUN_8013b6f0
// Entry: 8013b6f0
// Size: 8744 bytes

/* WARNING: Removing unreachable block (ram,0x8013d90c) */
/* WARNING: Removing unreachable block (ram,0x8013d904) */
/* WARNING: Removing unreachable block (ram,0x8013b708) */
/* WARNING: Removing unreachable block (ram,0x8013b700) */
/* WARNING: Removing unreachable block (ram,0x8013ce3c) */
/* WARNING: Removing unreachable block (ram,0x8013ce54) */

void FUN_8013b6f0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)

{
  ushort *puVar1;
  int iVar2;
  float *pfVar3;
  float *pfVar4;
  ushort uVar6;
  ushort uVar7;
  short sVar8;
  char cVar9;
  int iVar5;
  float *pfVar10;
  undefined *puVar11;
  uint uVar12;
  uint uVar13;
  byte bVar14;
  float *pfVar15;
  uint uVar16;
  float fVar17;
  float *pfVar18;
  uint uVar19;
  float fVar20;
  float *pfVar21;
  uint unaff_r23;
  float fVar22;
  float *pfVar23;
  float *pfVar24;
  double extraout_f1;
  double dVar25;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 extraout_f1_03;
  undefined8 extraout_f1_04;
  double dVar26;
  double in_f30;
  double in_f31;
  double dVar27;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar28;
  byte local_a8;
  byte local_a7;
  ushort local_a4 [4];
  undefined auStack_9c [8];
  undefined uStack_94;
  byte local_93;
  ushort local_92 [5];
  float local_88;
  float local_84;
  float local_80;
  float afStack_7c [9];
  longlong local_58;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar28 = FUN_80286828();
  puVar1 = (ushort *)((ulonglong)uVar28 >> 0x20);
  pfVar10 = (float *)uVar28;
  dVar26 = extraout_f1;
  if ((*(byte *)((int)pfVar10 + 9) < 5) &&
     (iVar2 = FUN_800dbe30((float *)(puVar1 + 0xc)), iVar2 == 0)) {
    param_11 = *DAT_803dd728;
    (**(code **)(param_11 + 0x20))(puVar1,pfVar10 + 0x3e);
    *(float *)(puVar1 + 6) = pfVar10[0x38];
    *(float *)(puVar1 + 8) = pfVar10[0x39];
    *(float *)(puVar1 + 10) = pfVar10[0x3a];
    *(float *)(puVar1 + 0xc) = pfVar10[0x38];
    *(float *)(puVar1 + 0xe) = pfVar10[0x39];
    *(float *)(puVar1 + 0x10) = pfVar10[0x3a];
    FUN_80036084((int)puVar1);
  }
  pfVar23 = (float *)pfVar10[10];
  pfVar3 = (float *)FUN_800dbf88((float *)(puVar1 + 0xc),(undefined *)0x0);
  if ((pfVar3 != (float *)0x0) && ((float *)(uint)*(ushort *)(pfVar10 + 0x34) != pfVar3)) {
    *(ushort *)(pfVar10 + 0x34) = (ushort)pfVar3;
    pfVar10[0x15] = (float)((uint)pfVar10[0x15] & 0xfffffbff);
    *(undefined2 *)(pfVar10 + 0x26) = 0;
    *(undefined2 *)((int)pfVar10 + 0x9a) = 0;
    *(undefined2 *)(pfVar10 + 0x27) = 0;
    *(undefined2 *)((int)pfVar10 + 0x9e) = 0;
  }
  pfVar4 = (float *)FUN_800dbf88(pfVar23,&uStack_94);
  if ((pfVar3 != (float *)0x0) && (pfVar4 == (float *)0x0)) {
    uVar6 = FUN_800dbcd8(pfVar23,(int)pfVar3,param_11,param_12,param_13);
    if (uVar6 != 0) {
      FUN_800db4b0((uint)uVar6,&local_a8);
      pfVar4 = (float *)(uint)local_a8;
      if (pfVar4 == pfVar3) {
        pfVar4 = (float *)(uint)local_a7;
      }
    }
  }
  if ((pfVar4 != (float *)0x0) && (pfVar4 != (float *)(uint)*(ushort *)((int)pfVar10 + 0x532))) {
    *(short *)((int)pfVar10 + 0x532) = (short)pfVar4;
  }
  *(undefined2 *)(pfVar10 + 0x14d) = *(undefined2 *)((int)pfVar10 + 0x532);
  uVar19 = (uint)*(ushort *)((int)pfVar10 + 0x532);
  FUN_80148ff0();
  if (*(short *)(pfVar10 + 0x34) == 0) {
    param_3 = (double)*(float *)(puVar1 + 0x10);
    FUN_80148fa0();
  }
  dVar27 = (double)pfVar10[5];
  pfVar18 = (float *)0x0;
  pfVar15 = pfVar23;
  FUN_8013d92c(dVar26,(short *)puVar1,(int)pfVar10,pfVar23,'\0');
  dVar26 = (double)pfVar10[5];
  FUN_80148ff0();
  if (pfVar4 == (float *)(uint)*(ushort *)(pfVar10 + 0x34)) {
    pfVar10[0x15] = (float)((uint)pfVar10[0x15] | 0x400);
    uVar19 = 0;
    param_14 = 1;
    puVar11 = &uStack_94;
    iVar2 = 2;
    pfVar15 = pfVar10;
    pfVar18 = pfVar10;
    do {
      if ((param_14 & local_93) != 0) {
        *(undefined2 *)(pfVar15 + 0x26) = *(undefined2 *)(puVar11 + 2);
        pfVar18[0x28] = *pfVar23;
        pfVar18[0x29] = pfVar23[1];
        pfVar18[0x2a] = pfVar23[2];
      }
      if ((param_14 << 1 & (uint)local_93) != 0) {
        *(undefined2 *)((int)pfVar15 + 0x9a) = *(undefined2 *)(puVar11 + 4);
        pfVar18[0x2b] = *pfVar23;
        pfVar18[0x2c] = pfVar23[1];
        pfVar18[0x2d] = pfVar23[2];
      }
      puVar11 = puVar11 + 4;
      pfVar15 = pfVar15 + 1;
      pfVar18 = pfVar18 + 6;
      uVar19 = uVar19 + 1;
      param_14 = (param_14 & 0x3f) << 2;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  if ((pfVar4 == (float *)0x0) || (pfVar4 != (float *)(uint)*(ushort *)(pfVar10 + 0x34))) {
    pfVar18 = (float *)((int)pfVar4 * (uint)*(ushort *)(pfVar10 + 0x34) & 0xffff);
    if (pfVar18 != (float *)0x0) {
      sVar8 = (short)((int)pfVar4 * (uint)*(ushort *)(pfVar10 + 0x34));
      pfVar15 = (float *)(int)sVar8;
      if ((pfVar18 == (float *)(uint)local_92[0]) && ((local_93 & 1) != 0)) {
        *(short *)((int)pfVar10 + 0xd2) = sVar8;
        pfVar10[0x35] = *pfVar23;
        pfVar10[0x36] = pfVar23[1];
        pfVar10[0x37] = pfVar23[2];
      }
      if ((pfVar18 == (float *)(uint)local_92[1]) && ((local_93 & 2) != 0)) {
        *(short *)((int)pfVar10 + 0xd2) = sVar8;
        pfVar10[0x35] = *pfVar23;
        pfVar10[0x36] = pfVar23[1];
        pfVar10[0x37] = pfVar23[2];
      }
      if ((pfVar18 == (float *)(uint)local_92[2]) && ((local_93 & 4) != 0)) {
        *(short *)((int)pfVar10 + 0xd2) = sVar8;
        pfVar10[0x35] = *pfVar23;
        pfVar10[0x36] = pfVar23[1];
        pfVar10[0x37] = pfVar23[2];
      }
      if ((pfVar18 == (float *)(uint)local_92[3]) && ((local_93 & 8) != 0)) {
        *(short *)((int)pfVar10 + 0xd2) = sVar8;
        pfVar10[0x35] = *pfVar23;
        pfVar10[0x36] = pfVar23[1];
        pfVar10[0x37] = pfVar23[2];
      }
    }
  }
  else {
    *(undefined2 *)((int)pfVar10 + 0xd2) = 0;
  }
  iVar2 = FUN_800dbe30(pfVar23);
  if (iVar2 == 0) {
    FUN_80148ff0();
  }
  else {
    FUN_80148ff0();
  }
  FUN_800dbcd8(pfVar23,(uint)*(ushort *)(pfVar10 + 0x34),pfVar15,pfVar18,(byte)uVar19);
  FUN_80148ff0();
  if (((uint)pfVar10[0x15] & 0x400) != 0) {
    iVar2 = 0;
    pfVar21 = pfVar10;
    pfVar24 = pfVar10;
    do {
      if (*(short *)(pfVar24 + 0x26) != 0) {
        dVar26 = (double)pfVar21[0x29];
        param_3 = (double)pfVar21[0x2a];
        FUN_80148ff0();
      }
      pfVar24 = (float *)((int)pfVar24 + 2);
      pfVar21 = pfVar21 + 3;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 4);
  }
  if (*(short *)((int)pfVar10 + 0xd2) != 0) {
    dVar26 = (double)pfVar10[0x36];
    param_3 = (double)pfVar10[0x37];
    FUN_80148ff0();
  }
  uVar6 = FUN_800dbcd8(pfVar23,(uint)*(ushort *)(pfVar10 + 0x34),pfVar15,pfVar18,(byte)uVar19);
  uVar13 = (uint)uVar6;
  uVar7 = FUN_800dbcd8((float *)(puVar1 + 0xc),(uint)*(ushort *)(pfVar10 + 0x34),pfVar15,pfVar18,
                       (byte)uVar19);
  uVar12 = (uint)uVar7;
  if ((pfVar4 == (float *)0x0) || (pfVar3 != pfVar4)) {
    uVar16 = (uint)*(ushort *)(pfVar10 + 0x34);
    sVar8 = FUN_800db670(puVar1 + 0xc,pfVar23,uVar16);
    if (sVar8 == 0) {
      if (*(byte *)((int)pfVar10 + 9) < 5) {
        if (uVar6 == 0) {
          if (pfVar4 == (float *)0x0) {
            if (pfVar3 == (float *)0x0) {
              *(undefined *)((int)pfVar10 + 9) = 0;
            }
            else {
              uVar6 = FUN_800dc158(pfVar23);
              if (uVar6 == 0) {
                *(undefined *)((int)pfVar10 + 9) = 0;
              }
              else {
                *(ushort *)((int)pfVar10 + 0x532) = uVar6 & 0xff;
                *(undefined *)((int)pfVar10 + 9) = 5;
              }
            }
          }
          else if (pfVar3 == (float *)0x0) {
            uVar6 = FUN_800dbcd8((float *)(puVar1 + 0xc),(uint)*(ushort *)(pfVar10 + 0x34),uVar16,
                                 pfVar18,(byte)uVar19);
            uVar13 = (uint)uVar6;
            if (uVar6 == 0) {
              FUN_80148fa0();
              *(undefined *)((int)pfVar10 + 9) = 0;
            }
            else if (pfVar4 == (float *)(uint)*(ushort *)(pfVar10 + 0x34)) {
              uVar12 = 0;
              iVar2 = 4;
              pfVar4 = pfVar10;
              do {
                if ((int)*(short *)(pfVar4 + 0x26) == uVar13) {
                  unaff_r23 = uVar12 & 0xff;
                  *(undefined *)((int)pfVar10 + 9) = 2;
                  break;
                }
                pfVar4 = (float *)((int)pfVar4 + 2);
                uVar12 = uVar12 + 1;
                iVar2 = iVar2 + -1;
              } while (iVar2 != 0);
              if (uVar12 == 4) {
                FUN_800db4cc(pfVar23,pfVar10 + 0x3b,uVar13);
                *(undefined *)((int)pfVar10 + 9) = 4;
              }
            }
            else if ((int)*(short *)((int)pfVar10 + 0xd2) == uVar13) {
              *(undefined *)((int)pfVar10 + 9) = 3;
            }
            else {
              FUN_800db4cc(pfVar23,pfVar10 + 0x3b,uVar13);
              *(undefined *)((int)pfVar10 + 9) = 4;
            }
          }
          else {
            uVar13 = (int)pfVar4 * (int)pfVar3 & 0xffff;
            uVar12 = FUN_800dbb64((float *)(puVar1 + 0xc),(uint)*(ushort *)(pfVar10 + 0x34),uVar13);
            if (uVar12 == 0) {
              uVar12 = 0;
              iVar2 = 4;
              pfVar23 = pfVar10;
              do {
                if ((int)*(short *)(pfVar23 + 0x26) == uVar13) {
                  unaff_r23 = uVar12 & 0xff;
                  *(undefined *)((int)pfVar10 + 9) = 2;
                  break;
                }
                pfVar23 = (float *)((int)pfVar23 + 2);
                uVar12 = uVar12 + 1;
                iVar2 = iVar2 + -1;
              } while (iVar2 != 0);
              if ((uVar12 == 4) || (uVar13 != (int)*(short *)((int)pfVar10 + 0xd2))) {
                *(undefined *)((int)pfVar10 + 9) = 5;
              }
            }
            else if ((int)*(short *)((int)pfVar10 + 0xd2) == uVar13) {
              *(undefined *)((int)pfVar10 + 9) = 3;
            }
            else {
              *(undefined *)((int)pfVar10 + 9) = 5;
            }
          }
        }
        else if (pfVar4 == (float *)0x0) {
          if (pfVar3 == (float *)0x0) {
            if (uVar7 == 0) {
              FUN_80148fa0();
              *(undefined *)((int)pfVar10 + 9) = 0;
            }
            else {
              uVar13 = 0;
              iVar2 = 4;
              pfVar4 = pfVar10;
              do {
                if ((int)*(short *)(pfVar4 + 0x26) == uVar12) {
                  uVar12 = uVar13 & 0xffff;
                  *(undefined *)((int)pfVar10 + 9) = 2;
                  break;
                }
                pfVar4 = (float *)((int)pfVar4 + 2);
                uVar13 = uVar13 + 1;
                iVar2 = iVar2 + -1;
              } while (iVar2 != 0);
              if (uVar13 == 4) {
                FUN_800db4cc(pfVar23,pfVar10 + 0x3b,uVar12);
                *(undefined *)((int)pfVar10 + 9) = 4;
              }
            }
          }
          else {
            uVar12 = 0;
            iVar2 = 4;
            pfVar23 = pfVar10;
            do {
              if ((int)*(short *)(pfVar23 + 0x26) == uVar13) {
                unaff_r23 = uVar12 & 0xff;
                *(undefined *)((int)pfVar10 + 9) = 2;
                break;
              }
              pfVar23 = (float *)((int)pfVar23 + 2);
              uVar12 = uVar12 + 1;
              iVar2 = iVar2 + -1;
            } while (iVar2 != 0);
            if (uVar12 == 4) {
              uVar12 = countLeadingZeros(0xff - (uint)*(ushort *)(pfVar10 + 0x14c));
              if ((uVar13 & uVar12 >> 5) == 0) {
                *(ushort *)((int)pfVar10 + 0x532) = uVar6 & 0xff;
              }
              else {
                *(ushort *)((int)pfVar10 + 0x532) = uVar6 >> 8;
              }
              *(undefined *)((int)pfVar10 + 9) = 5;
            }
          }
        }
        else if (pfVar3 == (float *)0x0) {
          if (pfVar3 == (float *)0x0) {
            uVar6 = FUN_800dbcd8((float *)(puVar1 + 0xc),(uint)*(ushort *)(pfVar10 + 0x34),uVar16,
                                 pfVar18,(byte)uVar19);
            uVar13 = (uint)uVar6;
            if (uVar6 != 0) {
              if ((int)*(short *)((int)pfVar10 + 0xd2) == uVar13) {
                *(undefined *)((int)pfVar10 + 9) = 3;
              }
              else {
                FUN_800db4cc(pfVar23,pfVar10 + 0x3b,uVar13);
                *(undefined *)((int)pfVar10 + 9) = 4;
              }
              goto LAB_8013bff8;
            }
          }
          param_14 = FUN_800dbb64((float *)(puVar1 + 0xc),(uint)*(ushort *)(pfVar10 + 0x34),uVar13);
          uVar19 = (uint)*(ushort *)(pfVar10 + 0x34);
          pfVar18 = pfVar3;
          FUN_80148fa0();
          *(undefined *)((int)pfVar10 + 9) = 0;
        }
        else {
          uVar12 = 0;
          iVar2 = 4;
          pfVar23 = pfVar10;
          do {
            if ((int)*(short *)(pfVar23 + 0x26) == uVar13) {
              unaff_r23 = uVar12 & 0xff;
              *(undefined *)((int)pfVar10 + 9) = 2;
              break;
            }
            pfVar23 = (float *)((int)pfVar23 + 2);
            uVar12 = uVar12 + 1;
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
          if (uVar12 == 4) {
            *(undefined *)((int)pfVar10 + 9) = 5;
          }
        }
      }
    }
    else {
      *(undefined *)((int)pfVar10 + 9) = 1;
      if (sVar8 != *(short *)(pfVar10 + 0x34)) {
        *(short *)(pfVar10 + 0x34) = sVar8;
        pfVar10[0x15] = (float)((uint)pfVar10[0x15] & 0xfffffbff);
        *(undefined2 *)(pfVar10 + 0x26) = 0;
        *(undefined2 *)((int)pfVar10 + 0x9a) = 0;
        *(undefined2 *)(pfVar10 + 0x27) = 0;
        *(undefined2 *)((int)pfVar10 + 0x9e) = 0;
      }
    }
  }
  else {
    *(undefined *)((int)pfVar10 + 9) = 1;
  }
LAB_8013bff8:
  if (*(byte *)((int)pfVar10 + 9) < 5) {
    pfVar10[0x15] = (float)((uint)pfVar10[0x15] & 0xffffdfff);
  }
  FUN_80148ff0();
  switch(*(undefined *)((int)pfVar10 + 9)) {
  case 0:
    FUN_80148ff0();
    fVar17 = (float)((double)FLOAT_803e30ac * (double)FLOAT_803dc074 + dVar27);
    if (fVar17 < FLOAT_803e306c) {
      fVar17 = FLOAT_803e306c;
    }
    pfVar10[5] = fVar17;
    if (FLOAT_803e306c != pfVar10[5]) {
      FUN_80139e14();
    }
    break;
  case 1:
    FUN_80148ff0();
    FUN_80139e14();
    break;
  case 2:
    FUN_80148ff0();
    pfVar10[5] = (float)dVar27;
    FUN_8013d92c((double)FLOAT_803e306c,(short *)puVar1,(int)pfVar10,
                 pfVar10 + (unaff_r23 & 0xff) * 3 + 0x28,'\x01');
    FUN_80139e14();
    break;
  case 3:
    FUN_80148ff0();
    pfVar10[5] = (float)dVar27;
    FUN_8013d92c((double)FLOAT_803e3118,(short *)puVar1,(int)pfVar10,pfVar10 + 0x35,'\x01');
    FUN_80139e14();
    break;
  case 4:
    FUN_80148ff0();
    pfVar10[5] = (float)dVar27;
    FUN_8013d92c((double)FLOAT_803e3118,(short *)puVar1,(int)pfVar10,pfVar10 + 0x3b,'\x01');
    FUN_80139e14();
    break;
  case 5:
    FUN_80148ff0();
    FUN_8013aed4(puVar1,auStack_9c,(ushort)pfVar3,afStack_7c);
    iVar2 = FUN_8013ab7c(pfVar10,afStack_7c,(int)auStack_9c,(uint)*(ushort *)((int)pfVar10 + 0x532))
    ;
    if (iVar2 == -1) {
      pfVar10[5] = (float)dVar27;
      goto LAB_8013d904;
    }
    *(undefined *)(pfVar10 + 0x107) = auStack_9c[iVar2];
    pfVar10[0x106] = afStack_7c[iVar2];
    pfVar10[5] = (float)dVar27;
    FUN_8013d92c((double)FLOAT_803e3118,(short *)puVar1,(int)pfVar10,
                 (float *)((int)pfVar10[0x106] + 8),'\x01');
    FUN_80139e14();
    *(undefined *)((int)pfVar10 + 9) = 6;
    break;
  case 6:
    dVar25 = FUN_80021730((float *)((int)pfVar10[0x106] + 8),(float *)(puVar1 + 0xc));
    local_58 = (longlong)(int)dVar25;
    FUN_80148ff0();
    dVar25 = FUN_80021730((float *)((int)pfVar10[0x106] + 8),(float *)(puVar1 + 0xc));
    if ((double)FLOAT_803e3070 <= dVar25) {
      fVar17 = pfVar10[0x106];
      if (fVar17 == 0.0) {
        fVar17 = 0.0;
      }
      else if ((((int)*(short *)((int)fVar17 + 0x30) != 0xffffffff) &&
               (uVar19 = FUN_80020078((int)*(short *)((int)fVar17 + 0x30)), uVar19 == 0)) ||
              (((int)*(short *)((int)fVar17 + 0x32) != 0xffffffff &&
               (uVar19 = FUN_80020078((int)*(short *)((int)fVar17 + 0x32)), uVar19 != 0)))) {
        fVar17 = 0.0;
      }
      if ((fVar17 == 0.0) && (pfVar3 != (float *)0x0)) {
        *(undefined *)((int)pfVar10 + 9) = 0;
      }
      else {
        pfVar10[5] = (float)dVar27;
        FUN_8013d92c((double)FLOAT_803e30fc,(short *)puVar1,(int)pfVar10,
                     (float *)((int)pfVar10[0x106] + 8),'\x01');
        FUN_80139e14();
      }
    }
    else {
      pfVar10[0x128] = (float)(uint)*(byte *)(pfVar10 + 0x107);
      fVar22 = pfVar10[0x106];
      fVar17 = (float)FUN_8013ad50((int)pfVar10,(int)fVar22,*(byte *)(pfVar10 + 0x107));
      if (fVar17 == 0.0) {
        *(undefined *)((int)pfVar10 + 9) = 0;
      }
      else {
        fVar20 = (float)FUN_8013ad50((int)pfVar10,(int)fVar17,*(byte *)(pfVar10 + 0x107));
        if (fVar20 == 0.0) {
          *(undefined *)((int)pfVar10 + 9) = 0;
        }
        else {
          FUN_800dac0c(extraout_f1_00,dVar26,param_3,param_4,param_5,param_6,param_7,param_8,
                       pfVar10 + 0x108,fVar22,fVar17,fVar20,uVar19,param_14,param_15,param_16);
          FUN_800dabb4((double)FLOAT_803e3114,pfVar10 + 0x108);
          iVar2 = FUN_80021884();
          iVar5 = FUN_80021884();
          sVar8 = (short)iVar2 - (short)iVar5;
          if (0x8000 < sVar8) {
            sVar8 = sVar8 + 1;
          }
          if (sVar8 < -0x8000) {
            sVar8 = sVar8 + -1;
          }
          if (sVar8 < 0x4001) {
            if (sVar8 < -0x4000) {
              sVar8 = sVar8 + -0x8000;
            }
          }
          else {
            sVar8 = sVar8 + -0x8000;
          }
          iVar2 = (int)sVar8;
          if (iVar2 < 0) {
            iVar2 = -iVar2;
          }
          if (0x1000 < iVar2) {
            pfVar10[5] = (float)dVar27;
            FUN_8013d92c((double)FLOAT_803e30fc,(short *)puVar1,(int)pfVar10,pfVar10 + 0x122,'\x01')
            ;
          }
          FUN_80139bbc((double)pfVar10[5],(int)puVar1,pfVar10 + 0x108);
          FUN_80139e14();
          cVar9 = *(char *)((int)fVar22 + 0x1a);
          if (cVar9 == '\x05') {
            pfVar10[0xb] = *(float *)((int)pfVar10[0x130] + 8) - *(float *)(puVar1 + 0xc);
            pfVar10[0xc] = *(float *)((int)pfVar10[0x130] + 0x10) - *(float *)(puVar1 + 0x10);
            dVar26 = FUN_80293900((double)(pfVar10[0xb] * pfVar10[0xb] + pfVar10[0xc] * pfVar10[0xc]
                                          ));
            if ((double)FLOAT_803e306c != dVar26) {
              pfVar10[0xb] = (float)((double)pfVar10[0xb] / dVar26);
              pfVar10[0xc] = (float)((double)pfVar10[0xc] / dVar26);
            }
            uVar19 = FUN_80022264(0,1);
            if (uVar19 == 0) {
              FUN_8013a778((double)FLOAT_803e3124,(int)puVar1,0x18,0x40000c0);
            }
            else {
              FUN_8013a778((double)FLOAT_803e3120,(int)puVar1,0x17,0x40000c0);
            }
            pfVar10[0x12] =
                 (*(float *)((int)pfVar10[0x130] + 0xc) - *(float *)(puVar1 + 0xe)) / FLOAT_803e3128
            ;
            *(undefined *)((int)pfVar10 + 9) = 0xc;
            if (pfVar10[0x128] == 0.0) {
              while (pfVar10[0x10c] == 0.0) {
                FUN_800dabb4((double)FLOAT_803e3088,pfVar10 + 0x108);
              }
            }
            else {
              while (pfVar10[0x10c] != 0.0) {
                FUN_800dabb4((double)FLOAT_803e30d8,pfVar10 + 0x108);
              }
            }
            pfVar10[0x1e8] = FLOAT_803e30d0;
          }
          else if (cVar9 < '\x05') {
            if (cVar9 == '\x02') {
LAB_8013c620:
              pfVar10[0x15] = (float)((uint)pfVar10[0x15] | 0x2000);
            }
            else if ((cVar9 < '\x02') && ('\0' < cVar9)) {
              pfVar10[0xb] = *(float *)((int)pfVar10[0x130] + 8) - *(float *)(puVar1 + 0xc);
              pfVar10[0xc] = *(float *)((int)pfVar10[0x130] + 0x10) - *(float *)(puVar1 + 0x10);
              dVar26 = FUN_80293900((double)(pfVar10[0xb] * pfVar10[0xb] +
                                            pfVar10[0xc] * pfVar10[0xc]));
              if ((double)FLOAT_803e306c != dVar26) {
                pfVar10[0xb] = (float)((double)pfVar10[0xb] / dVar26);
                pfVar10[0xc] = (float)((double)pfVar10[0xc] / dVar26);
              }
              pfVar10[5] = FLOAT_803e311c;
              FUN_8013a778((double)FLOAT_803e30f8,(int)puVar1,0x15,0x4000000);
              *(undefined *)((int)pfVar10 + 9) = 9;
              pfVar10[0x1e8] = FLOAT_803e30d0;
              break;
            }
LAB_8013c62c:
            *(undefined *)((int)pfVar10 + 9) = 7;
          }
          else {
            if (cVar9 == '\a') goto LAB_8013c620;
            if ('\x06' < cVar9) goto LAB_8013c62c;
            pfVar10[0xb] = *(float *)((int)pfVar10[0x130] + 8) - *(float *)(puVar1 + 0xc);
            pfVar10[0xc] = *(float *)((int)pfVar10[0x130] + 0x10) - *(float *)(puVar1 + 0x10);
            dVar26 = FUN_80293900((double)(pfVar10[0xb] * pfVar10[0xb] + pfVar10[0xc] * pfVar10[0xc]
                                          ));
            if ((double)FLOAT_803e306c != dVar26) {
              pfVar10[0xb] = (float)((double)pfVar10[0xb] / dVar26);
              pfVar10[0xc] = (float)((double)pfVar10[0xc] / dVar26);
            }
            FUN_8013a778((double)FLOAT_803e312c,(int)puVar1,0x19,0x40000c0);
            pfVar10[0x12] =
                 (*(float *)(puVar1 + 0xe) - *(float *)((int)pfVar10[0x130] + 0xc)) / FLOAT_803e3130
            ;
            *(undefined *)((int)pfVar10 + 9) = 0xe;
            if (pfVar10[0x128] == 0.0) {
              while (pfVar10[0x10c] == 0.0) {
                FUN_800dabb4((double)FLOAT_803e3088,pfVar10 + 0x108);
              }
            }
            else {
              while (pfVar10[0x10c] != 0.0) {
                FUN_800dabb4((double)FLOAT_803e30d8,pfVar10 + 0x108);
              }
            }
            pfVar10[0x1e8] = FLOAT_803e30d0;
          }
        }
      }
    }
    break;
  case 7:
    FUN_80148ff0();
    if (((float *)(uint)*(ushort *)(pfVar10 + 0x14d) != (float *)0x0) &&
       (pfVar3 == (float *)(uint)*(ushort *)(pfVar10 + 0x14d))) {
      fVar17 = (float)((double)FLOAT_803e30ac * (double)FLOAT_803dc074 + dVar27);
      if (fVar17 < FLOAT_803e306c) {
        fVar17 = FLOAT_803e306c;
      }
      pfVar10[5] = fVar17;
    }
    fVar17 = pfVar10[0x130];
    if ((*(char *)((int)pfVar10[0x12f] + 0x1a) != '\t') && (*(char *)((int)fVar17 + 0x1a) != '\t'))
    {
      pfVar23 = (float *)pfVar10[10];
      local_88 = *pfVar23 - *(float *)(puVar1 + 0xc);
      local_84 = pfVar23[1] - *(float *)(puVar1 + 0xe);
      local_80 = pfVar23[2] - *(float *)(puVar1 + 0x10);
      local_a4[0] = -*puVar1;
      local_a4[1] = 0;
      local_a4[2] = 0;
      FUN_80021b8c(local_a4,&local_88);
      if ((FLOAT_803e306c < local_80) && (FLOAT_803e306c != pfVar10[5])) {
        bVar14 = 0;
        while ((bVar14 < 4 &&
               ((ushort)*(byte *)((int)fVar17 + bVar14 + 4) != *(ushort *)((int)pfVar10 + 0x532))))
        {
          bVar14 = bVar14 + 1;
        }
        if (bVar14 == 4) {
          FUN_8004b498((int *)(pfVar10 + 0x14e),(int)pfVar10[0x131],(int)pfVar10[10],
                       (uint)*(ushort *)((int)pfVar10 + 0x532),SUB41(pfVar10[0x128],0));
          pfVar18 = (float *)(uint)*(ushort *)((int)pfVar10 + 0x532);
          uVar19 = (uint)pfVar10[0x128] ^ 1;
          FUN_8004b498((int *)(pfVar10 + 0x15a),(int)pfVar10[0x12f],(int)pfVar10[10],(int)pfVar18,
                       (byte)uVar19);
          cVar9 = '\0';
          bVar14 = 0;
          while ((bVar14 = bVar14 + 1, bVar14 < 100 && (cVar9 != '\x01'))) {
            cVar9 = FUN_8004b394();
            if (cVar9 != '\x01') {
              cVar9 = FUN_8004b394();
              if (cVar9 != '\0') {
                if (cVar9 < '\0') {
                  if (-2 < cVar9) {
                    cVar9 = '\x01';
                  }
                }
                else if (cVar9 < '\x02') {
                  fVar17 = (float)(((uint)pfVar10[0x128] ^ 1) & 0xff);
                  if (fVar17 == 0.0) {
                    FUN_800dabb4((double)FLOAT_803e3088,pfVar10 + 0x108);
                  }
                  else {
                    FUN_800dabb4((double)FLOAT_803e30d8,pfVar10 + 0x108);
                  }
                  pfVar10[0x128] = fVar17;
                  FUN_800da174(pfVar10 + 0x108);
                }
              }
            }
          }
        }
      }
    }
    fVar17 = pfVar10[0x128];
    if (((fVar17 == 0.0) && (pfVar10[0x10c] != 0.0)) || ((fVar17 != 0.0 && (pfVar10[0x10c] == 0.0)))
       ) {
      uVar13 = (uint)fVar17 & 0xff;
      fVar17 = (float)FUN_8013ad50((int)pfVar10,(int)pfVar10[0x131],SUB41(fVar17,0));
      if (fVar17 != 0.0) {
        FUN_800da4c8(extraout_f1_01,dVar26,param_3,param_4,param_5,param_6,param_7,param_8,
                     pfVar10 + 0x108,fVar17,uVar13,pfVar18,uVar19,param_14,param_15,param_16);
        cVar9 = *(char *)((int)pfVar10[0x12f] + 0x1a);
        if ((cVar9 == '\a') || ((cVar9 < '\a' && (cVar9 == '\x02')))) {
          fVar17 = pfVar10[0x15];
          if (((uint)fVar17 & 0x2000) == 0) {
            pfVar10[0x15] = (float)((uint)fVar17 | 0x2000);
          }
          else {
            pfVar10[0x15] = (float)((uint)fVar17 & 0xffffdfff);
          }
        }
        goto LAB_8013ca6c;
      }
      *(undefined *)((int)pfVar10 + 9) = 0;
    }
    else {
      fVar17 = (float)FUN_8013ad50((int)pfVar10,(int)pfVar10[0x130],SUB41(fVar17,0));
      if (fVar17 == 0.0) {
        *(undefined *)((int)pfVar10 + 9) = 0;
      }
      else {
        if (fVar17 != pfVar10[0x131]) {
          FUN_800da1c4((int)(pfVar10 + 0x108),(int)fVar17);
        }
LAB_8013ca6c:
        if (((float *)(uint)*(ushort *)(pfVar10 + 0x14d) == (float *)0x0) ||
           (pfVar3 != (float *)(uint)*(ushort *)(pfVar10 + 0x14d))) {
          iVar2 = FUN_80021884();
          iVar5 = FUN_80021884();
          sVar8 = (short)iVar2 - (short)iVar5;
          if (0x8000 < sVar8) {
            sVar8 = sVar8 + 1;
          }
          if (sVar8 < -0x8000) {
            sVar8 = sVar8 + -1;
          }
          if (sVar8 < 0x4001) {
            if (sVar8 < -0x4000) {
              sVar8 = sVar8 + -0x8000;
            }
          }
          else {
            sVar8 = sVar8 + -0x8000;
          }
          iVar2 = (int)sVar8;
          if (iVar2 < 0) {
            iVar2 = -iVar2;
          }
          if (0x1000 < iVar2) {
            pfVar10[5] = (float)dVar27;
            FUN_8013d92c((double)FLOAT_803e30fc,(short *)puVar1,(int)pfVar10,pfVar10 + 0x122,'\x01')
            ;
          }
        }
        FUN_80139bbc((double)pfVar10[5],(int)puVar1,pfVar10 + 0x108);
        FUN_80139e14();
        cVar9 = *(char *)((int)pfVar10[0x130] + 0x1a);
        if (cVar9 == '\x05') {
          *(undefined *)((int)pfVar10 + 9) = 0xb;
        }
        else if (cVar9 < '\x05') {
          if (cVar9 == '\x01') {
            *(undefined *)((int)pfVar10 + 9) = 8;
          }
        }
        else if (cVar9 < '\a') {
          *(undefined *)((int)pfVar10 + 9) = 0xd;
        }
      }
    }
    break;
  case 8:
    FUN_80148ff0();
    fVar17 = (float)((double)FLOAT_803e30b0 * (double)FLOAT_803dc074 + dVar27);
    if (FLOAT_803e311c < fVar17) {
      fVar17 = FLOAT_803e311c;
    }
    pfVar10[5] = fVar17;
    if (((float *)(uint)*(ushort *)(pfVar10 + 0x14d) != (float *)0x0) &&
       (pfVar3 == (float *)(uint)*(ushort *)(pfVar10 + 0x14d))) {
      fVar17 = (float)((double)FLOAT_803e30ac * (double)FLOAT_803dc074 + dVar27);
      if (fVar17 < FLOAT_803e306c) {
        fVar17 = FLOAT_803e306c;
      }
      pfVar10[5] = fVar17;
    }
    iVar2 = FUN_80021884();
    dVar26 = (double)(pfVar10[0x25] - pfVar10[0x124]);
    iVar5 = FUN_80021884();
    sVar8 = (short)iVar2 - (short)iVar5;
    if (0x8000 < sVar8) {
      sVar8 = sVar8 + 1;
    }
    if (sVar8 < -0x8000) {
      sVar8 = sVar8 + -1;
    }
    if (sVar8 < 0x4001) {
      if (sVar8 < -0x4000) {
        sVar8 = sVar8 + -0x8000;
      }
    }
    else {
      sVar8 = sVar8 + -0x8000;
    }
    iVar2 = (int)sVar8;
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (0x1000 < iVar2) {
      pfVar10[5] = (float)dVar27;
      pfVar18 = (float *)0x1;
      FUN_8013d92c((double)FLOAT_803e30fc,(short *)puVar1,(int)pfVar10,pfVar10 + 0x122,'\x01');
    }
    FUN_80139bbc((double)pfVar10[5],(int)puVar1,pfVar10 + 0x108);
    FUN_80139e14();
    fVar17 = pfVar10[0x128];
    if (((fVar17 == 0.0) && (pfVar10[0x10c] != 0.0)) || ((fVar17 != 0.0 && (pfVar10[0x10c] == 0.0)))
       ) {
      uVar13 = (uint)fVar17 & 0xff;
      fVar17 = (float)FUN_8013ad50((int)pfVar10,(int)pfVar10[0x131],SUB41(fVar17,0));
      if (fVar17 == 0.0) {
        *(undefined *)((int)pfVar10 + 9) = 0;
      }
      else {
        FUN_800da4c8(extraout_f1_02,dVar26,param_3,param_4,param_5,param_6,param_7,param_8,
                     pfVar10 + 0x108,fVar17,uVar13,pfVar18,uVar19,param_14,param_15,param_16);
        pfVar10[0xb] = *(float *)((int)pfVar10[0x130] + 8) - *(float *)(puVar1 + 0xc);
        pfVar10[0xc] = *(float *)((int)pfVar10[0x130] + 0x10) - *(float *)(puVar1 + 0x10);
        dVar26 = FUN_80293900((double)(pfVar10[0xb] * pfVar10[0xb] + pfVar10[0xc] * pfVar10[0xc]));
        if ((double)FLOAT_803e306c != dVar26) {
          pfVar10[0xb] = (float)((double)pfVar10[0xb] / dVar26);
          pfVar10[0xc] = (float)((double)pfVar10[0xc] / dVar26);
        }
        pfVar10[5] = FLOAT_803e311c;
        FUN_8013a778((double)FLOAT_803e30f8,(int)puVar1,0x15,0x4000000);
        *(undefined *)((int)pfVar10 + 9) = 9;
        pfVar10[0x1e8] = FLOAT_803e30d0;
      }
    }
    break;
  case 9:
    FUN_80148ff0();
    dVar26 = (double)FLOAT_803e3134;
    if (dVar27 <= dVar26) {
      dVar27 = (double)(float)((double)FLOAT_803e30b0 * (double)FLOAT_803dc074 + dVar27);
      if (dVar26 < dVar27) {
        dVar27 = dVar26;
      }
    }
    else {
      dVar27 = (double)(float)((double)FLOAT_803e30ac * (double)FLOAT_803dc074 + dVar27);
      if (dVar27 < dVar26) {
        dVar27 = dVar26;
      }
    }
    pfVar10[5] = (float)dVar27;
    fVar17 = *(float *)(*(int *)(puVar1 + 0x5c) + 0x2c);
    fVar22 = *(float *)(*(int *)(puVar1 + 0x5c) + 0x30);
    if (FLOAT_803e307c < fVar17 * fVar17 + fVar22 * fVar22) {
      iVar2 = FUN_80021884();
      FUN_80139cb8(puVar1,(ushort)iVar2);
    }
    if (FLOAT_803e3138 <= *(float *)(puVar1 + 0x4c)) {
      FUN_8002f6cc((double)(pfVar10[5] * FLOAT_803e313c),(int)puVar1,pfVar10 + 0xd);
      fVar17 = FLOAT_803e313c;
      *(float *)(puVar1 + 6) =
           FLOAT_803dc074 * pfVar10[0xb] * pfVar10[5] * FLOAT_803e313c + *(float *)(puVar1 + 6);
      *(float *)(puVar1 + 10) =
           FLOAT_803dc074 * pfVar10[0xc] * pfVar10[5] * fVar17 + *(float *)(puVar1 + 10);
    }
    else {
      FUN_8002f6cc((double)pfVar10[5],(int)puVar1,pfVar10 + 0xd);
      *(float *)(puVar1 + 6) = FLOAT_803dc074 * pfVar10[0xb] * pfVar10[5] + *(float *)(puVar1 + 6);
      *(float *)(puVar1 + 10) = FLOAT_803dc074 * pfVar10[0xc] * pfVar10[5] + *(float *)(puVar1 + 10)
      ;
    }
    if (((uint)pfVar10[0x15] & 0x8000000) != 0) {
      fVar20 = pfVar10[0x130];
      fVar17 = *(float *)((int)fVar20 + 8) - *(float *)(puVar1 + 0xc);
      fVar22 = *(float *)((int)fVar20 + 0x10) - *(float *)(puVar1 + 0x10);
      dVar26 = FUN_80293900((double)(fVar17 * fVar17 + fVar22 * fVar22));
      pfVar10[0x19] = (float)(dVar26 / (double)FLOAT_803e3134);
      dVar26 = (double)FLOAT_803e306c;
      pfVar10[0x1a] = FLOAT_803e306c;
      pfVar10[0x1d] = *(float *)(puVar1 + 0xc);
      pfVar10[0x1c] = *(float *)(puVar1 + 0xe);
      pfVar10[0x1e] = *(float *)(puVar1 + 0x10);
      pfVar10[0x1f] = *(float *)((int)fVar20 + 8);
      pfVar10[0x20] = *(float *)((int)fVar20 + 0x10);
      fVar17 = pfVar10[0x19];
      pfVar10[0x1b] =
           -(FLOAT_803e3140 * fVar17 * fVar17 -
            (*(float *)((int)fVar20 + 0xc) - *(float *)(puVar1 + 0xe))) / fVar17;
      FUN_8013a778(dVar26,(int)puVar1,0x16,0x4000000);
      pfVar10[0xf] = pfVar10[0x1a] / pfVar10[0x19];
      pfVar10[5] = FLOAT_803e3134;
      *(undefined *)((int)pfVar10 + 9) = 10;
      if (pfVar10[0x128] == 0.0) {
        while (pfVar10[0x10c] == 0.0) {
          FUN_800dabb4((double)FLOAT_803e3088,pfVar10 + 0x108);
        }
      }
      else {
        while (pfVar10[0x10c] != 0.0) {
          FUN_800dabb4((double)FLOAT_803e30d8,pfVar10 + 0x108);
        }
      }
    }
    break;
  case 10:
    FUN_80148ff0();
    pfVar10[0x1a] = pfVar10[0x1a] + FLOAT_803dc074;
    if (pfVar10[0x1a] < pfVar10[0x19]) {
      *(float *)(puVar1 + 6) =
           (pfVar10[0x1f] - pfVar10[0x1d]) * (pfVar10[0x1a] / pfVar10[0x19]) + pfVar10[0x1d];
      fVar17 = pfVar10[0x1a];
      *(float *)(puVar1 + 8) =
           FLOAT_803e3140 * fVar17 * fVar17 + pfVar10[0x1b] * fVar17 + pfVar10[0x1c];
      *(float *)(puVar1 + 10) =
           (pfVar10[0x20] - pfVar10[0x1e]) * (pfVar10[0x1a] / pfVar10[0x19]) + pfVar10[0x1e];
      fVar17 = pfVar10[0x19];
      if (FLOAT_803e3144 < fVar17) {
        fVar22 = pfVar10[0x1a];
        if (FLOAT_803e3148 < fVar22) {
          if (fVar22 < fVar17 - FLOAT_803e3148) {
            pfVar10[0xf] = ((fVar22 - FLOAT_803e3148) / (fVar17 - FLOAT_803e314c)) * FLOAT_803e3138
                           + FLOAT_803e313c;
          }
          else {
            pfVar10[0xf] = ((FLOAT_803e3144 - fVar17) + fVar22) / FLOAT_803e3144;
          }
        }
        else {
          pfVar10[0xf] = fVar22 / FLOAT_803e3144;
        }
      }
      else {
        pfVar10[0xf] = pfVar10[0x1a] / fVar17;
      }
      FUN_80063000((short *)puVar1,(short *)0x0,0);
      *(undefined *)((int)pfVar10 + 0x353) = 0;
    }
    else {
      *(undefined4 *)(puVar1 + 8) = *(undefined4 *)((int)pfVar10[0x130] + 0xc);
      pfVar10[0xf] = FLOAT_803e3078;
      *(undefined *)((int)pfVar10 + 9) = 7;
    }
    break;
  case 0xb:
    FUN_80148ff0();
    fVar17 = (float)((double)FLOAT_803e30b0 * (double)FLOAT_803dc074 + dVar27);
    if (FLOAT_803e311c < fVar17) {
      fVar17 = FLOAT_803e311c;
    }
    pfVar10[5] = fVar17;
    if (((float *)(uint)*(ushort *)(pfVar10 + 0x14d) != (float *)0x0) &&
       (pfVar3 == (float *)(uint)*(ushort *)(pfVar10 + 0x14d))) {
      fVar17 = (float)((double)FLOAT_803e30ac * (double)FLOAT_803dc074 + dVar27);
      if (fVar17 < FLOAT_803e306c) {
        fVar17 = FLOAT_803e306c;
      }
      pfVar10[5] = fVar17;
    }
    iVar2 = FUN_80021884();
    dVar26 = (double)(pfVar10[0x25] - pfVar10[0x124]);
    iVar5 = FUN_80021884();
    sVar8 = (short)iVar2 - (short)iVar5;
    if (0x8000 < sVar8) {
      sVar8 = sVar8 + 1;
    }
    if (sVar8 < -0x8000) {
      sVar8 = sVar8 + -1;
    }
    if (sVar8 < 0x4001) {
      if (sVar8 < -0x4000) {
        sVar8 = sVar8 + -0x8000;
      }
    }
    else {
      sVar8 = sVar8 + -0x8000;
    }
    iVar2 = (int)sVar8;
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (0x1000 < iVar2) {
      pfVar10[5] = (float)dVar27;
      pfVar18 = (float *)0x1;
      FUN_8013d92c((double)FLOAT_803e30fc,(short *)puVar1,(int)pfVar10,pfVar10 + 0x122,'\x01');
    }
    FUN_80139bbc((double)pfVar10[5],(int)puVar1,pfVar10 + 0x108);
    FUN_80139e14();
    fVar17 = pfVar10[0x128];
    if (((fVar17 == 0.0) && (pfVar10[0x10c] != 0.0)) || ((fVar17 != 0.0 && (pfVar10[0x10c] == 0.0)))
       ) {
      uVar13 = (uint)fVar17 & 0xff;
      fVar17 = (float)FUN_8013ad50((int)pfVar10,(int)pfVar10[0x131],SUB41(fVar17,0));
      if (fVar17 == 0.0) {
        *(undefined *)((int)pfVar10 + 9) = 0;
      }
      else {
        FUN_800da4c8(extraout_f1_03,dVar26,param_3,param_4,param_5,param_6,param_7,param_8,
                     pfVar10 + 0x108,fVar17,uVar13,pfVar18,uVar19,param_14,param_15,param_16);
        pfVar10[0xb] = *(float *)((int)pfVar10[0x130] + 8) - *(float *)(puVar1 + 0xc);
        pfVar10[0xc] = *(float *)((int)pfVar10[0x130] + 0x10) - *(float *)(puVar1 + 0x10);
        dVar26 = FUN_80293900((double)(pfVar10[0xb] * pfVar10[0xb] + pfVar10[0xc] * pfVar10[0xc]));
        if ((double)FLOAT_803e306c != dVar26) {
          pfVar10[0xb] = (float)((double)pfVar10[0xb] / dVar26);
          pfVar10[0xc] = (float)((double)pfVar10[0xc] / dVar26);
        }
        uVar19 = FUN_80022264(0,1);
        if (uVar19 == 0) {
          FUN_8013a778((double)FLOAT_803e3124,(int)puVar1,0x18,0x40000c0);
        }
        else {
          FUN_8013a778((double)FLOAT_803e3120,(int)puVar1,0x17,0x40000c0);
        }
        pfVar10[0x12] =
             (*(float *)((int)pfVar10[0x130] + 0xc) - *(float *)(puVar1 + 0xe)) / FLOAT_803e3128;
        *(undefined *)((int)pfVar10 + 9) = 0xc;
        if (pfVar10[0x128] == 0.0) {
          while (pfVar10[0x10c] == 0.0) {
            FUN_800dabb4((double)FLOAT_803e3088,pfVar10 + 0x108);
          }
        }
        else {
          while (pfVar10[0x10c] != 0.0) {
            FUN_800dabb4((double)FLOAT_803e30d8,pfVar10 + 0x108);
          }
        }
        pfVar10[0x1e8] = FLOAT_803e30d0;
      }
    }
    break;
  case 0xc:
  case 0xe:
    FUN_80148ff0();
    *(undefined *)((int)pfVar10 + 0x353) = 0;
    FUN_80139bbc((double)pfVar10[5],(int)puVar1,pfVar10 + 0x108);
    fVar17 = *(float *)(*(int *)(puVar1 + 0x5c) + 0x2c);
    fVar22 = *(float *)(*(int *)(puVar1 + 0x5c) + 0x30);
    if (FLOAT_803e307c < fVar17 * fVar17 + fVar22 * fVar22) {
      iVar2 = FUN_80021884();
      FUN_80139cb8(puVar1,(ushort)iVar2);
    }
    if (((uint)pfVar10[0x15] & 0x8000000) != 0) {
      pfVar10[5] = FLOAT_803e3150;
      FUN_80139e14();
      *(undefined *)((int)pfVar10 + 9) = 7;
    }
    break;
  case 0xd:
    FUN_80148ff0();
    fVar17 = (float)((double)FLOAT_803e30b0 * (double)FLOAT_803dc074 + dVar27);
    if (FLOAT_803e311c < fVar17) {
      fVar17 = FLOAT_803e311c;
    }
    pfVar10[5] = fVar17;
    if (((float *)(uint)*(ushort *)(pfVar10 + 0x14d) != (float *)0x0) &&
       (pfVar3 == (float *)(uint)*(ushort *)(pfVar10 + 0x14d))) {
      fVar17 = (float)((double)FLOAT_803e30ac * (double)FLOAT_803dc074 + dVar27);
      if (fVar17 < FLOAT_803e306c) {
        fVar17 = FLOAT_803e306c;
      }
      pfVar10[5] = fVar17;
    }
    iVar2 = FUN_80021884();
    dVar26 = (double)(pfVar10[0x25] - pfVar10[0x124]);
    iVar5 = FUN_80021884();
    sVar8 = (short)iVar2 - (short)iVar5;
    if (0x8000 < sVar8) {
      sVar8 = sVar8 + 1;
    }
    if (sVar8 < -0x8000) {
      sVar8 = sVar8 + -1;
    }
    if (sVar8 < 0x4001) {
      if (sVar8 < -0x4000) {
        sVar8 = sVar8 + -0x8000;
      }
    }
    else {
      sVar8 = sVar8 + -0x8000;
    }
    iVar2 = (int)sVar8;
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (0x1000 < iVar2) {
      pfVar10[5] = (float)dVar27;
      pfVar18 = (float *)0x1;
      FUN_8013d92c((double)FLOAT_803e30fc,(short *)puVar1,(int)pfVar10,pfVar10 + 0x122,'\x01');
    }
    FUN_80139bbc((double)pfVar10[5],(int)puVar1,pfVar10 + 0x108);
    FUN_80139e14();
    fVar17 = pfVar10[0x128];
    if (((fVar17 == 0.0) && (pfVar10[0x10c] != 0.0)) || ((fVar17 != 0.0 && (pfVar10[0x10c] == 0.0)))
       ) {
      uVar13 = (uint)fVar17 & 0xff;
      fVar17 = (float)FUN_8013ad50((int)pfVar10,(int)pfVar10[0x131],SUB41(fVar17,0));
      if (fVar17 == 0.0) {
        *(undefined *)((int)pfVar10 + 9) = 0;
      }
      else {
        FUN_800da4c8(extraout_f1_04,dVar26,param_3,param_4,param_5,param_6,param_7,param_8,
                     pfVar10 + 0x108,fVar17,uVar13,pfVar18,uVar19,param_14,param_15,param_16);
        pfVar10[0xb] = *(float *)((int)pfVar10[0x130] + 8) - *(float *)(puVar1 + 0xc);
        pfVar10[0xc] = *(float *)((int)pfVar10[0x130] + 0x10) - *(float *)(puVar1 + 0x10);
        dVar26 = FUN_80293900((double)(pfVar10[0xb] * pfVar10[0xb] + pfVar10[0xc] * pfVar10[0xc]));
        if ((double)FLOAT_803e306c != dVar26) {
          pfVar10[0xb] = (float)((double)pfVar10[0xb] / dVar26);
          pfVar10[0xc] = (float)((double)pfVar10[0xc] / dVar26);
        }
        FUN_8013a778((double)FLOAT_803e312c,(int)puVar1,0x19,0x40000c0);
        pfVar10[0x12] =
             (*(float *)(puVar1 + 0xe) - *(float *)((int)pfVar10[0x130] + 0xc)) / FLOAT_803e3130;
        *(undefined *)((int)pfVar10 + 9) = 0xe;
        if (pfVar10[0x128] == 0.0) {
          while (pfVar10[0x10c] == 0.0) {
            FUN_800dabb4((double)FLOAT_803e3088,pfVar10 + 0x108);
          }
        }
        else {
          while (pfVar10[0x10c] != 0.0) {
            FUN_800dabb4((double)FLOAT_803e30d8,pfVar10 + 0x108);
          }
        }
        pfVar10[0x1e8] = FLOAT_803e30d0;
      }
    }
    break;
  default:
    FUN_80148ff0();
  }
  if (*(byte *)((int)pfVar10 + 9) < 5) {
    iVar2 = FUN_800dbe30((float *)(puVar1 + 0xc));
    if (iVar2 == 0) {
      (**(code **)(*DAT_803dd728 + 0x20))(puVar1,pfVar10 + 0x3e);
      *(float *)(puVar1 + 6) = pfVar10[0x38];
      *(float *)(puVar1 + 8) = pfVar10[0x39];
      *(float *)(puVar1 + 10) = pfVar10[0x3a];
      *(float *)(puVar1 + 0xc) = pfVar10[0x38];
      *(float *)(puVar1 + 0xe) = pfVar10[0x39];
      *(float *)(puVar1 + 0x10) = pfVar10[0x3a];
      FUN_80036084((int)puVar1);
    }
    else {
      pfVar10[0x38] = *(float *)(puVar1 + 0xc);
      pfVar10[0x39] = *(float *)(puVar1 + 0xe);
      pfVar10[0x3a] = *(float *)(puVar1 + 0x10);
    }
  }
LAB_8013d904:
  FUN_80286874();
  return;
}

