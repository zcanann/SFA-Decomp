// Function: FUN_801787e4
// Entry: 801787e4
// Size: 3212 bytes

/* WARNING: Removing unreachable block (ram,0x80179450) */
/* WARNING: Removing unreachable block (ram,0x80179448) */
/* WARNING: Removing unreachable block (ram,0x80179440) */
/* WARNING: Removing unreachable block (ram,0x80178804) */
/* WARNING: Removing unreachable block (ram,0x801787fc) */
/* WARNING: Removing unreachable block (ram,0x801787f4) */

void FUN_801787e4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  short sVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  bool bVar11;
  undefined2 *puVar10;
  int *piVar12;
  int unaff_r25;
  float *pfVar13;
  int iVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double in_f29;
  double in_f30;
  double dVar20;
  double in_f31;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_78;
  int local_74;
  uint local_70 [2];
  undefined4 local_68;
  uint uStack_64;
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
  uVar4 = FUN_80286830();
  iVar14 = *(int *)(uVar4 + 0x4c);
  pfVar13 = *(float **)(uVar4 + 0xb8);
  dVar20 = (double)FLOAT_803e42e0;
  iVar5 = FUN_8002e1f4(&local_78,&local_74);
  *(undefined *)(param_11 + 0x56) = 0;
  iVar6 = FUN_8002bac4();
  dVar16 = (double)(*(float *)(iVar6 + 0xc) - *(float *)(iVar14 + 8));
  fVar3 = *(float *)(iVar6 + 0x14) - *(float *)(iVar14 + 0x10);
  dVar15 = FUN_80293900((double)(float)(dVar16 * dVar16 + (double)(fVar3 * fVar3)));
  dVar18 = dVar15;
  if (pfVar13[4] == -NAN) {
    uVar7 = 1;
  }
  else {
    uVar7 = FUN_80020078((uint)pfVar13[4]);
  }
  iVar8 = FUN_8003757c(uVar4,(int *)local_70,(int *)0x0,(int *)0x0);
  if (iVar8 != 0) {
    if (local_70[0] == 0x30003) {
      *(undefined *)(pfVar13 + 8) = 0;
    }
    else if (((int)local_70[0] < 0x30003) && (0x30001 < (int)local_70[0])) {
      *(undefined *)(pfVar13 + 8) = 1;
    }
  }
  iVar8 = (int)*(char *)(pfVar13 + 8);
  switch(*(undefined *)(iVar14 + 0x19)) {
  case 0:
    uStack_64 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
    local_68 = 0x43300000;
    dVar15 = (double)FUN_802945e0();
    dVar16 = (double)FUN_80294964();
    dVar19 = -(double)(float)((double)*(float *)(iVar14 + 8) * dVar15 +
                             (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar16));
    dVar17 = (double)*(float *)(iVar6 + 0xc);
    dVar20 = (double)(float)(dVar19 + (double)(float)(dVar15 * dVar17 +
                                                     (double)(float)(dVar16 * (double)*(float *)(
                                                  iVar6 + 0x14))));
    dVar15 = (double)pfVar13[3];
    if ((((dVar18 < dVar15) && (uVar7 != 0)) && (dVar20 < dVar15)) && (-dVar15 < dVar20)) {
      iVar8 = 1;
    }
    if ((iVar8 == 0) || (*(char *)((int)pfVar13 + 0x22) != '\0')) {
      if ((iVar8 == 0) && (*(char *)((int)pfVar13 + 0x22) == '\x01')) {
        if ((*(short *)(uVar4 + 0x46) == 200) && (dVar20 <= (double)FLOAT_803e42e0)) {
          FUN_80008cbc(dVar16,dVar17,dVar19,param_4,param_5,param_6,param_7,param_8,0,0,0xe,0,
                       param_13,param_14,param_15,param_16);
        }
        *(undefined *)((int)pfVar13 + 0x22) = 0;
      }
    }
    else {
      if (*(short *)(uVar4 + 0x46) == 200) {
        uVar7 = FUN_80020078(0x57);
        if (uVar7 == 0) {
          FUN_80008cbc(dVar16,dVar17,dVar19,param_4,param_5,param_6,param_7,param_8,0,0,0x7c,0,
                       param_13,param_14,param_15,param_16);
        }
        else {
          FUN_80008cbc(dVar16,dVar17,dVar19,param_4,param_5,param_6,param_7,param_8,0,0,0x7f,0,
                       param_13,param_14,param_15,param_16);
        }
      }
      *(undefined *)((int)pfVar13 + 0x22) = 1;
    }
    break;
  case 1:
    if ((dVar18 < (double)FLOAT_803e42ec) && (uVar7 != 0)) {
      uStack_64 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
      local_68 = 0x43300000;
      dVar18 = (double)FUN_802945e0();
      dVar15 = (double)FUN_80294964();
      dVar20 = (double)(-(float)((double)*(float *)(iVar14 + 8) * dVar18 +
                                (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar15)) +
                       (float)(dVar18 * (double)*(float *)(iVar6 + 0xc) +
                              (double)(float)(dVar15 * (double)*(float *)(iVar6 + 0x14))));
      if (*(int *)(uVar4 + 0xf8) == 0) {
        if ((dVar20 < (double)FLOAT_803e42e0) && ((double)FLOAT_803e42f0 < dVar20)) {
          iVar8 = 1;
        }
      }
      else if ((dVar20 < (double)FLOAT_803e42f4) && ((double)FLOAT_803e42f0 < dVar20)) {
        iVar8 = 1;
      }
    }
    break;
  case 2:
    if (uVar7 != 0) {
      if (uVar7 != 0) {
        iVar8 = 1;
      }
    }
    else {
      if (((*(byte *)(uVar4 + 0xaf) & 8) != 0) && (uVar7 = FUN_80020078(0x2c), uVar7 != 0)) {
        *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) & 0xf7;
      }
      if ((*(byte *)(uVar4 + 0xaf) & 1) != 0) {
        *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) | 8;
        FUN_800201ac((uint)pfVar13[4],1);
      }
    }
    break;
  case 3:
    if ((dVar18 < (double)FLOAT_803e42ec) && (uVar7 != 0)) {
      uStack_64 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
      local_68 = 0x43300000;
      dVar18 = (double)FUN_802945e0();
      dVar15 = (double)FUN_80294964();
      dVar20 = (double)(-(float)((double)*(float *)(iVar14 + 8) * dVar18 +
                                (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar15)) +
                       (float)(dVar18 * (double)*(float *)(iVar6 + 0xc) +
                              (double)(float)(dVar15 * (double)*(float *)(iVar6 + 0x14))));
      if ((dVar20 < (double)FLOAT_803e4304) && ((double)FLOAT_803e4308 < dVar20)) {
        iVar8 = 1;
      }
    }
    break;
  case 4:
    *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) & 0xf7;
    if (uVar7 != 0) {
      piVar12 = (int *)(iVar5 + local_78 * 4);
      iVar5 = local_78;
      while ((iVar5 < local_74 && (iVar8 == 0))) {
        unaff_r25 = *piVar12;
        if (*(short *)(unaff_r25 + 0x46) == 0x7c) {
          dVar16 = (double)(*(float *)(unaff_r25 + 0xc) - *(float *)(iVar14 + 8));
          fVar3 = *(float *)(unaff_r25 + 0x14) - *(float *)(iVar14 + 0x10);
          dVar15 = FUN_80293900((double)(float)(dVar16 * dVar16 + (double)(fVar3 * fVar3)));
          if (dVar15 < (double)FLOAT_803e42f8) {
            uStack_64 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
            local_68 = 0x43300000;
            dVar18 = (double)FUN_802945e0();
            dVar15 = (double)FUN_80294964();
            param_3 = -(double)(float)((double)*(float *)(iVar14 + 8) * dVar18 +
                                      (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar15));
            dVar16 = (double)*(float *)(unaff_r25 + 0xc);
            dVar20 = (double)(float)(param_3 +
                                    (double)(float)(dVar18 * dVar16 +
                                                   (double)(float)(dVar15 * (double)*(float *)(
                                                  unaff_r25 + 0x14))));
            if ((dVar20 < (double)FLOAT_803e42fc) && ((double)FLOAT_803e4300 < dVar20)) {
              iVar8 = 1;
            }
          }
        }
        piVar12 = piVar12 + 1;
        iVar5 = iVar5 + 1;
      }
      if (iVar8 == 0) {
        if (*(int *)(uVar4 + 0xf8) == 1) {
          *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 8;
        }
      }
      else {
        iVar5 = FUN_800375e4(uVar4,local_70,(uint *)0x0,(uint *)0x0);
        if (((iVar5 != 0) && ((int)local_70[0] < 10)) && (7 < (int)local_70[0])) {
          FUN_800379bc(dVar15,dVar16,param_3,param_4,param_5,param_6,param_7,param_8,unaff_r25,
                       local_70[0],uVar4,0,param_13,param_14,param_15,param_16);
        }
        if ((dVar20 < (double)FLOAT_803e42e0) && (*(int *)(uVar4 + 0xf8) == 0)) {
          *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 0x14;
        }
      }
    }
    break;
  case 5:
    uVar9 = FUN_80020078((uint)pfVar13[5]);
    if ((uVar9 != 0) && (uVar7 == 0)) {
      *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) & 0xf7;
      if ((*(byte *)(uVar4 + 0xaf) & 1) != 0) {
        *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) | 8;
        FUN_800201ac((uint)pfVar13[4],1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,uVar4,0xffffffff);
        uVar7 = 1;
      }
    }
    if (uVar7 != 0) {
      iVar8 = 1;
      *(byte *)(uVar4 + 0xaf) = *(byte *)(uVar4 + 0xaf) | 8;
    }
    break;
  case 6:
    if (uVar7 != 0) {
      iVar8 = 1;
    }
  }
  if (*(int *)(uVar4 + 0xf8) == 0) {
    if (iVar8 != 0) {
      *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 1;
    }
  }
  else if (iVar8 == 0) {
    *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 2;
  }
  *(int *)(uVar4 + 0xf8) = iVar8;
  if (((*(short *)(uVar4 + 0x46) == 0x13e) || (*(short *)(uVar4 + 0x46) == 0x151)) &&
     (*(char *)((int)pfVar13 + 0x21) != '\0')) {
    *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 1;
  }
  do {
    iVar5 = FUN_800375e4(uVar4,local_70,(uint *)0x0,(uint *)0x0);
  } while (iVar5 != 0);
  iVar5 = 0;
  do {
    if ((int)(uint)*(byte *)(param_11 + 0x8b) <= iVar5) {
      if (*(int *)(uVar4 + 0xf4) != 0) {
        *(undefined4 *)(uVar4 + 0xf4) = 0;
      }
      FUN_8028687c();
      return;
    }
    bVar1 = *(byte *)(param_11 + iVar5 + 0x81);
    if (bVar1 != 0) {
      if (bVar1 == 3) {
LAB_80179188:
        if (*(ushort *)(pfVar13 + 7) != 0) {
          FUN_8000bb38(uVar4,*(ushort *)(pfVar13 + 7));
        }
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          puVar10 = FUN_8000facc();
          dVar16 = (double)pfVar13[2];
          dVar15 = (double)*pfVar13;
          dVar18 = (double)*(float *)(puVar10 + 6);
          if (FLOAT_803e42e0 <=
              (float)(dVar16 + (double)(float)(dVar15 * dVar18 +
                                              (double)(pfVar13[1] * *(float *)(puVar10 + 10))))) {
            if ((int)*(short *)(iVar14 + 0x1a) != 0xffffffff) {
              uVar7 = FUN_80020078((int)*(short *)(iVar14 + 0x1a));
              FUN_800201ac((int)*(short *)(iVar14 + 0x1a),
                           uVar7 & 0xff ^ (int)*(short *)(iVar14 + 0x1c) >> 8 & 0xffU);
            }
          }
          else if ((int)*(short *)(iVar14 + 0x20) != 0xffffffff) {
            uVar7 = FUN_80020078((int)*(short *)(iVar14 + 0x20));
            FUN_800201ac((int)*(short *)(iVar14 + 0x20),
                         uVar7 & 0xff ^ (int)*(short *)(iVar14 + 0x1c) & 0xffU);
          }
          if (dVar20 <= (double)FLOAT_803e42e0) {
            sVar2 = *(short *)(uVar4 + 0x46);
            if (sVar2 == 0x205) {
              FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x202,0,uVar4,0x30006,0,param_14,param_15,param_16);
            }
            else if (sVar2 < 0x205) {
              if (sVar2 == 0x1bb) {
                FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                             param_8,0x1b9,0,uVar4,0x30006,0,param_14,param_15,param_16);
              }
              else if (sVar2 < 0x1bb) {
                if (sVar2 == 0x1ad) {
                  FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                               param_8,0x1ac,0,uVar4,0x30006,0,param_14,param_15,param_16);
                }
                else if ((sVar2 < 0x1ad) && (sVar2 == 0x1a2)) {
                  FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                               param_8,0x19c,0,uVar4,0x30006,0,param_14,param_15,param_16);
                }
              }
              else if (sVar2 == 0x1ea) {
                FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                             param_8,0x1e7,0,uVar4,0x30006,0,param_14,param_15,param_16);
              }
            }
            else if (sVar2 == 0x238) {
              FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x233,0,uVar4,0x30006,0,param_14,param_15,param_16);
            }
            else if (sVar2 < 0x238) {
              if (sVar2 == 0x21a) {
                FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                             param_8,0x217,0,uVar4,0x30006,0,param_14,param_15,param_16);
              }
            }
            else if (sVar2 == 0x23f) {
              FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x23c,0,uVar4,0x30006,0,param_14,param_15,param_16);
            }
          }
          goto LAB_80179188;
        }
        if (bVar1 != 0) {
          puVar10 = FUN_8000facc();
          dVar16 = (double)pfVar13[2];
          dVar15 = (double)*pfVar13;
          dVar18 = (double)*(float *)(puVar10 + 6);
          if (FLOAT_803e42e0 <=
              (float)(dVar16 + (double)(float)(dVar15 * dVar18 +
                                              (double)(pfVar13[1] * *(float *)(puVar10 + 10))))) {
            if ((int)*(short *)(iVar14 + 0x1a) != 0xffffffff) {
              uVar7 = FUN_80020078((int)*(short *)(iVar14 + 0x1a));
              FUN_800201ac((int)*(short *)(iVar14 + 0x1a),
                           uVar7 & 0xff ^ (int)*(short *)(iVar14 + 0x1c) >> 8 & 0xffU);
            }
          }
          else if ((int)*(short *)(iVar14 + 0x20) != 0xffffffff) {
            uVar7 = FUN_80020078((int)*(short *)(iVar14 + 0x20));
            FUN_800201ac((int)*(short *)(iVar14 + 0x20),
                         uVar7 & 0xff ^ (int)*(short *)(iVar14 + 0x1c) & 0xffU);
          }
          sVar2 = *(short *)(uVar4 + 0x46);
          if (sVar2 == 0x205) {
            FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,param_8
                         ,0x202,0,uVar4,0x30005,0,param_14,param_15,param_16);
          }
          else if (sVar2 < 0x205) {
            if (sVar2 == 0x1bb) {
              FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x1b9,0,uVar4,0x30005,0,param_14,param_15,param_16);
            }
            else if (sVar2 < 0x1bb) {
              if (sVar2 == 0x1ad) {
                FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                             param_8,0x1ac,0,uVar4,0x30005,0,param_14,param_15,param_16);
              }
              else if ((sVar2 < 0x1ad) && (sVar2 == 0x1a2)) {
                FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                             param_8,0x19c,0,uVar4,0x30005,0,param_14,param_15,param_16);
              }
            }
            else if (sVar2 == 0x1ea) {
              FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x1e7,0,uVar4,0x30005,0,param_14,param_15,param_16);
            }
          }
          else if (sVar2 == 0x238) {
            FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,param_8
                         ,0x233,0,uVar4,0x30005,0,param_14,param_15,param_16);
          }
          else if (sVar2 < 0x238) {
            if (sVar2 == 0x21a) {
              FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,
                           param_8,0x217,0,uVar4,0x30005,0,param_14,param_15,param_16);
            }
          }
          else if (sVar2 == 0x23f) {
            FUN_80037694((double)FLOAT_803e430c,dVar18,dVar15,dVar16,param_5,param_6,param_7,param_8
                         ,0x23c,0,uVar4,0x30005,0,param_14,param_15,param_16);
          }
        }
      }
      else if (bVar1 == 5) {
        if ((*(short *)((int)pfVar13 + 0x1e) != 0) && (uVar7 = FUN_80020078(0xcbb), uVar7 == 0)) {
          FUN_8000bb38(uVar4,*(ushort *)((int)pfVar13 + 0x1e));
        }
      }
      else if (((bVar1 < 5) && (*(short *)(pfVar13 + 7) != 0)) &&
              (bVar11 = FUN_8000b5f0(uVar4,*(short *)(pfVar13 + 7)), bVar11)) {
        FUN_8000b844(uVar4,*(short *)(pfVar13 + 7));
      }
      *(undefined *)(param_11 + iVar5 + 0x81) = 0;
    }
    iVar5 = iVar5 + 1;
  } while( true );
}

