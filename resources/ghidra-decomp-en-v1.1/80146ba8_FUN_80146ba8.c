// Function: FUN_80146ba8
// Entry: 80146ba8
// Size: 8672 bytes

void FUN_80146ba8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  char cVar2;
  float fVar3;
  short sVar4;
  short sVar5;
  uint uVar6;
  int iVar7;
  ushort *puVar8;
  uint uVar9;
  undefined2 *puVar10;
  int iVar11;
  bool bVar14;
  int iVar12;
  undefined4 *puVar13;
  bool bVar15;
  ushort uVar16;
  uint *puVar17;
  undefined4 in_r8;
  uint uVar18;
  undefined4 in_r9;
  uint uVar19;
  undefined4 in_r10;
  uint uVar20;
  int *piVar21;
  int *piVar22;
  undefined8 uVar23;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  double dVar24;
  char local_d0 [4];
  char local_cc [4];
  char local_c8 [4];
  char local_c4 [4];
  char local_c0 [4];
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined auStack_a4 [13];
  char local_97;
  undefined4 local_28;
  uint uStack_24;
  longlong local_20;
  
  puVar8 = (ushort *)FUN_8028683c();
  piVar22 = *(int **)(puVar8 + 0x5c);
  bVar15 = false;
  local_b8 = DAT_802c2948;
  local_b4 = DAT_802c294c;
  local_b0 = DAT_802c2950;
  local_ac = DAT_802c2954;
  local_a8 = DAT_802c2958;
  local_bc = DAT_803e3054;
  FUN_800dc624();
  uVar9 = FUN_80020078(0x186);
  if (((uVar9 != 0) && (piVar22[499] == 0)) && (uVar9 = FUN_8002e144(), (uVar9 & 0xff) != 0)) {
    uVar23 = FUN_80059da8(auStack_a4);
    if (local_97 == '\0') {
      puVar10 = FUN_8002becc(0x20,0x254);
    }
    else {
      puVar10 = FUN_8002becc(0x20,0x244);
    }
    iVar11 = FUN_8002e088(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar10,4,
                          0xff,0xffffffff,*(uint **)(puVar8 + 0x18),in_r8,in_r9,in_r10);
    piVar22[499] = iVar11;
    FUN_80037e24((int)puVar8,piVar22[499],3);
  }
  if ((piVar22[0x15] & 0x40000000U) != 0) {
    if (*(char *)*piVar22 == ((char *)*piVar22)[1]) {
      iVar11 = *(int *)(puVar8 + 0x5c);
      if ((((*(byte *)(iVar11 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < (short)puVar8[0x50] || ((short)puVar8[0x50] < 0x29)))) &&
         (bVar14 = FUN_8000b598((int)puVar8,0x10), !bVar14)) {
        FUN_800394f0(puVar8,iVar11 + 0x3a8,0x364,0x500,0xffffffff,0);
      }
    }
    else {
      iVar11 = *(int *)(puVar8 + 0x5c);
      if ((((*(byte *)(iVar11 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < (short)puVar8[0x50] || ((short)puVar8[0x50] < 0x29)))) &&
         (bVar14 = FUN_8000b598((int)puVar8,0x10), !bVar14)) {
        FUN_800394f0(puVar8,iVar11 + 0x3a8,0x363,0x500,0xffffffff,0);
      }
    }
    piVar22[0x15] = piVar22[0x15] & 0xbfffffff;
  }
  uVar20 = (uint)*(char *)(piVar22 + 0xd6);
  uVar9 = uVar20 & 4;
  puVar17 = (uint *)(uVar20 & 8);
  uVar18 = uVar20 & 0x10;
  uVar19 = uVar20 & 0x20;
  uVar20 = uVar20 & 0x40;
  FUN_80148ff0();
  FUN_80148ff0();
  if ((piVar22[0x15] & 0x200U) != 0) {
    FUN_80036018((int)puVar8);
    if ((piVar22[0x15] & 0x4000U) == 0) {
      *(undefined *)(piVar22 + 2) = 1;
      *(undefined *)((int)piVar22 + 10) = 0;
      fVar3 = FLOAT_803e306c;
      piVar22[0x1c7] = (int)FLOAT_803e306c;
      piVar22[0x1c8] = (int)fVar3;
      piVar22[0x15] = piVar22[0x15] & 0xffffffef;
      piVar22[0x15] = piVar22[0x15] & 0xfffeffff;
      piVar22[0x15] = piVar22[0x15] & 0xfffdffff;
      piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
      *(undefined *)((int)piVar22 + 0xd) = 0xff;
      *(undefined *)((int)piVar22 + 9) = 0;
      piVar22[4] = (int)fVar3;
      piVar22[5] = (int)fVar3;
      piVar22[0x38] = *(int *)(puVar8 + 0xc);
      piVar22[0x39] = *(int *)(puVar8 + 0xe);
      piVar22[0x3a] = *(int *)(puVar8 + 0x10);
      (**(code **)(*DAT_803dd728 + 0x20))(puVar8,piVar22 + 0x3e);
      if ((puVar8[0x50] == 8) || (puVar8[0x50] == 7)) {
        piVar22[0xab] = (int)FLOAT_803e30a4;
        piVar22[0xac] = (int)FLOAT_803e31d4;
      }
      else {
        piVar22[0xab] = (int)FLOAT_803e306c;
      }
    }
    piVar22[0x15] = piVar22[0x15] & 0xffffbdfe;
    bVar1 = *(byte *)((int)piVar22 + 0x82e);
    if ((bVar1 >> 5 & 1) == 0) {
      *(byte *)((int)piVar22 + 0x82e) = bVar1 & 0x7f | 0x80;
    }
    else {
      *(byte *)((int)piVar22 + 0x82e) = bVar1 & 0xdf;
    }
  }
  if ((piVar22[9] != 0) && ((*(ushort *)(piVar22[9] + 0xb0) & 0x40) != 0)) {
    if ((piVar22[0x15] & 0x10U) != 0) {
      piVar22[0x15] = piVar22[0x15] & 0xffffffef;
      *(undefined *)(piVar22 + 0xdd) = 2;
      (**(code **)(*DAT_803dd728 + 0x20))(puVar8,piVar22 + 0x3e);
      *(int *)(puVar8 + 6) = piVar22[0x38];
      *(int *)(puVar8 + 8) = piVar22[0x39];
      *(int *)(puVar8 + 10) = piVar22[0x3a];
      *(int *)(puVar8 + 0xc) = piVar22[0x38];
      *(int *)(puVar8 + 0xe) = piVar22[0x39];
      *(int *)(puVar8 + 0x10) = piVar22[0x3a];
      FUN_80036084((int)puVar8);
      iVar11 = 0;
      *(undefined *)((int)piVar22 + 9) = 0;
      fVar3 = FLOAT_803e306c;
      piVar22[4] = (int)FLOAT_803e306c;
      piVar22[5] = (int)fVar3;
      piVar22[0x15] = piVar22[0x15] | 0x80000;
      piVar22[0x15] = piVar22[0x15] & 0xffffdfff;
      if ((piVar22[0x15] & 0x800U) != 0) {
        piVar22[0x15] = piVar22[0x15] & 0xfffff7ff;
        piVar22[0x15] = piVar22[0x15] | 0x1000;
        piVar21 = piVar22;
        do {
          FUN_801784f8(piVar21[0x1c0]);
          piVar21 = piVar21 + 1;
          iVar11 = iVar11 + 1;
        } while (iVar11 < 7);
        FUN_8000dbb0();
        iVar11 = *(int *)(puVar8 + 0x5c);
        if (((*(byte *)(iVar11 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < (short)puVar8[0x50] || ((short)puVar8[0x50] < 0x29)) &&
            (bVar14 = FUN_8000b598((int)puVar8,0x10), !bVar14)))) {
          uVar9 = 0;
          puVar17 = (uint *)0xffffffff;
          uVar18 = 0;
          FUN_800394f0(puVar8,iVar11 + 0x3a8,0x29d,0,0xffffffff,0);
        }
      }
      FUN_8000dbb0();
    }
    *(undefined *)(piVar22 + 2) = 1;
    *(undefined *)((int)piVar22 + 10) = 0;
    fVar3 = FLOAT_803e306c;
    piVar22[0x1c7] = (int)FLOAT_803e306c;
    piVar22[0x1c8] = (int)fVar3;
    piVar22[0x15] = piVar22[0x15] & 0xffffffef;
    piVar22[0x15] = piVar22[0x15] & 0xfffeffff;
    piVar22[0x15] = piVar22[0x15] & 0xfffdffff;
    piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
    *(undefined *)((int)piVar22 + 0xd) = 0xff;
    piVar22[9] = 0;
  }
  if (((piVar22[0x15] & 0x10U) == 0) ||
     (iVar11 = (**(code **)(*DAT_803dd6e8 + 0x20))(0xc1), iVar11 == 0)) {
    iVar11 = (**(code **)(*DAT_803dd6e8 + 0x24))(&local_b8,5);
    uVar23 = extraout_f1_00;
  }
  else {
    iVar11 = 0;
    uVar23 = extraout_f1;
  }
  piVar21 = piVar22;
  for (uVar6 = (uint)*(byte *)(piVar22 + 0x1e6); uVar6 != 0; uVar6 = uVar6 - 1) {
    if (*(char *)((int)piVar21 + 0x74d) == iVar11) {
      bVar15 = true;
      break;
    }
    piVar21 = piVar21 + 2;
  }
  if (((piVar22[0x15] & 0x10U) == 0) &&
     (iVar12 = FUN_8013dec4((int)puVar8,(int)piVar22), uVar23 = extraout_f1_01, iVar12 == 2)) {
    *(undefined *)(piVar22 + 2) = 0x11;
    goto LAB_80148194;
  }
  cVar2 = *(char *)(piVar22 + 2);
  if ((cVar2 == '\b') && (iVar11 == 4)) {
    *(byte *)(piVar22 + 0x1cd) = *(byte *)(piVar22 + 0x1cd) ^ 1;
    goto LAB_80148194;
  }
  if (((cVar2 == '\r') && (iVar11 == 4)) && (!bVar15)) {
    piVar22[0x1ca] = 1;
    goto LAB_80148194;
  }
  if ((cVar2 == '\x0e') && (iVar11 == 4)) {
    piVar22[0x1ca] = 1;
    goto LAB_80148194;
  }
  if (iVar11 == 0) {
    piVar22[0x15] = piVar22[0x15] | 0x30002;
    goto LAB_80148194;
  }
  uVar6 = piVar22[0x15];
  if ((uVar6 & 0x10) != 0) {
    if (iVar11 == 3) {
      piVar22[0x15] = uVar6 | 0x40000;
    }
    goto LAB_80148194;
  }
  if (iVar11 == 3) {
    bVar15 = false;
    if (*(char *)((int)piVar22 + 0xd) == '\x03') {
      piVar21 = piVar22;
      for (uVar6 = (uint)*(byte *)(piVar22 + 0x1e6); uVar6 != 0; uVar6 = uVar6 - 1) {
        if (*(char *)((int)piVar21 + 0x74d) == '\x03') {
          bVar15 = true;
        }
        piVar21 = piVar21 + 2;
      }
    }
    else {
      bVar15 = true;
    }
    if (!bVar15) goto LAB_80148194;
    *(undefined *)((int)piVar22 + 0xd) = 3;
    iVar11 = FUN_801395e8();
    if (iVar11 == 0) {
      piVar22[0x15] = piVar22[0x15] | 0x40000;
      goto LAB_80148194;
    }
    sVar4 = *(short *)(piVar22[9] + 0x46);
    if (sVar4 != 0x26c) {
      if (sVar4 < 0x26c) {
        if (sVar4 != 0x131) {
          if (sVar4 < 0x131) {
            if ((sVar4 != 0x104) && ((0x103 < sVar4 || (sVar4 != 0x36)))) {
LAB_80147cac:
              *(undefined *)(piVar22 + 2) = 8;
              goto LAB_80148194;
            }
          }
          else if (sVar4 != 0x19f) goto LAB_80147cac;
        }
      }
      else {
        if (sVar4 == 0x6f0) {
          *(undefined *)(piVar22 + 2) = 0xe;
          goto LAB_80148194;
        }
        if (sVar4 < 0x6f0) {
          if ((sVar4 != 0x546) && ((0x545 < sVar4 || (sVar4 != 0x475)))) goto LAB_80147cac;
        }
        else if (sVar4 != 0x7c3) goto LAB_80147cac;
      }
    }
    *(undefined *)(piVar22 + 2) = 10;
    uStack_24 = FUN_80022264(500,0x2ee);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    piVar22[0x1d0] = (int)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e30f0);
    goto LAB_80148194;
  }
  if (2 < iVar11) {
    if (iVar11 == 5) {
      uVar6 = FUN_8002e144();
      if ((uVar6 & 0xff) != 0) {
        *(undefined *)((int)piVar22 + 0xd) = 5;
        puVar10 = FUN_8002becc(0x18,0x112);
        *(undefined *)((int)puVar10 + 7) = 0xff;
        *(undefined *)(puVar10 + 2) = 2;
        *(undefined4 *)(puVar10 + 4) = *(undefined4 *)(puVar8 + 0xc);
        *(undefined4 *)(puVar10 + 6) = *(undefined4 *)(puVar8 + 0xe);
        *(undefined4 *)(puVar10 + 8) = *(undefined4 *)(puVar8 + 0x10);
        uVar9 = 0xffffffff;
        puVar17 = *(uint **)(puVar8 + 0x18);
        iVar11 = FUN_8002e088(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar10
                              ,5,0xff,0xffffffff,puVar17,uVar18,uVar19,uVar20);
        piVar22[9] = iVar11;
        if (piVar22[10] != piVar22[9] + 0x18) {
          piVar22[10] = piVar22[9] + 0x18;
          piVar22[0x15] = piVar22[0x15] & 0xfffffbff;
          *(undefined2 *)((int)piVar22 + 0xd2) = 0;
        }
        *(undefined *)((int)piVar22 + 10) = 0;
        *(undefined *)(piVar22 + 2) = 0xb;
      }
      goto LAB_80148194;
    }
    if (4 < iVar11) goto LAB_801480fc;
    if (*(byte *)*piVar22 < 4) {
      uVar6 = FUN_8002e144();
      if ((uVar6 & 0xff) != 0) {
        piVar22[0x15] = piVar22[0x15] | 4;
        *(undefined *)(piVar22 + 2) = 1;
        *(undefined *)((int)piVar22 + 10) = 0;
        fVar3 = FLOAT_803e306c;
        piVar22[0x1c7] = (int)FLOAT_803e306c;
        piVar22[0x1c8] = (int)fVar3;
        piVar22[0x15] = piVar22[0x15] & 0xffffffef;
        piVar22[0x15] = piVar22[0x15] & 0xfffeffff;
        piVar22[0x15] = piVar22[0x15] & 0xfffdffff;
        piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
        *(undefined *)((int)piVar22 + 0xd) = 0xff;
        if (piVar22[0x1ee] == 0) {
          puVar10 = FUN_8002becc(0x20,0x17b);
          local_d0[0] = -1;
          local_d0[1] = -1;
          local_d0[2] = -1;
          if (piVar22[0x1ea] != 0) {
            local_d0[*(byte *)(piVar22 + 0x1ef) >> 6] = '\x01';
          }
          if (piVar22[0x1ec] != 0) {
            local_d0[*(byte *)(piVar22 + 0x1ef) >> 4 & 3] = '\x01';
          }
          if (piVar22[0x1ee] != 0) {
            local_d0[*(byte *)(piVar22 + 0x1ef) >> 2 & 3] = '\x01';
          }
          if (local_d0[0] == -1) {
            uVar9 = 0;
          }
          else if (local_d0[1] == -1) {
            uVar9 = 1;
          }
          else if (local_d0[2] == -1) {
            uVar9 = 2;
          }
          else if (local_d0[3] == -1) {
            uVar9 = 3;
          }
          else {
            uVar9 = 0xffffffff;
          }
          *(byte *)(piVar22 + 0x1ef) =
               (byte)((uVar9 & 0xff) << 2) & 0xc | *(byte *)(piVar22 + 0x1ef) & 0xf3;
          uVar9 = 0xffffffff;
          puVar17 = *(uint **)(puVar8 + 0x18);
          iVar11 = FUN_8002e088(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                puVar10,4,0xff,0xffffffff,puVar17,uVar18,uVar19,uVar20);
          piVar22[0x1ee] = iVar11;
          FUN_80037e24((int)puVar8,piVar22[0x1ee],*(byte *)(piVar22 + 0x1ef) >> 2 & 3);
          fVar3 = FLOAT_803e306c;
          piVar22[0x1f0] = (int)FLOAT_803e306c;
          piVar22[0x1f1] = (int)fVar3;
          piVar22[0x1f2] = (int)fVar3;
        }
      }
      goto LAB_80148194;
    }
    *(undefined *)((int)piVar22 + 0xd) = 4;
    FUN_801395e8();
    *(undefined *)(piVar22 + 2) = 7;
    sVar4 = *(short *)(piVar22[9] + 0x46);
    if (sVar4 == 0x50f) {
      piVar22[0x1c9] = (int)FUN_80227970;
      goto LAB_80148194;
    }
    if (sVar4 < 0x50f) {
      if (sVar4 == 0x194) {
LAB_80147fa8:
        piVar22[0x1c9] = 0;
        goto LAB_80148194;
      }
      if (sVar4 < 0x194) {
        if (sVar4 == 0x102) goto LAB_80147fa8;
        if (sVar4 < 0x102) {
          if (sVar4 == 0x3c) {
            piVar22[0x1c9] = (int)&LAB_801dafbc;
            goto LAB_80148194;
          }
        }
        else if (sVar4 == 0x191) {
          piVar22[0x1c9] = (int)&LAB_801b0d38;
          goto LAB_80148194;
        }
      }
      else {
        if (sVar4 == 0x470) {
          piVar22[0x1c9] = (int)&LAB_8021aad4;
          goto LAB_80148194;
        }
        if ((sVar4 < 0x470) && (sVar4 == 0x1c9)) {
          piVar22[0x1c9] = (int)&LAB_801b1da8;
          goto LAB_80148194;
        }
      }
    }
    else {
      if (sVar4 == 0x551) {
        piVar22[0x1c9] = (int)&LAB_801fdae0;
        goto LAB_80148194;
      }
      if (sVar4 < 0x551) {
        if ((sVar4 == 0x54c) || ((sVar4 < 0x54c && (sVar4 == 0x542)))) goto LAB_80147fa8;
      }
      else {
        if (sVar4 == 0x718) {
          piVar22[0x1c9] = (int)&LAB_801b72f4;
          goto LAB_80148194;
        }
        if ((sVar4 < 0x718) && (sVar4 == 0x6f9)) goto LAB_80147fa8;
      }
    }
    *(undefined *)(piVar22 + 2) = 1;
    *(undefined *)((int)piVar22 + 10) = 0;
    fVar3 = FLOAT_803e306c;
    piVar22[0x1c7] = (int)FLOAT_803e306c;
    piVar22[0x1c8] = (int)fVar3;
    piVar22[0x15] = piVar22[0x15] & 0xffffffef;
    piVar22[0x15] = piVar22[0x15] & 0xfffeffff;
    piVar22[0x15] = piVar22[0x15] & 0xfffdffff;
    piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
    *(undefined *)((int)piVar22 + 0xd) = 0xff;
    FUN_80148fa0();
    goto LAB_80148194;
  }
  if (iVar11 != 1) {
LAB_801480fc:
    if ((((cVar2 == '\x01') && (*(char *)((int)piVar22 + 0xd) != '\0')) && ((uVar6 & 0x20000) == 0))
       && (iVar11 = FUN_80139330(), iVar11 != 0)) {
      piVar22[9] = iVar11;
      if (piVar22[10] != iVar11 + 0x18) {
        piVar22[10] = iVar11 + 0x18;
        piVar22[0x15] = piVar22[0x15] & 0xfffffbff;
        *(undefined2 *)((int)piVar22 + 0xd2) = 0;
      }
      *(undefined *)(piVar22 + 2) = 0xd;
      *(undefined *)((int)piVar22 + 10) = 0;
      piVar22[0x1ca] = 0;
    }
    goto LAB_80148194;
  }
  *(undefined *)((int)piVar22 + 0xd) = 1;
  uVar23 = FUN_801395e8();
  iVar11 = *(int *)(puVar8 + 0x5c);
  if ((((*(byte *)(iVar11 + 0x58) >> 6 & 1) == 0) &&
      ((0x2f < (short)puVar8[0x50] || ((short)puVar8[0x50] < 0x29)))) &&
     (bVar15 = FUN_8000b598((int)puVar8,0x10), !bVar15)) {
    uVar9 = 0;
    puVar17 = (uint *)0xffffffff;
    uVar18 = 0;
    uVar23 = FUN_800394f0(puVar8,iVar11 + 0x3a8,0x13c,0,0xffffffff,0);
  }
  sVar4 = *(short *)(piVar22[9] + 0x46);
  if (sVar4 == 0x1ca) {
    if (*(byte *)*piVar22 < 4) {
      uVar6 = FUN_8002e144();
      if ((uVar6 & 0xff) != 0) {
        piVar22[0x15] = piVar22[0x15] | 4;
        *(undefined *)(piVar22 + 2) = 1;
        *(undefined *)((int)piVar22 + 10) = 0;
        fVar3 = FLOAT_803e306c;
        piVar22[0x1c7] = (int)FLOAT_803e306c;
        piVar22[0x1c8] = (int)fVar3;
        piVar22[0x15] = piVar22[0x15] & 0xffffffef;
        piVar22[0x15] = piVar22[0x15] & 0xfffeffff;
        piVar22[0x15] = piVar22[0x15] & 0xfffdffff;
        piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
        *(undefined *)((int)piVar22 + 0xd) = 0xff;
        if (piVar22[0x1ee] == 0) {
          puVar10 = FUN_8002becc(0x20,0x17b);
          local_c0[0] = -1;
          local_c0[1] = -1;
          local_c0[2] = -1;
          if (piVar22[0x1ea] != 0) {
            local_c0[*(byte *)(piVar22 + 0x1ef) >> 6] = '\x01';
          }
          if (piVar22[0x1ec] != 0) {
            local_c0[*(byte *)(piVar22 + 0x1ef) >> 4 & 3] = '\x01';
          }
          if (piVar22[0x1ee] != 0) {
            local_c0[*(byte *)(piVar22 + 0x1ef) >> 2 & 3] = '\x01';
          }
          if (local_c0[0] == -1) {
            uVar9 = 0;
          }
          else if (local_c0[1] == -1) {
            uVar9 = 1;
          }
          else if (local_c0[2] == -1) {
            uVar9 = 2;
          }
          else if (local_c0[3] == -1) {
            uVar9 = 3;
          }
          else {
            uVar9 = 0xffffffff;
          }
          *(byte *)(piVar22 + 0x1ef) =
               (byte)((uVar9 & 0xff) << 2) & 0xc | *(byte *)(piVar22 + 0x1ef) & 0xf3;
          uVar9 = 0xffffffff;
          puVar17 = *(uint **)(puVar8 + 0x18);
          iVar11 = FUN_8002e088(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                puVar10,4,0xff,0xffffffff,puVar17,uVar18,uVar19,uVar20);
          piVar22[0x1ee] = iVar11;
          FUN_80037e24((int)puVar8,piVar22[0x1ee],*(byte *)(piVar22 + 0x1ef) >> 2 & 3);
          fVar3 = FLOAT_803e306c;
          piVar22[0x1f0] = (int)FLOAT_803e306c;
          piVar22[0x1f1] = (int)fVar3;
          piVar22[0x1f2] = (int)fVar3;
        }
      }
    }
    else {
      *(undefined *)(piVar22 + 2) = 2;
    }
    goto LAB_80148194;
  }
  if (sVar4 < 0x1ca) {
    if (sVar4 != 0x193) {
      if (sVar4 < 0x193) {
        if (sVar4 == 0x160) {
          if (*(byte *)*piVar22 < 4) {
            uVar6 = FUN_8002e144();
            if ((uVar6 & 0xff) != 0) {
              piVar22[0x15] = piVar22[0x15] | 4;
              *(undefined *)(piVar22 + 2) = 1;
              *(undefined *)((int)piVar22 + 10) = 0;
              fVar3 = FLOAT_803e306c;
              piVar22[0x1c7] = (int)FLOAT_803e306c;
              piVar22[0x1c8] = (int)fVar3;
              piVar22[0x15] = piVar22[0x15] & 0xffffffef;
              piVar22[0x15] = piVar22[0x15] & 0xfffeffff;
              piVar22[0x15] = piVar22[0x15] & 0xfffdffff;
              piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
              *(undefined *)((int)piVar22 + 0xd) = 0xff;
              if (piVar22[0x1ee] == 0) {
                puVar10 = FUN_8002becc(0x20,0x17b);
                local_c4[0] = -1;
                local_c4[1] = -1;
                local_c4[2] = -1;
                if (piVar22[0x1ea] != 0) {
                  local_c4[*(byte *)(piVar22 + 0x1ef) >> 6] = '\x01';
                }
                if (piVar22[0x1ec] != 0) {
                  local_c4[*(byte *)(piVar22 + 0x1ef) >> 4 & 3] = '\x01';
                }
                if (piVar22[0x1ee] != 0) {
                  local_c4[*(byte *)(piVar22 + 0x1ef) >> 2 & 3] = '\x01';
                }
                if (local_c4[0] == -1) {
                  uVar9 = 0;
                }
                else if (local_c4[1] == -1) {
                  uVar9 = 1;
                }
                else if (local_c4[2] == -1) {
                  uVar9 = 2;
                }
                else if (local_c4[3] == -1) {
                  uVar9 = 3;
                }
                else {
                  uVar9 = 0xffffffff;
                }
                *(byte *)(piVar22 + 0x1ef) =
                     (byte)((uVar9 & 0xff) << 2) & 0xc | *(byte *)(piVar22 + 0x1ef) & 0xf3;
                uVar9 = 0xffffffff;
                puVar17 = *(uint **)(puVar8 + 0x18);
                iVar11 = FUN_8002e088(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,puVar10,4,0xff,0xffffffff,puVar17,uVar18,uVar19,uVar20);
                piVar22[0x1ee] = iVar11;
                FUN_80037e24((int)puVar8,piVar22[0x1ee],*(byte *)(piVar22 + 0x1ef) >> 2 & 3);
                fVar3 = FLOAT_803e306c;
                piVar22[0x1f0] = (int)FLOAT_803e306c;
                piVar22[0x1f1] = (int)fVar3;
                piVar22[0x1f2] = (int)fVar3;
              }
            }
          }
          else {
            *(undefined *)(piVar22 + 2) = 3;
          }
          goto LAB_80148194;
        }
        if ((sVar4 < 0x160) && (sVar4 == 0x6a)) goto LAB_80147724;
      }
      else if (sVar4 == 0x195) {
        if (*(byte *)*piVar22 < 2) {
          uVar6 = FUN_8002e144();
          if ((uVar6 & 0xff) != 0) {
            piVar22[0x15] = piVar22[0x15] | 4;
            *(undefined *)(piVar22 + 2) = 1;
            *(undefined *)((int)piVar22 + 10) = 0;
            fVar3 = FLOAT_803e306c;
            piVar22[0x1c7] = (int)FLOAT_803e306c;
            piVar22[0x1c8] = (int)fVar3;
            piVar22[0x15] = piVar22[0x15] & 0xffffffef;
            piVar22[0x15] = piVar22[0x15] & 0xfffeffff;
            piVar22[0x15] = piVar22[0x15] & 0xfffdffff;
            piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
            *(undefined *)((int)piVar22 + 0xd) = 0xff;
            if (piVar22[0x1ee] == 0) {
              puVar10 = FUN_8002becc(0x20,0x17b);
              local_c8[0] = -1;
              local_c8[1] = -1;
              local_c8[2] = -1;
              if (piVar22[0x1ea] != 0) {
                local_c8[*(byte *)(piVar22 + 0x1ef) >> 6] = '\x01';
              }
              if (piVar22[0x1ec] != 0) {
                local_c8[*(byte *)(piVar22 + 0x1ef) >> 4 & 3] = '\x01';
              }
              if (piVar22[0x1ee] != 0) {
                local_c8[*(byte *)(piVar22 + 0x1ef) >> 2 & 3] = '\x01';
              }
              if (local_c8[0] == -1) {
                uVar9 = 0;
              }
              else if (local_c8[1] == -1) {
                uVar9 = 1;
              }
              else if (local_c8[2] == -1) {
                uVar9 = 2;
              }
              else if (local_c8[3] == -1) {
                uVar9 = 3;
              }
              else {
                uVar9 = 0xffffffff;
              }
              *(byte *)(piVar22 + 0x1ef) =
                   (byte)((uVar9 & 0xff) << 2) & 0xc | *(byte *)(piVar22 + 0x1ef) & 0xf3;
              uVar9 = 0xffffffff;
              puVar17 = *(uint **)(puVar8 + 0x18);
              iVar11 = FUN_8002e088(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    puVar10,4,0xff,0xffffffff,puVar17,uVar18,uVar19,uVar20);
              piVar22[0x1ee] = iVar11;
              FUN_80037e24((int)puVar8,piVar22[0x1ee],*(byte *)(piVar22 + 0x1ef) >> 2 & 3);
              fVar3 = FLOAT_803e306c;
              piVar22[0x1f0] = (int)FLOAT_803e306c;
              piVar22[0x1f1] = (int)fVar3;
              piVar22[0x1f2] = (int)fVar3;
            }
          }
        }
        else {
          *(undefined *)(piVar22 + 2) = 0x10;
        }
        goto LAB_80148194;
      }
      goto LAB_80147b04;
    }
  }
  else if (sVar4 != 0x3fb) {
    if (sVar4 < 0x3fb) {
      if (sVar4 == 0x358) {
        *(undefined *)(piVar22 + 2) = 0xe;
        goto LAB_80148194;
      }
      if ((sVar4 < 0x358) && (sVar4 == 0x352)) {
        if (*(byte *)*piVar22 < 4) {
          uVar6 = FUN_8002e144();
          if ((uVar6 & 0xff) != 0) {
            piVar22[0x15] = piVar22[0x15] | 4;
            *(undefined *)(piVar22 + 2) = 1;
            *(undefined *)((int)piVar22 + 10) = 0;
            fVar3 = FLOAT_803e306c;
            piVar22[0x1c7] = (int)FLOAT_803e306c;
            piVar22[0x1c8] = (int)fVar3;
            piVar22[0x15] = piVar22[0x15] & 0xffffffef;
            piVar22[0x15] = piVar22[0x15] & 0xfffeffff;
            piVar22[0x15] = piVar22[0x15] & 0xfffdffff;
            piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
            *(undefined *)((int)piVar22 + 0xd) = 0xff;
            if (piVar22[0x1ee] == 0) {
              puVar10 = FUN_8002becc(0x20,0x17b);
              local_cc[0] = -1;
              local_cc[1] = -1;
              local_cc[2] = -1;
              if (piVar22[0x1ea] != 0) {
                local_cc[*(byte *)(piVar22 + 0x1ef) >> 6] = '\x01';
              }
              if (piVar22[0x1ec] != 0) {
                local_cc[*(byte *)(piVar22 + 0x1ef) >> 4 & 3] = '\x01';
              }
              if (piVar22[0x1ee] != 0) {
                local_cc[*(byte *)(piVar22 + 0x1ef) >> 2 & 3] = '\x01';
              }
              if (local_cc[0] == -1) {
                uVar9 = 0;
              }
              else if (local_cc[1] == -1) {
                uVar9 = 1;
              }
              else if (local_cc[2] == -1) {
                uVar9 = 2;
              }
              else if (local_cc[3] == -1) {
                uVar9 = 3;
              }
              else {
                uVar9 = 0xffffffff;
              }
              *(byte *)(piVar22 + 0x1ef) =
                   (byte)((uVar9 & 0xff) << 2) & 0xc | *(byte *)(piVar22 + 0x1ef) & 0xf3;
              uVar9 = 0xffffffff;
              puVar17 = *(uint **)(puVar8 + 0x18);
              iVar11 = FUN_8002e088(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    puVar10,4,0xff,0xffffffff,puVar17,uVar18,uVar19,uVar20);
              piVar22[0x1ee] = iVar11;
              FUN_80037e24((int)puVar8,piVar22[0x1ee],*(byte *)(piVar22 + 0x1ef) >> 2 & 3);
              fVar3 = FLOAT_803e306c;
              piVar22[0x1f0] = (int)FLOAT_803e306c;
              piVar22[0x1f1] = (int)fVar3;
              piVar22[0x1f2] = (int)fVar3;
            }
          }
        }
        else {
          *(undefined *)(piVar22 + 2) = 2;
        }
        goto LAB_80148194;
      }
    }
    else if (sVar4 == 0x658) goto LAB_80147724;
LAB_80147b04:
    *(undefined *)(piVar22 + 2) = 1;
    *(undefined *)((int)piVar22 + 10) = 0;
    fVar3 = FLOAT_803e306c;
    piVar22[0x1c7] = (int)FLOAT_803e306c;
    piVar22[0x1c8] = (int)fVar3;
    piVar22[0x15] = piVar22[0x15] & 0xffffffef;
    piVar22[0x15] = piVar22[0x15] & 0xfffeffff;
    piVar22[0x15] = piVar22[0x15] & 0xfffdffff;
    piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
    *(undefined *)((int)piVar22 + 0xd) = 0xff;
    FUN_80148fa0();
    goto LAB_80148194;
  }
LAB_80147724:
  *(undefined *)(piVar22 + 2) = 9;
LAB_80148194:
  uVar6 = piVar22[0x15];
  if ((uVar6 & 0x10) == 0) {
    if ((uVar6 & 0x10000) == 0) {
      if ((uVar6 & 0x40000) != 0) {
        piVar22[9] = (int)puVar8;
        *(undefined *)(piVar22 + 2) = 0xf;
        uStack_24 = FUN_80022264(500,0x2ee);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_28 = 0x43300000;
        piVar22[0x1d0] = (int)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e30f0);
        piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
        *(undefined *)((int)piVar22 + 0xd) = 3;
        if ((int *)piVar22[10] != piVar22 + 0x1cb) {
          piVar22[10] = (int)(piVar22 + 0x1cb);
          piVar22[0x15] = piVar22[0x15] & 0xfffffbff;
          *(undefined2 *)((int)piVar22 + 0xd2) = 0;
        }
      }
    }
    else {
      if ((uVar6 & 0x20000) == 0) {
        *(undefined *)(piVar22 + 2) = 1;
        *(undefined *)((int)piVar22 + 10) = 0;
        fVar3 = FLOAT_803e306c;
        piVar22[0x1c7] = (int)FLOAT_803e306c;
        piVar22[0x1c8] = (int)fVar3;
        piVar22[0x15] = piVar22[0x15] & 0xffffffef;
        piVar22[0x15] = piVar22[0x15] & 0xfffeffff;
        piVar22[0x15] = piVar22[0x15] & 0xfffdffff;
        piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
        *(undefined *)((int)piVar22 + 0xd) = 0xff;
      }
      else {
        *(undefined *)(piVar22 + 2) = 1;
        *(undefined *)((int)piVar22 + 10) = 0;
        fVar3 = FLOAT_803e306c;
        piVar22[0x1c7] = (int)FLOAT_803e306c;
        piVar22[0x1c8] = (int)fVar3;
        piVar22[0x15] = piVar22[0x15] & 0xffffffef;
        piVar22[0x15] = piVar22[0x15] & 0xfffeffff;
        piVar22[0x15] = piVar22[0x15] & 0xfffdffff;
        piVar22[0x15] = piVar22[0x15] & 0xfffbffff;
        *(undefined *)((int)piVar22 + 0xd) = 0xff;
        *(undefined *)((int)piVar22 + 0xd) = 0;
      }
      piVar22[0x1c7] = (int)FLOAT_803e31d8;
    }
  }
  *(byte *)((int)puVar8 + 0xaf) = *(byte *)((int)puVar8 + 0xaf) | 8;
  *(undefined *)((int)piVar22 + 0x353) = 1;
  (**(code **)((uint)*(byte *)(piVar22 + 2) * 4 + -0x7fce20a4))(puVar8,piVar22);
  piVar22[0x15] = piVar22[0x15] & 0xfffffffd;
  piVar22[6] = (int)((float)piVar22[6] + FLOAT_803dc074);
  if ((FLOAT_803e310c < (float)piVar22[6]) && (iVar11 = piVar22[8], (short)puVar8[0x50] != iVar11))
  {
    if (((piVar22[0x14] & 0x1000000U) == 0) || ((piVar22[0x15] & 0x1000000U) == 0)) {
      FUN_8003042c((double)FLOAT_803e306c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar8,iVar11,0,uVar9,puVar17,uVar18,uVar19,uVar20);
    }
    else {
      FUN_8003042c((double)*(float *)(puVar8 + 0x4c),param_2,param_3,param_4,param_5,param_6,param_7
                   ,param_8,puVar8,iVar11,0,uVar9,puVar17,uVar18,uVar19,uVar20);
    }
    piVar22[0x15] = piVar22[0x15] & 0xf9fffe1f;
    piVar22[0x15] = piVar22[0x15] | piVar22[0x14];
    piVar22[6] = (int)FLOAT_803e306c;
    piVar22[0xd] = piVar22[0xe];
  }
  if ((piVar22[0x15] & 0x2000000U) != 0) {
    *(float *)(puVar8 + 6) =
         FLOAT_803dc074 * (float)piVar22[0xb] * (float)piVar22[5] + *(float *)(puVar8 + 6);
    *(float *)(puVar8 + 10) =
         FLOAT_803dc074 * (float)piVar22[0xc] * (float)piVar22[5] + *(float *)(puVar8 + 10);
    FUN_8002f6cc((double)(float)piVar22[5],(int)puVar8,(float *)(piVar22 + 0xd));
  }
  if ((float)piVar22[0xd] == FLOAT_803e306c) {
    FUN_800303fc((double)(float)piVar22[0xf],(int)puVar8);
  }
  iVar11 = FUN_8002fb40((double)(float)piVar22[0xd],(double)FLOAT_803dc074);
  if (iVar11 == 0) {
    piVar22[0x15] = piVar22[0x15] & 0xf7ffffff;
  }
  else {
    piVar22[0x15] = piVar22[0x15] | 0x8000000;
  }
  if ((piVar22[0x15] & 0x100U) != 0) {
    iVar11 = (int)*(short *)((int)piVar22 + 0x5a) - (uint)*puVar8;
    if (0x8000 < iVar11) {
      iVar11 = iVar11 + -0xffff;
    }
    if (iVar11 < -0x8000) {
      iVar11 = iVar11 + 0xffff;
    }
    uStack_24 = (int)*(short *)((int)piVar22 + 0x81a) ^ 0x80000000;
    local_28 = 0x43300000;
    iVar12 = (int)((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e30f0) *
                  (float)piVar22[0x13]);
    local_20 = (longlong)iVar12;
    iVar7 = iVar11;
    if (iVar11 < 0) {
      iVar7 = -iVar11;
    }
    sVar4 = (short)iVar11;
    if (iVar7 < 4) {
      *puVar8 = *puVar8 + sVar4;
    }
    else {
      sVar5 = (short)iVar12;
      if (((iVar12 < 1) || (iVar11 < 1)) && ((-1 < iVar12 || (-1 < iVar11)))) {
        *puVar8 = *puVar8 + sVar5;
      }
      else {
        if (iVar11 < 0) {
          iVar11 = -iVar11;
        }
        if (iVar12 < 0) {
          iVar12 = -iVar12;
        }
        if (iVar11 < iVar12) {
          *puVar8 = *puVar8 + sVar4;
        }
        else {
          *puVar8 = *puVar8 + sVar5;
        }
      }
    }
  }
  if ((piVar22[0x15] & 0x40U) != 0) {
    *(float *)(puVar8 + 6) =
         (float)piVar22[0x11] * (float)piVar22[0xb] * -(float)piVar22[0x205] +
         *(float *)(puVar8 + 6);
    *(float *)(puVar8 + 10) =
         (float)piVar22[0x11] * (float)piVar22[0xc] * -(float)piVar22[0x205] +
         *(float *)(puVar8 + 10);
  }
  if ((piVar22[0x15] & 0x80U) != 0) {
    *(float *)(puVar8 + 8) = (float)piVar22[0x204] * (float)piVar22[0x12] + *(float *)(puVar8 + 8);
  }
  if ((piVar22[0x15] & 0x20U) != 0) {
    *(float *)(puVar8 + 6) =
         (float)piVar22[0x10] * (float)piVar22[0xc] * (float)piVar22[0x203] + *(float *)(puVar8 + 6)
    ;
    *(float *)(puVar8 + 10) =
         (float)piVar22[0x10] * (float)piVar22[0xb] * -(float)piVar22[0x203] +
         *(float *)(puVar8 + 10);
  }
  if (piVar22[9] == 0) {
    *(undefined *)(piVar22 + 0xde) = 0;
  }
  else {
    *(undefined *)(piVar22 + 0xde) = 1;
    piVar22[0xdf] = *(int *)(piVar22[9] + 0x18);
    piVar22[0xe0] = *(int *)(piVar22[9] + 0x1c);
    piVar22[0xe1] = *(int *)(piVar22[9] + 0x20);
  }
  if (puVar8[0x50] == 0x2a) {
    FUN_8003a260((int)puVar8,(int)(piVar22 + 0xde));
    FUN_8003b320((int)puVar8,(int)(piVar22 + 0xde));
  }
  else {
    FUN_8003a328((double)FLOAT_803e306c,(short *)puVar8,(char *)(piVar22 + 0xde));
    FUN_8003b408((int)puVar8,(int)(piVar22 + 0xde));
  }
  FUN_80039030((int)puVar8,(char *)(piVar22 + 0xea));
  iVar11 = *(int *)(puVar8 + 0x5c);
  puVar13 = *(undefined4 **)(iVar11 + 0x28);
  *(undefined4 **)(iVar11 + 0x6f0) = puVar13;
  if (*(int *)(iVar11 + 0x6f0) != 0) {
    *(undefined4 *)(iVar11 + 0x6f4) = *puVar13;
    *(undefined4 *)(iVar11 + 0x6f8) = puVar13[1];
    *(undefined4 *)(iVar11 + 0x6fc) = puVar13[2];
  }
  piVar22[4] = piVar22[5];
  iVar11 = *(byte *)(piVar22 + 0x1e6) - 1;
  piVar21 = piVar22 + iVar11 * 2;
  for (; -1 < iVar11; iVar11 = iVar11 + -1) {
    *(char *)((int)piVar21 + 0x74e) = *(char *)((int)piVar21 + 0x74e) + -1;
    if (*(char *)((int)piVar21 + 0x74e) == '\0') {
      FUN_8028fa2c((uint)(piVar21 + 0x1d2),(uint)(piVar22 + (iVar11 + 1) * 2 + 0x1d2),
                   (((uint)*(byte *)(piVar22 + 0x1e6) - iVar11) + -1) * 8);
      *(char *)(piVar22 + 0x1e6) = *(char *)(piVar22 + 0x1e6) + -1;
    }
    piVar21 = piVar21 + -2;
  }
  dVar24 = FUN_80021730((float *)(puVar8 + 0xc),(float *)(piVar22[1] + 0x18));
  if (((double)FLOAT_803e31c8 <= dVar24) && (uVar9 = FUN_80020078(0x4e4), uVar9 != 0)) {
    piVar22[0x15] = piVar22[0x15] | 0x10000;
  }
  piVar22[0x1e7] = (int)((float)piVar22[0x1e7] - FLOAT_803dc074);
  if ((float)piVar22[0x1e7] < FLOAT_803e306c) {
    piVar22[0x1e7] = (int)FLOAT_803e306c;
  }
  if ((piVar22[0x15] & 4U) != 0) {
    iVar11 = *(int *)(puVar8 + 0x5c);
    if ((*(byte *)(iVar11 + 0x58) >> 6 & 1) == 0) {
      if (((short)puVar8[0x50] < 0x30) && (0x28 < (short)puVar8[0x50])) {
        bVar15 = false;
      }
      else {
        bVar15 = FUN_8000b598((int)puVar8,0x10);
        if (bVar15) {
          bVar15 = false;
        }
        else {
          FUN_800394f0(puVar8,iVar11 + 0x3a8,0x298,0x500,0xffffffff,0);
          bVar15 = true;
        }
      }
    }
    else {
      bVar15 = false;
    }
    if (bVar15) {
      piVar22[0x15] = piVar22[0x15] & 0xfffffffb;
    }
  }
  piVar22[0x1e8] = (int)((float)piVar22[0x1e8] - FLOAT_803dc074);
  if ((float)piVar22[0x1e8] < FLOAT_803e306c) {
    piVar22[0x1e8] = (int)FLOAT_803e306c;
  }
  if ((((FLOAT_803e306c < (float)piVar22[0x1e8]) &&
       (iVar11 = *(int *)(puVar8 + 0x5c), (*(byte *)(iVar11 + 0x58) >> 6 & 1) == 0)) &&
      ((0x2f < (short)puVar8[0x50] || ((short)puVar8[0x50] < 0x29)))) &&
     (bVar15 = FUN_8000b598((int)puVar8,0x10), !bVar15)) {
    FUN_800394f0(puVar8,iVar11 + 0x3a8,0x29c,0x100,0xffffffff,0);
  }
  FUN_80139724((uint)puVar8);
  if (((piVar22[0x15] & 0x80000000U) != 0) &&
     (piVar22[0x202] = (int)((float)piVar22[0x202] - FLOAT_803dc074),
     (float)piVar22[0x202] <= FLOAT_803e306c)) {
    piVar22[0x15] = piVar22[0x15] & 0x7fffffff;
    uVar9 = FUN_80022264(0,1);
    uVar16 = *(ushort *)((int)&local_bc + uVar9 * 2);
    iVar11 = *(int *)(puVar8 + 0x5c);
    if (((*(byte *)(iVar11 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < (short)puVar8[0x50] || ((short)puVar8[0x50] < 0x29)) &&
        (bVar15 = FUN_8000b598((int)puVar8,0x10), !bVar15)))) {
      FUN_800394f0(puVar8,iVar11 + 0x3a8,uVar16,0x500,0xffffffff,0);
    }
  }
  FUN_80139104((int)puVar8,piVar22);
  FUN_80138ee8((int)puVar8,piVar22);
  if ((double)FLOAT_803e31dc < (double)(float)piVar22[5]) {
    FUN_8006f0b4((double)(float)piVar22[5],(double)FLOAT_803e3078,puVar8,piVar22 + 0x203,1,
                 (int)(piVar22 + 0x1f6),(int)(piVar22 + 0x3e));
  }
  if (FLOAT_803e306c == (float)piVar22[0xab]) {
    bVar15 = false;
  }
  else if (FLOAT_803e30a0 == (float)piVar22[0xac]) {
    bVar15 = true;
  }
  else if ((float)piVar22[0xad] - (float)piVar22[0xac] <= FLOAT_803e30a4) {
    bVar15 = false;
  }
  else {
    bVar15 = true;
  }
  if (bVar15) {
    uVar16 = 0;
    iVar12 = 0;
    iVar11 = (int)*(char *)((int)piVar22 + 0x827);
    if (0 < iVar11) {
      do {
        cVar2 = *(char *)((int)piVar22 + iVar12 + 0x81f);
        if ((cVar2 < '\x03') && (-1 < cVar2)) {
          uVar16 = 0x433;
        }
        iVar12 = iVar12 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
    }
    if (uVar16 != 0) {
      FUN_8000bb38((uint)puVar8,uVar16);
    }
  }
  piVar22[0x23] = *(int *)(puVar8 + 0x40);
  piVar22[0x24] = *(int *)(puVar8 + 0x42);
  piVar22[0x25] = *(int *)(puVar8 + 0x44);
  if (piVar22[0x1ee] != 0) {
    piVar22[0x1f0] = (int)((float)piVar22[0x1f0] + FLOAT_803dc074);
    piVar22[0x1f1] = (int)((float)piVar22[0x1f1] + FLOAT_803dc074);
    piVar22[0x1f2] = (int)((float)piVar22[0x1f2] + FLOAT_803dc074);
    if (FLOAT_803e3158 < (float)piVar22[0x1f2]) {
      piVar22[0x1f2] = (int)((float)piVar22[0x1f2] - FLOAT_803e3158);
    }
    if ((float)piVar22[0x1f2] < FLOAT_803e3098) {
      *(ushort *)(piVar22[0x1ee] + 6) = *(ushort *)(piVar22[0x1ee] + 6) & 0xbfff;
    }
    else {
      *(ushort *)(piVar22[0x1ee] + 6) = *(ushort *)(piVar22[0x1ee] + 6) | 0x4000;
    }
    fVar3 = (float)piVar22[0x1f1];
    if (FLOAT_803e3168 < fVar3) {
      if (FLOAT_803e30d0 < fVar3) {
        piVar22[0x1f1] = (int)(fVar3 - FLOAT_803e30d0);
      }
      *(ushort *)(piVar22[0x1ee] + 6) = *(ushort *)(piVar22[0x1ee] + 6) | 0x4000;
    }
    if (FLOAT_803e31e0 < (float)piVar22[0x1f0]) {
      uVar9 = FUN_80020078(0xc1);
      if (uVar9 == 0) {
        iVar11 = *(int *)(puVar8 + 0x5c);
        if ((((*(byte *)(iVar11 + 0x58) >> 6 & 1) == 0) &&
            ((0x2f < (short)puVar8[0x50] || ((short)puVar8[0x50] < 0x29)))) &&
           (bVar15 = FUN_8000b598((int)puVar8,0x10), !bVar15)) {
          FUN_800394f0(puVar8,iVar11 + 0x3a8,0x298,0x500,0xffffffff,0);
        }
      }
      else {
        iVar11 = *(int *)(puVar8 + 0x5c);
        if (((*(byte *)(iVar11 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < (short)puVar8[0x50] || ((short)puVar8[0x50] < 0x29)) &&
            (bVar15 = FUN_8000b598((int)puVar8,0x10), !bVar15)))) {
          FUN_800394f0(puVar8,iVar11 + 0x3a8,0x392,0x500,0xffffffff,0);
        }
      }
      piVar22[0x1f0] = (int)((float)piVar22[0x1f0] - FLOAT_803e31e0);
    }
    FUN_8002fb40((double)FLOAT_803e307c,(double)FLOAT_803dc074);
  }
  if (piVar22[0x1ec] != 0) {
    FUN_8002fb40((double)FLOAT_803e307c,(double)FLOAT_803dc074);
  }
  if (piVar22[0x1ea] != 0) {
    FUN_8002fb40((double)FLOAT_803e307c,(double)FLOAT_803dc074);
  }
  FUN_80286888();
  return;
}

