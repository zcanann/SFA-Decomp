// Function: FUN_802b2da4
// Entry: 802b2da4
// Size: 7416 bytes

/* WARNING: Removing unreachable block (ram,0x802b4a74) */
/* WARNING: Removing unreachable block (ram,0x802b4a6c) */
/* WARNING: Removing unreachable block (ram,0x802b4a7c) */

void FUN_802b2da4(undefined4 param_1,undefined4 param_2,int param_3,char param_4)

{
  float fVar1;
  ushort uVar2;
  float fVar3;
  bool bVar4;
  short sVar5;
  char cVar6;
  undefined2 *puVar7;
  short *psVar8;
  int iVar9;
  char cVar15;
  undefined4 uVar10;
  float *pfVar11;
  undefined2 uVar14;
  int *piVar12;
  int iVar13;
  short *psVar16;
  int iVar17;
  int iVar18;
  int unaff_r27;
  undefined4 uVar19;
  int iVar20;
  undefined4 uVar21;
  double dVar22;
  undefined8 in_f29;
  double dVar23;
  undefined8 in_f30;
  double dVar24;
  undefined8 in_f31;
  double dVar25;
  double dVar26;
  undefined8 uVar27;
  float local_e8;
  int local_e4;
  undefined auStack224 [4];
  undefined auStack220 [4];
  undefined auStack216 [4];
  float local_d4;
  float local_d0;
  float local_cc;
  undefined4 local_c8;
  uint uStack196;
  longlong local_c0;
  undefined4 local_b8;
  uint uStack180;
  undefined4 local_b0;
  uint uStack172;
  longlong local_a8;
  undefined4 local_a0;
  uint uStack156;
  undefined4 local_98;
  uint uStack148;
  longlong local_90;
  undefined4 local_88;
  uint uStack132;
  double local_80;
  undefined4 local_78;
  uint uStack116;
  double local_70;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar21 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar27 = FUN_802860c4();
  puVar7 = (undefined2 *)((ulonglong)uVar27 >> 0x20);
  psVar16 = (short *)uVar27;
  iVar18 = *(int *)(psVar16 + 0x26);
  iVar20 = *(int *)(puVar7 + 0x5c);
  uVar19 = 0;
  psVar8 = (short *)FUN_800395d8(puVar7,0);
  iVar9 = FUN_800395d8(puVar7,9);
  *(code **)(param_3 + 0xe8) = FUN_802a93f4;
  if (DAT_803de450 != 0) {
    FUN_80170380(DAT_803de450,0);
  }
  FUN_802b07d8(puVar7,iVar20);
  if ((DAT_803de448 == 0) && (cVar15 = FUN_8002e04c(), cVar15 != '\0')) {
    uVar10 = FUN_8002bdf4(0x18,0x66a);
    DAT_803de448 = FUN_8002df90(uVar10,4,0xffffffff,0xffffffff,*(undefined4 *)(puVar7 + 0x18));
    FUN_80037d2c(puVar7,DAT_803de448,3);
  }
  if ((DAT_803de448 != 0) &&
     (*(undefined4 *)(DAT_803de448 + 0x30) = *(undefined4 *)(puVar7 + 0x18),
     *(short *)(iVar20 + 0x81a) == 0)) {
    *(ushort *)(DAT_803de448 + 6) = *(ushort *)(DAT_803de448 + 6) | 0x4000;
  }
  if ((DAT_803de450 == 0) && (cVar15 = FUN_8002e04c(), cVar15 != '\0')) {
    uVar10 = FUN_8002bdf4(0x24,0x773);
    DAT_803de450 = FUN_8002df90(uVar10,5,0xffffffff,0xffffffff,*(undefined4 *)(puVar7 + 0x18));
  }
  if (DAT_803de450 != 0) {
    FUN_8003842c(puVar7,4,DAT_803de450 + 0xc,DAT_803de450 + 0x10,DAT_803de450 + 0x14,0);
  }
  if ((((*(byte *)(iVar20 + 0x3f3) >> 3 & 1) != 0) || (*(short *)(iVar20 + 0x80a) == 0x40)) &&
     (-1 < *(char *)(iVar20 + 0x3f4))) {
    FUN_80295e90(puVar7,0);
    *(undefined2 *)(iVar20 + 0x80a) = 0xffff;
  }
  FUN_80035f00(puVar7);
  *(uint *)(iVar20 + 0x360) = *(uint *)(iVar20 + 0x360) & 0xfffffffd;
  if (*(char *)(param_3 + 0x56) == '\0') {
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) | *(ushort *)(param_3 + 0x70) & 0xfbff
    ;
    *(undefined *)(iVar20 + 0x34c) = 0;
    fVar1 = FLOAT_803e7ea4;
    *(float *)(iVar20 + 0x290) = FLOAT_803e7ea4;
    *(float *)(iVar20 + 0x28c) = fVar1;
    *(undefined2 *)(iVar20 + 0x330) = 0;
    *(undefined4 *)(iVar20 + 0x31c) = 0;
    *(undefined4 *)(iVar20 + 0x318) = 0;
    if ((*(ushort *)(param_3 + 0x6e) & 1) != 0) {
      *(uint *)(iVar20 + 4) = *(uint *)(iVar20 + 4) | 0x100000;
      *(undefined *)(iVar20 + 0x25f) = 0;
    }
    for (iVar9 = 0; iVar9 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar9 = iVar9 + 1) {
      switch(*(undefined *)(param_3 + iVar9 + 0x81)) {
      case 1:
        if (*(int *)(iVar20 + 0x684) != 0) {
          FUN_800378c4(*(int *)(iVar20 + 0x684),0x7000b,puVar7,0);
          *(undefined4 *)(iVar20 + 0x684) = 0;
        }
        break;
      case 2:
        iVar18 = FUN_802957b4(puVar7);
        if (iVar18 != 0) {
          *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) | 4;
        }
        break;
      case 3:
        piVar12 = (int *)FUN_80036f50(10,&local_e4);
        bVar4 = false;
        dVar23 = (double)FLOAT_803e80ac;
        for (iVar18 = 0; iVar18 < local_e4; iVar18 = iVar18 + 1) {
          iVar17 = *piVar12;
          if (((iVar17 != 0) &&
              (iVar13 = FUN_8007fe74(&DAT_80332ffc,9,(int)*(short *)(iVar17 + 0x46)), iVar13 != -1))
             && ((dVar24 = (double)FUN_800216d0(iVar17 + 0x18,puVar7 + 0xc), dVar24 < dVar23 ||
                 (!bVar4)))) {
            *(int *)(iVar20 + 0x7f0) = iVar17;
            bVar4 = true;
            dVar23 = dVar24;
          }
          piVar12 = piVar12 + 1;
        }
        if (bVar4) {
          *(float *)(iVar20 + 0x6a4) = FLOAT_803e7ee0;
          *(undefined4 *)(iVar20 + 0x6a8) = *(undefined4 *)(iVar20 + 0x768);
          *(undefined4 *)(iVar20 + 0x6ac) = *(undefined4 *)(iVar20 + 0x76c);
          *(undefined4 *)(iVar20 + 0x6b0) = *(undefined4 *)(iVar20 + 0x770);
          iVar18 = *(int *)(iVar20 + 0x7f0);
          (**(code **)(**(int **)(iVar18 + 0x68) + 0x3c))(iVar18,2);
          puVar7[3] = puVar7[3] | 8;
          *(uint *)(*(int *)(puVar7 + 0x32) + 0x30) =
               *(uint *)(*(int *)(puVar7 + 0x32) + 0x30) | 0x1000;
          *(undefined2 *)(*(int *)(puVar7 + 0x32) + 0x36) = 0;
          *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffb;
          sVar5 = *(short *)(iVar18 + 0x46);
          if (sVar5 == 0x416) {
            FUN_8000a518(0xd5,1);
            *(short **)(iVar20 + 0x6e8) = &DAT_803332f8;
            *(undefined *)(iVar20 + 0x6ec) = 8;
            FUN_80030334((double)FLOAT_803e7ea4,puVar7,(int)DAT_803332f8,1);
          }
          else if (sVar5 < 0x416) {
            if (sVar5 == 0x8c) {
              *(undefined **)(iVar20 + 0x6e8) = &DAT_803332c8;
              *(undefined *)(iVar20 + 0x6ec) = 4;
              FUN_80030334((double)FLOAT_803e7ea4,puVar7,0x7b,1);
              iVar17 = FUN_801e1da8();
              if (iVar17 != 0) {
                (**(code **)(*DAT_803dca50 + 0x28))(iVar18,0);
                (**(code **)(*DAT_803dca54 + 0x50))(0x4a,1,0,0x78);
              }
            }
            else {
              if (sVar5 < 0x8c) {
                if (sVar5 == 0x72) {
LAB_802b3d58:
                  FUN_8000a518(0x97,1);
                  FUN_800200e8(0xc1f,0);
                  *(undefined **)(iVar20 + 0x6e8) = &DAT_803332b0;
                  *(undefined *)(iVar20 + 0x6ec) = 3;
                  FUN_80030334((double)FLOAT_803e7ea4,puVar7,0x17,1);
                  goto LAB_802b3ed8;
                }
              }
              else if (sVar5 == 0x38c) goto LAB_802b3d58;
LAB_802b3ea8:
              FUN_8000a518(0x1f,1);
LAB_802b3eb4:
              *(undefined **)(iVar20 + 0x6e8) = &DAT_803332e0;
              *(undefined *)(iVar20 + 0x6ec) = 4;
              FUN_80030334((double)FLOAT_803e7ea4,puVar7,0xf8,1);
            }
          }
          else if (sVar5 == 0x484) {
            FUN_8000a518(0xe6,1);
            *(undefined **)(iVar20 + 0x6e8) = &DAT_803332e0;
            *(undefined *)(iVar20 + 0x6ec) = 4;
            FUN_80030334((double)FLOAT_803e7ea4,puVar7,0xf8,1);
          }
          else {
            if (0x483 < sVar5) {
              if (sVar5 != 0x714) goto LAB_802b3ea8;
              goto LAB_802b3eb4;
            }
            if (sVar5 != 0x419) goto LAB_802b3ea8;
            FUN_8000a518(0xe6,1);
            *(undefined **)(iVar20 + 0x6e8) = &DAT_803332c8;
            *(undefined *)(iVar20 + 0x6ec) = 4;
            FUN_80030334((double)FLOAT_803e7ea4,puVar7,0x7b,1);
          }
LAB_802b3ed8:
          iVar18 = FUN_8007fe74(&DAT_80333020,4,(int)*(short *)(iVar18 + 0x46));
          if (iVar18 == -1) {
            (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar20,0x18);
            *(code **)(iVar20 + 0x304) = FUN_8029f67c;
          }
          else {
            (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar20,0x1a);
            *(code **)(iVar20 + 0x304) = FUN_8029f67c;
          }
        }
        break;
      case 4:
        iVar18 = *(int *)(iVar20 + 0x7f0);
        (**(code **)(*DAT_803dca50 + 0x28))(iVar18,0);
        (**(code **)(*DAT_803dca54 + 0x50))(0x45,0,0,0);
        *(undefined4 *)(iVar20 + 0x6e8) = 0;
        if ((iVar18 == 0) || (*(short *)(iVar18 + 0x46) != 0x22)) {
          (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar20,0x18);
          *(code **)(iVar20 + 0x304) = FUN_8029f67c;
        }
        else {
          (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar20,0x16);
          *(undefined4 *)(iVar20 + 0x304) = 0;
        }
        break;
      case 6:
        (**(code **)(*DAT_803dca54 + 0x50))(0x44,0,0,0);
        (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar20,0x17);
        *(undefined4 *)(iVar20 + 0x304) = 0;
        break;
      case 7:
        *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffc;
        iVar18 = *(int *)(puVar7 + 0x5c);
        (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar18,0x3e);
        *(undefined4 *)(iVar18 + 0x304) = 0;
        *(uint *)(iVar18 + 0x360) = *(uint *)(iVar18 + 0x360) | 1;
        puVar7[3] = puVar7[3] | 8;
        break;
      case 8:
        *(undefined2 *)(param_3 + 0x6e) = *(undefined2 *)(param_3 + 0x70);
        iVar18 = *(int *)(puVar7 + 0x5c);
        (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar18,1);
        *(code **)(iVar18 + 0x304) = FUN_802a514c;
        *(uint *)(iVar18 + 0x360) = *(uint *)(iVar18 + 0x360) & 0xfffffffe;
        puVar7[3] = puVar7[3] & 0xfff7;
        break;
      case 10:
        if ((DAT_803de44c != 0) && ((*(byte *)(iVar20 + 0x3f4) >> 6 & 1) != 0)) {
          *(undefined *)(iVar20 + 0x8b4) = 2;
          *(byte *)(iVar20 + 0x3f4) = *(byte *)(iVar20 + 0x3f4) & 0xf7;
        }
        break;
      case 0xb:
        iVar18 = *(int *)(iVar20 + 0x7f0);
        if ((iVar18 == 0) || (*(short *)(iVar18 + 0x46) != 0x416)) {
          if ((iVar18 == 0) ||
             (iVar18 = FUN_8007fe74(&DAT_80333020,4,(int)*(short *)(iVar18 + 0x46)), iVar18 == -1))
          {
            (**(code **)(*DAT_803dca50 + 0x24))(0,0x1d,0);
            (**(code **)(*DAT_803dca54 + 0x50))(0x42,4,0,0);
          }
          else {
            (**(code **)(*DAT_803dca54 + 0x50))(0x53,0,0,0);
          }
        }
        else {
          (**(code **)(*DAT_803dca50 + 0x28))(iVar18,0);
          (**(code **)(*DAT_803dca50 + 0x24))(0,0x69,0);
          (**(code **)(*DAT_803dca54 + 0x50))(0x42,4,0,0);
        }
        break;
      case 0xd:
        (**(code **)(*DAT_803dca54 + 0x7c))
                  ((int)*(short *)(*(int *)(puVar7 + 0x62) + 0x46),*(int *)(puVar7 + 0x62),0);
        iVar18 = *(int *)(puVar7 + 0x62);
        iVar17 = *(int *)(iVar18 + 0xb8);
        if (*(int *)(iVar18 + 0x54) == 0) {
          fVar1 = *(float *)(iVar18 + 0xa8) * *(float *)(iVar18 + 8);
        }
        else {
          local_70 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(*(int *)(iVar18 + 0x54) + 0x5a) ^ 0x80000000);
          fVar1 = (float)(local_70 - DOUBLE_803e7ec0);
        }
        dVar26 = (double)fVar1;
        dVar24 = (double)((*(float *)(*(int *)(iVar18 + 0x74) + 4) - *(float *)(iVar18 + 0x10)) -
                         FLOAT_803e8158);
        uStack116 = (int)*(short *)(iVar17 + 0x478) ^ 0x80000000;
        local_78 = 0x43300000;
        dVar23 = (double)FUN_80294204((double)((FLOAT_803e7f94 *
                                               (float)((double)CONCAT44(0x43300000,uStack116) -
                                                      DOUBLE_803e7ec0)) / FLOAT_803e7f98));
        dVar25 = (double)(float)(dVar26 * -dVar23);
        local_80 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar17 + 0x478) ^ 0x80000000);
        dVar23 = (double)FUN_80293e80((double)((FLOAT_803e7f94 * (float)(local_80 - DOUBLE_803e7ec0)
                                               ) / FLOAT_803e7f98));
        (**(code **)(*DAT_803dca54 + 0x80))((double)(float)(dVar26 * -dVar23),dVar24,dVar25);
        (**(code **)(*DAT_803dca54 + 0x48))(*(undefined4 *)(puVar7 + 0x7a),puVar7,0xffffffff);
        break;
      case 0xf:
        FUN_80062e84(puVar7,0,1);
        break;
      case 0x10:
        local_e8 = FLOAT_803e815c;
        iVar18 = FUN_80036e58(6,puVar7,&local_e8);
        if (iVar18 != 0) {
          FUN_80062e84(puVar7,iVar18,1);
        }
        break;
      case 0x12:
        *(uint *)(iVar20 + 0x360) = *(uint *)(iVar20 + 0x360) | 0x8000;
        break;
      case 0x13:
        FUN_80014948(1);
        break;
      case 0x14:
        *(uint *)(iVar20 + 0x360) = *(uint *)(iVar20 + 0x360) | 0x40000;
        break;
      case 0x15:
        *(uint *)(iVar20 + 0x360) = *(uint *)(iVar20 + 0x360) & 0xfffbffff;
        break;
      case 0x16:
        *(uint *)(iVar20 + 0x360) = *(uint *)(iVar20 + 0x360) | 0x20000;
        break;
      case 0x17:
        iVar18 = *(int *)(puVar7 + 0x5c);
        if (*(int *)(iVar18 + 0x7f8) != 0) {
          *(undefined *)(iVar18 + 0x800) = 0;
          if (*(int *)(iVar18 + 0x7f8) != 0) {
            sVar5 = *(short *)(*(int *)(iVar18 + 0x7f8) + 0x46);
            if ((sVar5 == 0x3cf) || (sVar5 == 0x662)) {
              FUN_80182504();
            }
            else {
              FUN_800ea774();
            }
            *(ushort *)(*(int *)(iVar18 + 0x7f8) + 6) =
                 *(ushort *)(*(int *)(iVar18 + 0x7f8) + 6) & 0xbfff;
            *(undefined4 *)(*(int *)(iVar18 + 0x7f8) + 0xf8) = 0;
            *(undefined4 *)(iVar18 + 0x7f8) = 0;
          }
          *(uint *)(iVar18 + 0x360) = *(uint *)(iVar18 + 0x360) | 0x800000;
          (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar18,1);
          *(code **)(iVar18 + 0x304) = FUN_802a514c;
        }
        break;
      case 0x18:
        if ((DAT_803de44c != 0) && ((*(byte *)(iVar20 + 0x3f4) >> 6 & 1) != 0)) {
          *(undefined *)(iVar20 + 0x8b4) = 0;
          *(byte *)(iVar20 + 0x3f4) = *(byte *)(iVar20 + 0x3f4) & 0xf7;
        }
        break;
      case 0x19:
        (**(code **)(*DAT_803dcaac + 0x28))();
        break;
      case 0x1a:
        if (*(int *)(iVar20 + 0x684) != 0) {
          iVar17 = *(int *)(*(int *)(iVar20 + 0x684) + 0x50);
          iVar18 = (int)*(short *)(iVar17 + 0x7a);
          if (iVar18 < 0) {
            (**(code **)(*DAT_803dca68 + 0x38))((int)*(short *)(iVar17 + 0x7c),0x154,300,0);
          }
          else {
            (**(code **)(*DAT_803dca68 + 0x38))(iVar18,0x154,300,0);
          }
        }
        break;
      case 0x1c:
        FUN_80295cf4(puVar7,0);
        break;
      case 0x1d:
        (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar20,0x1a);
        *(code **)(iVar20 + 0x304) = FUN_8029f67c;
        break;
      case 0x1e:
        (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar20,1);
        *(code **)(iVar20 + 0x304) = FUN_802a514c;
        break;
      case 0x1f:
        FUN_80026c48(DAT_803de420);
        FUN_80026c30(DAT_803de420,1);
        break;
      case 0x20:
        FUN_80026c30(DAT_803de420,0);
        break;
      case 0x21:
        DAT_803dc66c = '\x02';
        break;
      case 0x22:
        DAT_803dc66c = '\x01';
        break;
      case 0x25:
        *(ushort *)(iVar20 + 0x8d8) = *(ushort *)(iVar20 + 0x8d8) ^ 1;
        break;
      case 0x26:
        *(ushort *)(iVar20 + 0x8d8) = *(ushort *)(iVar20 + 0x8d8) ^ 2;
        break;
      case 0x27:
        FUN_8011f38c(1);
        break;
      case 0x28:
        iVar18 = FUN_8005afac((double)*(float *)(puVar7 + 6),(double)*(float *)(puVar7 + 10));
        if (iVar18 == 0xd) {
          unaff_r27 = 0x18;
        }
        else if (iVar18 < 0xd) {
          if (iVar18 == 2) {
            unaff_r27 = 0x1c;
          }
          else if ((1 < iVar18) && (0xb < iVar18)) {
            unaff_r27 = 0x14;
          }
        }
        else if (iVar18 == 0x13) {
          unaff_r27 = 0x10;
        }
        if ((int)*(char *)(*(int *)(*(int *)(puVar7 + 0x5c) + 0x35c) + 1) <= unaff_r27 + -4) {
          if (unaff_r27 < 0) {
            cVar15 = '\0';
          }
          else {
            cVar15 = (char)unaff_r27;
            if (0x50 < unaff_r27) {
              cVar15 = 'P';
            }
          }
          *(char *)(*(int *)(*(int *)(puVar7 + 0x5c) + 0x35c) + 1) = cVar15;
          if (unaff_r27 < 0) {
            cVar6 = '\0';
          }
          else {
            cVar15 = *(char *)(*(int *)(*(int *)(puVar7 + 0x5c) + 0x35c) + 1);
            cVar6 = (char)unaff_r27;
            if (cVar15 < unaff_r27) {
              cVar6 = cVar15;
            }
          }
          **(char **)(*(int *)(puVar7 + 0x5c) + 0x35c) = cVar6;
        }
        break;
      case 0x29:
        FUN_8011f38c(0);
        break;
      case 0x2a:
        cVar15 = (**(code **)(*DAT_803dcaac + 0x40))(0xb);
        if (cVar15 == '\a') {
          FUN_80008b74(puVar7,puVar7,0x1fb,0);
          FUN_80008b74(puVar7,puVar7,0x1ff,0);
          FUN_80008b74(puVar7,puVar7,0x249,0);
          FUN_80008b74(puVar7,puVar7,0x1fd,0);
        }
        else {
          FUN_80008b74(puVar7,puVar7,0x217,0);
          FUN_80008b74(puVar7,puVar7,0x216,0);
          FUN_80008b74(puVar7,puVar7,0x22e,0);
          FUN_80008b74(puVar7,puVar7,0x218,0);
          FUN_80008b74(puVar7,puVar7,0x84,0);
          FUN_80008b74(puVar7,puVar7,0x8a,0);
        }
        FUN_80088e54((double)FLOAT_803e7ea4,0);
        break;
      case 0x2b:
        *(uint *)(*(int *)(puVar7 + 0x32) + 0x30) =
             *(uint *)(*(int *)(puVar7 + 0x32) + 0x30) & 0xfffffffb;
        break;
      case 0x2c:
        *(uint *)(*(int *)(puVar7 + 0x32) + 0x30) = *(uint *)(*(int *)(puVar7 + 0x32) + 0x30) | 4;
        break;
      case 0x2d:
        FUN_800550ac(1);
        break;
      case 0x2e:
        FUN_800550ac(0);
        break;
      case 0x31:
        FUN_800969a4();
        break;
      case 0x32:
        FUN_8000fc34();
        FUN_80096994();
      }
    }
    if ((*(uint *)(*(int *)(puVar7 + 0x5c) + 0x360) & 1) != 0) {
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffc;
    }
  }
  else {
    *(uint *)(iVar20 + 0x360) = *(uint *)(iVar20 + 0x360) & 0xfffffbff;
    fVar1 = FLOAT_803e7ea4;
    *(float *)(iVar20 + 0x79c) = FLOAT_803e7ea4;
    *(float *)(iVar20 + 0x7a0) = fVar1;
    if (-1 < *(char *)(iVar20 + 0x3f2)) {
      if ((DAT_803de44c != 0) && ((*(byte *)(iVar20 + 0x3f4) >> 6 & 1) != 0)) {
        *(undefined *)(iVar20 + 0x8b4) = 1;
        *(byte *)(iVar20 + 0x3f4) = *(byte *)(iVar20 + 0x3f4) & 0xf7 | 8;
      }
      *(undefined *)(iVar20 + 0x800) = 0;
      if (*(int *)(iVar20 + 0x7f8) != 0) {
        sVar5 = *(short *)(*(int *)(iVar20 + 0x7f8) + 0x46);
        if ((sVar5 == 0x3cf) || (sVar5 == 0x662)) {
          FUN_80182504();
        }
        else {
          FUN_800ea774();
        }
        *(ushort *)(*(int *)(iVar20 + 0x7f8) + 6) =
             *(ushort *)(*(int *)(iVar20 + 0x7f8) + 6) & 0xbfff;
        *(undefined4 *)(*(int *)(iVar20 + 0x7f8) + 0xf8) = 0;
        *(undefined4 *)(iVar20 + 0x7f8) = 0;
      }
    }
    if (((*(char *)(iVar18 + 0x20) == '\0') ||
        (cVar15 = *(char *)(param_3 + 0x56), cVar15 == '\x03')) || (cVar15 == '\x02')) {
      *(undefined2 *)(param_3 + 0x6e) = *(undefined2 *)(param_3 + 0x70);
      if (*(char *)(param_3 + 0x56) != '\x02') {
        *(float *)(param_3 + 0x4c) = FLOAT_803e7ee0;
        *(float *)(param_3 + 0x40) = *(float *)(puVar7 + 6) - *(float *)(psVar16 + 6);
        *(float *)(param_3 + 0x44) = *(float *)(puVar7 + 8) - *(float *)(psVar16 + 8);
        *(float *)(param_3 + 0x48) = *(float *)(puVar7 + 10) - *(float *)(psVar16 + 10);
        *(short *)(param_3 + 0x50) = *(short *)(iVar20 + 0x478) - *psVar16;
        if (0x8000 < *(short *)(param_3 + 0x50)) {
          *(short *)(param_3 + 0x50) = *(short *)(param_3 + 0x50) + 1;
        }
        if (*(short *)(param_3 + 0x50) < -0x8000) {
          *(short *)(param_3 + 0x50) = *(short *)(param_3 + 0x50) + -1;
        }
        *(short *)(param_3 + 0x52) = puVar7[1] - psVar16[1];
        if (0x8000 < *(short *)(param_3 + 0x52)) {
          *(short *)(param_3 + 0x52) = *(short *)(param_3 + 0x52) + 1;
        }
        if (*(short *)(param_3 + 0x52) < -0x8000) {
          *(short *)(param_3 + 0x52) = *(short *)(param_3 + 0x52) + -1;
        }
        *(short *)(param_3 + 0x54) = psVar16[2] - puVar7[2];
        if (0x8000 < *(short *)(param_3 + 0x54)) {
          *(short *)(param_3 + 0x54) = *(short *)(param_3 + 0x54) + 1;
        }
        if (*(short *)(param_3 + 0x54) < -0x8000) {
          *(short *)(param_3 + 0x54) = *(short *)(param_3 + 0x54) + -1;
        }
        *(undefined *)(param_3 + 0x56) = 2;
      }
      *(float *)(param_3 + 0x4c) =
           -(*(float *)(param_3 + 0x24) * FLOAT_803db414 - *(float *)(param_3 + 0x4c));
      if (*(float *)(param_3 + 0x4c) <= FLOAT_803e7ea4) {
        *(undefined *)(param_3 + 0x56) = 0;
      }
      puVar7[0x51] = 0xffff;
      *(undefined2 *)(iVar20 + 0x4d2) = 0;
      *(undefined2 *)(iVar20 + 0x4d0) = 0;
      *(undefined2 *)(iVar20 + 0x4d4) = 0;
      *(undefined2 *)(iVar20 + 0x4d6) = 0;
    }
    else if (cVar15 == '\x04') {
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffb3;
      *(ushort *)(param_3 + 0x70) = *(ushort *)(param_3 + 0x70) & 0xffb7;
      iVar9 = FUN_80080234();
      iVar18 = FUN_800395d8(iVar9,0);
      if (iVar18 == 0) {
        pfVar11 = *(float **)(iVar9 + 0x74);
        if (pfVar11 == (float *)0x0) {
          local_d4 = *(float *)(iVar9 + 0x18);
          local_d0 = *(float *)(iVar9 + 0x1c);
          local_cc = *(float *)(iVar9 + 0x20);
        }
        else {
          local_d4 = *pfVar11;
          local_d0 = pfVar11[1];
          local_cc = pfVar11[2];
        }
      }
      else {
        FUN_80039510(iVar9,0,&local_d4);
      }
      FUN_8003842c(puVar7,5,auStack224,auStack220,auStack216,0);
      dVar23 = (double)(*(float *)(puVar7 + 0xc) - local_d4);
      dVar24 = (double)((*(float *)(iVar20 + 0x7dc) + *(float *)(puVar7 + 0xe)) - local_d0);
      dVar25 = (double)(*(float *)(puVar7 + 0x10) - local_cc);
      DAT_803de4b0 = FUN_800217c0(dVar23,dVar25);
      iVar9 = (int)DAT_803de4b0 - ((int)*(short *)(iVar20 + 0x478) & 0xffffU);
      if (0x8000 < iVar9) {
        iVar9 = iVar9 + -0xffff;
      }
      if (iVar9 < -0x8000) {
        iVar9 = iVar9 + 0xffff;
      }
      *(short *)(iVar20 + 0x4d8) = -psVar8[1];
      *(short *)(iVar20 + 0x4dc) = -*psVar8;
      sVar5 = (short)iVar9;
      if (iVar9 < 0) {
        if (iVar9 < -0x2aaa) {
          *(undefined2 *)(iVar20 + 0x4da) = 0x2aaa;
          *(short *)(iVar20 + 0x4e0) = sVar5 + 0x2aaa;
        }
        else {
          *(short *)(iVar20 + 0x4da) = -sVar5;
          *(undefined2 *)(iVar20 + 0x4e0) = 0;
        }
      }
      else if (iVar9 < 0x2aab) {
        *(short *)(iVar20 + 0x4da) = -sVar5;
        *(undefined2 *)(iVar20 + 0x4e0) = 0;
      }
      else {
        *(undefined2 *)(iVar20 + 0x4da) = 0xd556;
        *(short *)(iVar20 + 0x4e0) = sVar5 + -0x2aaa;
      }
      uVar27 = FUN_802931a0((double)(float)(dVar23 * dVar23 + (double)(float)(dVar25 * dVar25)));
      uVar14 = FUN_800217c0(dVar24,uVar27);
      *(undefined2 *)(iVar20 + 0x4de) = uVar14;
      sVar5 = *(short *)(iVar20 + 0x4de);
      if (sVar5 < -0x1000) {
        sVar5 = -0x1000;
      }
      else if (0x1000 < sVar5) {
        sVar5 = 0x1000;
      }
      *(short *)(iVar20 + 0x4de) = sVar5;
      *(undefined2 *)(param_3 + 0x54) = 0;
      *(float *)(param_3 + 0x4c) = FLOAT_803e7ea4;
      *(float *)(param_3 + 0x24) = FLOAT_803e8154;
      *(undefined *)(param_3 + 0x56) = 5;
      if (*(int *)(iVar20 + 0x7f8) == 0) {
        iVar9 = 0;
      }
      else {
        iVar9 = 8;
      }
      if ((short)puVar7[0x50] != iVar9) {
        FUN_80030334((double)FLOAT_803e7ea4,puVar7,iVar9,0);
        FUN_8002f574(puVar7,1);
      }
      FUN_8002fa48((double)FLOAT_803e7f78,(double)FLOAT_803db414,puVar7,0);
      uVar19 = 1;
    }
    else if (cVar15 == '\x05') {
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffb3;
      *(ushort *)(param_3 + 0x70) = *(ushort *)(param_3 + 0x70) & 0xffb7;
      FUN_80035f20(puVar7);
      if ((*(float *)(param_3 + 0x4c) < FLOAT_803e7ee0) ||
         (iVar18 = (**(code **)(*DAT_803dca50 + 0x50))(), iVar18 != 0)) {
        fVar1 = *(float *)(param_3 + 0x4c);
        *(float *)(param_3 + 0x4c) = *(float *)(param_3 + 0x24) * FLOAT_803db414 + fVar1;
        if (FLOAT_803e7ee0 < *(float *)(param_3 + 0x4c)) {
          *(float *)(param_3 + 0x4c) = FLOAT_803e7ee0;
        }
        uStack196 = (int)*(short *)(iVar20 + 0x4e0) ^ 0x80000000;
        local_c8 = 0x43300000;
        iVar18 = (int)((*(float *)(param_3 + 0x4c) - fVar1) *
                      (float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803e7ec0));
        local_c0 = (longlong)iVar18;
        *(short *)(iVar20 + 0x478) = *(short *)(iVar20 + 0x478) + (short)iVar18;
        *(undefined2 *)(iVar20 + 0x484) = *(undefined2 *)(iVar20 + 0x478);
        *puVar7 = *(undefined2 *)(iVar20 + 0x478);
        uStack180 = (int)*(short *)(iVar20 + 0x4d8) - ((int)*(short *)(iVar20 + 0x4da) & 0xffffU);
        if (0x8000 < (int)uStack180) {
          uStack180 = uStack180 - 0xffff;
        }
        if ((int)uStack180 < -0x8000) {
          uStack180 = uStack180 + 0xffff;
        }
        uStack180 = uStack180 ^ 0x80000000;
        local_b8 = 0x43300000;
        uStack172 = (int)*(short *)(iVar20 + 0x4d8) ^ 0x80000000;
        local_b0 = 0x43300000;
        iVar18 = (int)((float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803e7ec0) *
                       *(float *)(param_3 + 0x4c) +
                      (float)((double)CONCAT44(0x43300000,uStack172) - DOUBLE_803e7ec0));
        local_a8 = (longlong)iVar18;
        psVar8[1] = (short)iVar18;
        dVar23 = DOUBLE_803e7ec0;
        uStack156 = (int)*(short *)(iVar20 + 0x4dc) - ((int)*(short *)(iVar20 + 0x4de) & 0xffffU);
        if (0x8000 < (int)uStack156) {
          uStack156 = uStack156 - 0xffff;
        }
        if ((int)uStack156 < -0x8000) {
          uStack156 = uStack156 + 0xffff;
        }
        uStack156 = uStack156 ^ 0x80000000;
        local_a0 = 0x43300000;
        uStack148 = (int)*(short *)(iVar20 + 0x4dc) ^ 0x80000000;
        local_98 = 0x43300000;
        iVar18 = (int)((float)((double)CONCAT44(0x43300000,uStack156) - DOUBLE_803e7ec0) *
                       *(float *)(param_3 + 0x4c) +
                      (float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e7ec0));
        local_90 = (longlong)iVar18;
        *psVar8 = (short)iVar18;
        fVar1 = FLOAT_803e7ee0;
        uStack132 = (int)*(short *)(iVar20 + 0x4d2) ^ 0x80000000;
        local_88 = 0x43300000;
        iVar18 = (int)((float)((double)CONCAT44(0x43300000,uStack132) - dVar23) *
                      (FLOAT_803e7ee0 - *(float *)(param_3 + 0x4c)));
        local_80 = (double)(longlong)iVar18;
        *(short *)(iVar9 + 2) = (short)iVar18;
        uStack116 = (int)*(short *)(iVar20 + 0x4d0) ^ 0x80000000;
        local_78 = 0x43300000;
        iVar18 = (int)((float)((double)CONCAT44(0x43300000,uStack116) - dVar23) *
                      (fVar1 - *(float *)(param_3 + 0x4c)));
        local_70 = (double)(longlong)iVar18;
        *(short *)(iVar9 + 4) = (short)iVar18;
        uVar2 = *(ushort *)(iVar9 + 4);
        puVar7[2] = ((short)uVar2 >> 2) + (ushort)((short)uVar2 < 0 && (uVar2 & 3) != 0);
        *(short *)(iVar20 + 0x4d4) = psVar8[1];
        *(short *)(iVar20 + 0x4d6) = -*psVar8;
      }
      else {
        *(undefined2 *)(iVar20 + 0x4d2) = 0;
        *(undefined2 *)(iVar20 + 0x4d0) = 0;
        if (param_4 == '\0') {
          *(undefined *)(param_3 + 0x56) = 0;
        }
        else {
          *(undefined *)(param_3 + 0x56) = 6;
        }
        if (*(int *)(iVar20 + 0x7f0) == 0) {
          (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar20,1);
          *(code **)(iVar20 + 0x304) = FUN_802a514c;
          *(undefined2 *)(iVar20 + 0x276) = 1;
        }
        else {
          (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar20,0x18);
          *(code **)(iVar20 + 0x304) = FUN_8029f67c;
        }
      }
      FUN_8002fa48((double)FLOAT_803e7f78,(double)FLOAT_803db414,puVar7,0);
      uVar19 = 1;
    }
    else if (cVar15 == '\x06') {
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffb3;
      *(ushort *)(param_3 + 0x70) = *(ushort *)(param_3 + 0x70) & 0xffb7;
      FUN_80035f20(puVar7);
      if (param_4 == '\0') {
        *(undefined *)(param_3 + 0x56) = 0;
      }
      FUN_8002fa48((double)FLOAT_803e7f78,(double)FLOAT_803db414,puVar7,0);
      uVar19 = 0;
    }
    else {
      if (cVar15 != '\x01') {
        *(undefined4 *)(param_3 + 0x40) = *(undefined4 *)(puVar7 + 6);
        *(undefined4 *)(param_3 + 0x44) = *(undefined4 *)(puVar7 + 8);
        *(undefined4 *)(param_3 + 0x48) = *(undefined4 *)(puVar7 + 10);
        FLOAT_803de468 = FLOAT_803e80ac;
        DAT_803de46c = '\0';
      }
      uVar19 = 1;
      *(undefined2 *)(param_3 + 0x6e) = 0;
      *(undefined *)(param_3 + 0x56) = 1;
      fVar1 = *(float *)(param_3 + 0x40) - *(float *)(puVar7 + 6);
      fVar3 = *(float *)(param_3 + 0x48) - *(float *)(puVar7 + 10);
      dVar23 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar3 * fVar3));
      dVar25 = (double)(*(float *)(psVar16 + 6) - *(float *)(param_3 + 0x40));
      dVar26 = (double)(*(float *)(psVar16 + 10) - *(float *)(param_3 + 0x48));
      dVar24 = (double)FUN_802931a0((double)(float)(dVar25 * dVar25 +
                                                   (double)(float)(dVar26 * dVar26)));
      if (dVar23 <= (double)FLOAT_803de468) {
        DAT_803de46c = DAT_803de46c + '\x01';
      }
      if ((dVar24 <= dVar23) || ('\x05' < DAT_803de46c)) {
        iVar9 = (int)*(short *)(iVar20 + 0x478) - ((int)*psVar16 & 0xffffU);
        if (0x8000 < iVar9) {
          iVar9 = iVar9 + -0xffff;
        }
        if (iVar9 < -0x8000) {
          iVar9 = iVar9 + 0xffff;
        }
        if (0x4000 < iVar9) {
          iVar9 = 0x4000;
        }
        if (iVar9 < -0x4000) {
          iVar9 = -0x4000;
        }
        *(short *)(iVar20 + 0x478) =
             *(short *)(iVar20 + 0x478) - (short)((int)(iVar9 * (uint)DAT_803db410) >> 3);
        *(undefined2 *)(iVar20 + 0x484) = *(undefined2 *)(iVar20 + 0x478);
        fVar1 = FLOAT_803e7ea4;
        if ('\x06' < DAT_803de46c) {
          iVar9 = 0;
        }
        if ((iVar9 < 0x100) && (-0x100 < iVar9)) {
          *(undefined2 *)(param_3 + 0x6e) = *(undefined2 *)(param_3 + 0x70);
          *(undefined *)(param_3 + 0x56) = 0;
          *(short *)(param_3 + 0x5a) = *(short *)(param_3 + 0x58) + -1;
          puVar7[0x51] = 0xffff;
          uVar19 = 0;
        }
        else {
          *(float *)(iVar20 + 0x290) = FLOAT_803e7ea4;
          *(float *)(iVar20 + 0x28c) = fVar1;
          (**(code **)(*DAT_803dca8c + 0x10))(psVar16);
          *(undefined4 *)(iVar20 + 0x31c) = 0;
          *(undefined4 *)(iVar20 + 0x318) = 0;
          *(undefined4 *)(puVar7 + 0x7a) = 0;
          *(undefined2 *)(iVar20 + 0x330) = 0;
          *(undefined *)(iVar20 + 0x25f) = 1;
          *(uint *)(iVar20 + 4) = *(uint *)(iVar20 + 4) & 0xffefffff;
          *(undefined *)(iVar20 + 0x8c5) = 0;
          FUN_802b0ea4(puVar7,iVar20,iVar20);
          (**(code **)(*DAT_803dca8c + 8))
                    ((double)FLOAT_803db414,(double)FLOAT_803db414,puVar7,iVar20,&DAT_803dafc8,
                     &DAT_803de4b8);
        }
      }
      else {
        dVar22 = (double)FLOAT_803e80c4;
        *(float *)(iVar20 + 0x290) = (float)(dVar22 * -(double)(float)(dVar25 / dVar24));
        *(float *)(iVar20 + 0x28c) = (float)(dVar22 * (double)(float)(dVar26 / dVar24));
        *(float *)(puVar7 + 6) =
             (float)(dVar23 * (double)(float)(dVar25 / dVar24) + (double)*(float *)(param_3 + 0x40))
        ;
        *(float *)(puVar7 + 10) =
             (float)(dVar23 * (double)(float)(dVar26 / dVar24) + (double)*(float *)(param_3 + 0x48))
        ;
        (**(code **)(*DAT_803dca8c + 0x10))(psVar16);
        *(undefined4 *)(iVar20 + 0x31c) = 0;
        *(undefined4 *)(iVar20 + 0x318) = 0;
        *(undefined4 *)(puVar7 + 0x7a) = 0;
        *(undefined2 *)(iVar20 + 0x330) = 0;
        *(undefined *)(iVar20 + 0x25f) = 1;
        *(uint *)(iVar20 + 4) = *(uint *)(iVar20 + 4) & 0xffefffff;
        *(undefined *)(iVar20 + 0x8c5) = 0;
        FUN_802b0ea4(puVar7,iVar20,iVar20);
        (**(code **)(*DAT_803dca8c + 8))
                  ((double)FLOAT_803db414,(double)FLOAT_803db414,puVar7,iVar20,&DAT_803dafc8,
                   &DAT_803de4b8);
      }
      FLOAT_803de468 = (float)dVar23;
    }
    if (*(char *)(param_3 + 0x56) == '\0') {
      (**(code **)(*DAT_803dca8c + 0x14))(puVar7,iVar20,1);
      *(code **)(iVar20 + 0x304) = FUN_802a514c;
      *(undefined2 *)(iVar20 + 0x276) = 1;
    }
  }
  if (DAT_803de458 != '\0') {
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
    DAT_803de458 = '\0';
  }
  if ((*(int *)(iVar20 + 0x7f0) != 0) &&
     (iVar9 = (**(code **)(**(int **)(*(int *)(iVar20 + 0x7f0) + 0x68) + 0x38))(), iVar9 == 2)) {
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffc;
  }
  if ((*(byte *)(iVar20 + 0x3f2) >> 6 & 1) != 0) {
    FUN_8003b310(puVar7,iVar20 + 0x364);
  }
  if (DAT_803dc66c == '\x02') {
    DAT_803dc66c = '\x01';
  }
  if (*(short *)(DAT_803de44c + 0x44) == 0x2d) {
    FUN_8016e81c();
  }
  FUN_802aef34((double)FLOAT_803db414,puVar7,iVar20);
  if (((DAT_803de44c != 0) && ((*(byte *)(iVar20 + 0x3f4) >> 6 & 1) != 0)) &&
     (*(ushort *)(DAT_803de44c + 0xb0) = *(ushort *)(DAT_803de44c + 0xb0) & 0xfff8,
     *(char *)(iVar20 + 0x8b3) == '\0')) {
    *(ushort *)(DAT_803de44c + 0xb0) = *(ushort *)(DAT_803de44c + 0xb0) | 2;
  }
  *(uint *)(iVar20 + 0x360) = *(uint *)(iVar20 + 0x360) | 0x800000;
  FUN_8006ef38((double)*(float *)(iVar20 + 0x280),(double)FLOAT_803e7ee0,puVar7,param_3 + 0xf0,
               *(undefined *)(iVar20 + 0x8a6),iVar20 + 0x3c4,iVar20 + 4);
  __psq_l0(auStack8,uVar21);
  __psq_l1(auStack8,uVar21);
  __psq_l0(auStack24,uVar21);
  __psq_l1(auStack24,uVar21);
  __psq_l0(auStack40,uVar21);
  __psq_l1(auStack40,uVar21);
  FUN_80286110(uVar19);
  return;
}

