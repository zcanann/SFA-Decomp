// Function: FUN_801d5f58
// Entry: 801d5f58
// Size: 1928 bytes

/* WARNING: Removing unreachable block (ram,0x801d60b4) */
/* WARNING: Removing unreachable block (ram,0x801d66c0) */

void FUN_801d5f58(void)

{
  byte bVar1;
  short *psVar2;
  char cVar5;
  undefined uVar6;
  int iVar3;
  short sVar4;
  undefined *puVar7;
  int iVar8;
  int iVar9;
  float *pfVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f31;
  undefined auStack120 [12];
  undefined auStack108 [4];
  undefined auStack104 [4];
  undefined auStack100 [4];
  float local_60 [2];
  float local_58;
  short local_52;
  char local_4d [8];
  char local_45;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  psVar2 = (short *)FUN_802860d8();
  iVar9 = *(int *)(psVar2 + 0x5c);
  iVar8 = *(int *)(psVar2 + 0x26);
  if (*(char *)(iVar9 + 0x624) == '\f') {
    if (*(float *)(iVar9 + 0x638) <= FLOAT_803e5418) {
      if ((psVar2[0x58] & 0x800U) != 0) {
        FUN_8003842c(psVar2,4,auStack108,auStack104,auStack100,0);
        (**(code **)(*DAT_803dca88 + 8))(psVar2,0x7f0,auStack120,0x200001,0xffffffff,0);
      }
      *(float *)(iVar9 + 0x638) = FLOAT_803e5450;
    }
    *(float *)(iVar9 + 0x638) = *(float *)(iVar9 + 0x638) - FLOAT_803db414;
  }
  *(byte *)(iVar9 + 0x625) = *(byte *)(iVar9 + 0x625) & 0xf7;
  if (((&DAT_80327388)[*(char *)(iVar9 + 0x624)] & 2) == 0) {
    puVar7 = &DAT_80326f38;
  }
  else {
    puVar7 = &DAT_8032712c;
  }
  cVar5 = FUN_800353a4(psVar2,puVar7,0x19,*(undefined *)(iVar9 + 0x640),iVar9 + 0x8ac);
  *(char *)(iVar9 + 0x640) = cVar5;
  if (cVar5 == '\0') {
    uVar6 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(psVar2 + 0x56));
    *(undefined *)(iVar9 + 0x626) = uVar6;
    bVar1 = *(byte *)(iVar8 + 0x18);
    if (bVar1 == 2) {
      FUN_801d56c4(psVar2,iVar9);
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        FUN_801d5b68(psVar2,iVar9,iVar8);
      }
      else {
        FUN_801d58e4(psVar2,iVar9,iVar8);
      }
    }
    else if (bVar1 < 4) {
      FUN_801d550c(psVar2,iVar9);
    }
    if (((&DAT_80327388)[*(char *)(iVar9 + 0x624)] & 1) == 0) {
      *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) & 0xef;
      *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) & 0xf7;
    }
    else {
      *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) | 0x10;
    }
    if ((*(byte *)(iVar9 + 0x625) & 0x10) != 0) {
      bVar1 = *(char *)(iVar9 + 0x63f) + 1;
      *(byte *)(iVar9 + 0x63f) = bVar1;
      if (bVar1 < 0xb) {
        *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) | 8;
      }
      else {
        *(byte *)(iVar9 + 0x625) = *(byte *)(iVar9 + 0x625) & 0xef;
      }
    }
    if ((int)psVar2[0x50] != (int)*(short *)(&DAT_80327320 + *(char *)(iVar9 + 0x624) * 2)) {
      FUN_80030334((double)FLOAT_803e5418,psVar2,
                   (int)*(short *)(&DAT_80327320 + *(char *)(iVar9 + 0x624) * 2),0);
      *(short *)(iVar9 + 0x63c) = *psVar2;
    }
    iVar3 = FUN_8002fa48((double)*(float *)(&DAT_80327344 + *(char *)(iVar9 + 0x624) * 4),
                         (double)FLOAT_803db414,psVar2,local_60);
    if (iVar3 == 0) {
      *(byte *)(iVar9 + 0x625) = *(byte *)(iVar9 + 0x625) & 0xfe;
    }
    else {
      *(byte *)(iVar9 + 0x625) = *(byte *)(iVar9 + 0x625) | 1;
    }
    if (((&DAT_80327388)[*(char *)(iVar9 + 0x624)] & 8) != 0) {
      if ((*(byte *)(iVar9 + 0x625) & 1) != 0) {
        *(short *)(iVar9 + 0x63c) = *psVar2;
      }
      uStack60 = (int)*(short *)(iVar9 + 0x63c) ^ 0x80000000;
      local_40 = 0x43300000;
      dVar12 = (double)FUN_80293e80((double)((FLOAT_803e5454 *
                                             (float)((double)CONCAT44(0x43300000,uStack60) -
                                                    DOUBLE_803e5428)) / FLOAT_803e5458));
      dVar12 = -dVar12;
      uStack52 = (int)*(short *)(iVar9 + 0x63c) ^ 0x80000000;
      local_38 = 0x43300000;
      dVar13 = (double)FUN_80294204((double)((FLOAT_803e5454 *
                                             (float)((double)CONCAT44(0x43300000,uStack52) -
                                                    DOUBLE_803e5428)) / FLOAT_803e5458));
      *(float *)(psVar2 + 6) = (float)(dVar12 * -(double)local_58 + (double)*(float *)(psVar2 + 6));
      *(float *)(psVar2 + 10) =
           (float)(-dVar13 * -(double)local_58 + (double)*(float *)(psVar2 + 10));
      *(float *)(psVar2 + 6) =
           (float)(-dVar13 * -(double)local_60[0] + (double)*(float *)(psVar2 + 6));
      *(float *)(psVar2 + 10) =
           (float)(dVar12 * (double)local_60[0] + (double)*(float *)(psVar2 + 10));
      *psVar2 = *psVar2 + local_52;
    }
    pfVar10 = local_60;
    for (iVar3 = 0; iVar3 < local_45; iVar3 = iVar3 + 1) {
      if (*(char *)((int)pfVar10 + 0x13) == '\0') {
        if (*(short *)(&DAT_8032739c + *(char *)(iVar9 + 0x624) * 2) != 0) {
          FUN_8000bb18(psVar2);
        }
      }
      else if ((*(char *)((int)pfVar10 + 0x13) == '\a') &&
              ((&DAT_803273c0)[*(char *)(iVar9 + 0x624)] != '\0')) {
        FUN_8000bb18(psVar2);
      }
      pfVar10 = (float *)((int)pfVar10 + 1);
    }
    FUN_8006ef38((double)FLOAT_803e5448,(double)FLOAT_803e5448,psVar2,local_60,8,iVar9 + 0x8e0,
                 iVar9 + 0x644);
    if (((&DAT_80327388)[*(char *)(iVar9 + 0x624)] & 4) == 0) {
      *(byte *)(iVar9 + 0x611) = *(byte *)(iVar9 + 0x611) | 1;
    }
    else {
      *(byte *)(iVar9 + 0x611) = *(byte *)(iVar9 + 0x611) & 0xfe;
    }
    FUN_80115094(psVar2,iVar9);
    if (((&DAT_80327388)[*(char *)(iVar9 + 0x624)] & 2) == 0) {
      FUN_8003b310(psVar2,iVar9 + 0x8b0);
    }
    else {
      FUN_8003b228(psVar2,iVar9 + 0x8b0);
    }
    *(byte *)(iVar9 + 0x625) = *(byte *)(iVar9 + 0x625) & 0xfd;
    if (((*(byte *)(iVar9 + 0x625) & 4) == 0) && (iVar3 = FUN_80038024(psVar2), iVar3 != 0)) {
      iVar3 = FUN_800221a0(1,**(undefined **)(iVar9 + 0x62c));
      *(byte *)(iVar9 + 0x625) = *(byte *)(iVar9 + 0x625) | 2;
      (**(code **)(*DAT_803dca54 + 0x48))
                (*(undefined *)(*(int *)(iVar9 + 0x62c) + iVar3),psVar2,0xffffffff);
    }
    if (*(char *)(iVar8 + 0x1b) != '\0') {
      dVar12 = (double)FUN_8002166c(psVar2 + 0xc,iVar8 + 8);
      uStack52 = (uint)*(byte *)(iVar8 + 0x1b) * (uint)*(byte *)(iVar8 + 0x1b) ^ 0x80000000;
      local_38 = 0x43300000;
      if (((double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e5428) < dVar12) &&
         (iVar3 = FUN_8005a10c((double)(*(float *)(psVar2 + 0x54) * *(float *)(psVar2 + 4)),
                               psVar2 + 6), iVar3 == 0)) {
        sVar4 = FUN_800217c0((double)(*(float *)(psVar2 + 6) - *(float *)(iVar8 + 8)),
                             (double)(*(float *)(psVar2 + 10) - *(float *)(iVar8 + 0x10)));
        *psVar2 = sVar4;
      }
    }
    *(undefined *)(iVar9 + 0x89f) = 1;
    if (DAT_803dbff8 == -1) {
      DAT_803dbff8 = *(int *)(*(int *)(psVar2 + 0x26) + 0x14);
      *(float *)(psVar2 + 0x14) = -(FLOAT_803e544c * FLOAT_803db414 - *(float *)(psVar2 + 0x14));
      (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,psVar2,iVar9 + 0x644);
      (**(code **)(*DAT_803dcaa8 + 0x14))(psVar2,iVar9 + 0x644);
      (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,psVar2,iVar9 + 0x644);
      psVar2[1] = *(short *)(iVar9 + 0x7dc);
      psVar2[2] = *(short *)(iVar9 + 0x7de);
    }
    else {
      if (DAT_803dbff8 == *(int *)(*(int *)(psVar2 + 0x26) + 0x14)) {
        DAT_803dbff8 = -1;
      }
      if ((*(char *)(iVar9 + 0x624) < '\x02') || ('\x06' < *(char *)(iVar9 + 0x624))) {
        (**(code **)(*DAT_803dcaa8 + 0x20))(psVar2,iVar9 + 0x644);
      }
      else {
        *(float *)(psVar2 + 0x14) = -(FLOAT_803e544c * FLOAT_803db414 - *(float *)(psVar2 + 0x14));
        (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,psVar2,iVar9 + 0x644);
        (**(code **)(*DAT_803dcaa8 + 0x14))(psVar2,iVar9 + 0x644);
        (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,psVar2,iVar9 + 0x644);
        psVar2[1] = *(short *)(iVar9 + 0x7dc);
        psVar2[2] = *(short *)(iVar9 + 0x7de);
      }
    }
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286124();
  return;
}

