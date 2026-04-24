// Function: FUN_80158494
// Entry: 80158494
// Size: 1944 bytes

/* WARNING: Removing unreachable block (ram,0x80158c0c) */

void FUN_80158494(void)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  short *psVar4;
  char cVar6;
  int iVar5;
  int *piVar7;
  int iVar8;
  undefined *puVar9;
  undefined *puVar10;
  undefined *puVar11;
  undefined *puVar12;
  undefined4 uVar13;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  undefined8 uVar16;
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar16 = FUN_802860d4();
  psVar4 = (short *)((ulonglong)uVar16 >> 0x20);
  piVar7 = (int *)uVar16;
  uVar3 = (uint)*(byte *)((int)piVar7 + 0x33b);
  puVar12 = (&PTR_DAT_8031faf0)[uVar3 * 8];
  puVar11 = (&PTR_DAT_8031fae8)[uVar3 * 8];
  puVar10 = (&PTR_DAT_8031fafc)[uVar3 * 8];
  puVar9 = (&PTR_DAT_8031faf4)[uVar3 * 8];
  iVar8 = *piVar7;
  dVar15 = (double)FLOAT_803e2ba4;
  piVar7[0xba] = piVar7[0xba] & 0xffffffbf;
  if (*(int *)(psVar4 + 100) != 0) {
    FUN_8021fab4();
  }
  if ((piVar7[0xb7] & 0x80000000U) != 0) {
    *(byte *)((int)piVar7 + 0x33d) = *(byte *)((int)piVar7 + 0x33d) | 8;
    cVar6 = (**(code **)(*DAT_803dca9c + 0x8c))
                      ((double)FLOAT_803e2ba8,*piVar7,psVar4,&DAT_803dbcf0,0xffffffff);
    if (cVar6 != '\0') {
      piVar7[0xb7] = piVar7[0xb7] & 0xffffdfff;
    }
    if (*(char *)((int)piVar7 + 0x33b) == '\0') {
      FUN_80157988(psVar4,piVar7);
    }
    *(undefined *)((int)piVar7 + 0x33a) = 0;
  }
  fVar1 = FLOAT_803e2ba8;
  if (((float)piVar7[0xca] != FLOAT_803e2ba8) && (*(char *)((int)piVar7 + 0x33f) != '\0')) {
    piVar7[0xca] = (int)((float)piVar7[0xca] - FLOAT_803db414);
    if ((float)piVar7[0xca] <= fVar1) {
      piVar7[0xca] = (int)fVar1;
      piVar7[0xb7] = piVar7[0xb7] | 0x40000000;
      *(char *)(piVar7 + 0xcf) =
           (char)*(undefined4 *)(puVar10 + (uint)*(byte *)((int)piVar7 + 0x33f) * 0x10 + 0xc);
      *(byte *)(psVar4 + 0x72) = *(byte *)(piVar7 + 0xcf) & 1;
      *(undefined *)((int)piVar7 + 0x33f) =
           puVar10[(uint)*(byte *)((int)piVar7 + 0x33f) * 0x10 + 10];
    }
    if ((piVar7[0xb7] & 0xc0000000U) == 0) goto LAB_80158c0c;
  }
  if ((piVar7[0xb7] & 0x2000U) == 0) {
    if ((piVar7[0xb7] & 0xc0000000U) != 0) {
      uVar3 = FUN_800221a0(1,puVar12[8]);
      iVar8 = (uVar3 & 0xff) * 0xc;
      FUN_8014d08c((double)*(float *)(puVar12 + iVar8),psVar4,piVar7,puVar12[iVar8 + 8],0,
                   puVar12[iVar8 + 10]);
    }
  }
  else {
    iVar5 = FUN_8014c11c((double)FLOAT_803e2bb8,psVar4,1,0x28,&DAT_803ac4a8);
    if ((0 < iVar5) &&
       ((float)((double)CONCAT44(0x43300000,(uint)DAT_803ac4ac) - DOUBLE_803e2b90) <= FLOAT_803e2bb8
       )) {
      uVar3 = FUN_800217c0(-(double)(*(float *)(psVar4 + 0xc) - *(float *)(DAT_803ac4a8 + 0x18)),
                           -(double)(*(float *)(psVar4 + 0x10) - *(float *)(DAT_803ac4a8 + 0x20)));
      uVar3 = (uVar3 & 0xffff) - ((int)*psVar4 & 0xffffU);
      if (0x8000 < (int)uVar3) {
        uVar3 = uVar3 - 0xffff;
      }
      if ((int)uVar3 < -0x8000) {
        uVar3 = uVar3 + 0xffff;
      }
      uVar3 = (uVar3 & 0xffff) >> 0xd;
      if ((uVar3 == 3) || (uVar3 == 4)) {
        dVar15 = (double)((float)((double)CONCAT44(0x43300000,(uint)DAT_803ac4ac) - DOUBLE_803e2b90)
                         / FLOAT_803e2bb8);
      }
      else if ((uVar3 == 0) || (uVar3 == 7)) {
        dVar15 = (double)(FLOAT_803e2bb4 *
                          (FLOAT_803e2ba4 -
                          (float)((double)CONCAT44(0x43300000,(uint)DAT_803ac4ac) - DOUBLE_803e2b90)
                          / FLOAT_803e2bb8) + FLOAT_803e2ba4);
      }
    }
    fVar1 = *(float *)(iVar8 + 0x68) - *(float *)(psVar4 + 6);
    fVar2 = *(float *)(iVar8 + 0x70) - *(float *)(psVar4 + 10);
    dVar14 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
    if ((double)FLOAT_803e2ba0 < dVar14) {
      dVar14 = (double)FLOAT_803e2ba0;
    }
    piVar7[0xc4] = (int)(float)(dVar15 * (double)((float)((double)(float)((double)FLOAT_803e2ba0 -
                                                                         dVar14) /
                                                         (double)FLOAT_803e2ba0) *
                                                 (float)piVar7[0xbf]));
    if ((float)piVar7[0xc4] < FLOAT_803e2bbc) {
      piVar7[0xc4] = (int)FLOAT_803e2bbc;
    }
    iVar5 = FUN_80010320((double)(float)piVar7[0xc4],iVar8);
    if ((((iVar5 != 0) || (*(int *)(iVar8 + 0x10) != 0)) &&
        (cVar6 = (**(code **)(*DAT_803dca9c + 0x90))(iVar8), cVar6 != '\0')) &&
       (cVar6 = (**(code **)(*DAT_803dca9c + 0x8c))
                          ((double)FLOAT_803e2bc0,*piVar7,psVar4,&DAT_803dbcf0,0xffffffff),
       cVar6 != '\0')) {
      piVar7[0xb7] = piVar7[0xb7] & 0xffffdfff;
    }
    if ((*(byte *)((int)piVar7 + 0x33d) & 10) == 0) {
      uVar3 = FUN_800217c0((double)*(float *)(iVar8 + 0x74),(double)*(float *)(iVar8 + 0x7c));
      fVar1 = (float)((double)CONCAT44(0x43300000,
                                       ((uVar3 & 0xffff) + 0x8000) - ((int)*psVar4 & 0xffffU) ^
                                       0x80000000) - DOUBLE_803e2b98);
      if (FLOAT_803e2bc8 < fVar1) {
        fVar1 = FLOAT_803e2bc4 + fVar1;
      }
      if (fVar1 < FLOAT_803e2bd0) {
        fVar1 = FLOAT_803e2bcc + fVar1;
      }
      if (fVar1 < FLOAT_803e2ba8) {
        fVar1 = -fVar1;
      }
      piVar7[0xc2] = (int)(((float)((double)(float)piVar7[0xbf] * dVar15 -
                                   (double)(float)piVar7[0xc4]) / FLOAT_803e2b84) *
                          (FLOAT_803e2ba4 - fVar1 / FLOAT_803e2bcc));
      if (FLOAT_803e2bd4 <= (float)piVar7[0xc2]) {
        if (FLOAT_803e2bd8 < (float)piVar7[0xc2]) {
          piVar7[0xc2] = (int)FLOAT_803e2bd8;
        }
      }
      else {
        piVar7[0xc2] = (int)FLOAT_803e2bd4;
      }
    }
    if ((piVar7[0xb7] & 0xc0000000U) != 0) {
      *(byte *)((int)piVar7 + 0x33d) = *(byte *)((int)piVar7 + 0x33d) & 0xdf;
      if (*(byte *)((int)piVar7 + 0x33f) == 0) {
        uVar3 = FUN_800217c0(-(double)(*(float *)(psVar4 + 0xc) - *(float *)(iVar8 + 0x68)),
                             -(double)(*(float *)(psVar4 + 0x10) - *(float *)(iVar8 + 0x70)));
        uVar3 = (uVar3 & 0xffff) - ((int)*psVar4 & 0xffffU);
        if (0x8000 < (int)uVar3) {
          uVar3 = uVar3 - 0xffff;
        }
        if ((int)uVar3 < -0x8000) {
          uVar3 = uVar3 + 0xffff;
        }
        iVar5 = ((uVar3 & 0xffff) >> 0xd) * 0xc;
        if (puVar9[iVar5 + 8] == '\0') {
          *(byte *)((int)piVar7 + 0x33d) = *(byte *)((int)piVar7 + 0x33d) & 0xe7;
          fVar1 = (float)piVar7[0xc4];
          iVar5 = (uint)*(byte *)((int)piVar7 + 0x33b) * 0xc;
          if (fVar1 <= *(float *)(&DAT_8031fb48 + iVar5)) {
            if (fVar1 <= *(float *)(&DAT_8031fb4c + iVar5)) {
              if (fVar1 <= *(float *)(&DAT_8031fb50 + iVar5)) {
                *(undefined *)((int)piVar7 + 0x323) = 1;
                piVar7[0xc2] = (int)FLOAT_803e2bdc;
                FUN_80030334((double)FLOAT_803e2ba8,psVar4,puVar11[8],0);
                piVar7[0xc4] = (int)FLOAT_803e2ba8;
              }
              else {
                *(undefined *)((int)piVar7 + 0x323) = 1;
                FUN_80030334((double)FLOAT_803e2ba8,psVar4,puVar11[0x14],0);
              }
            }
            else {
              *(undefined *)((int)piVar7 + 0x323) = 1;
              FUN_80030334((double)FLOAT_803e2ba8,psVar4,puVar11[0x20],0);
            }
          }
          else {
            *(undefined *)((int)piVar7 + 0x323) = 1;
            FUN_80030334((double)FLOAT_803e2ba8,psVar4,puVar11[0x2c],0);
          }
        }
        else {
          FUN_8014d08c((double)*(float *)(puVar9 + iVar5),psVar4,piVar7,puVar9[iVar5 + 8],0,
                       puVar9[iVar5 + 10]);
          *(byte *)((int)piVar7 + 0x33d) = *(byte *)((int)piVar7 + 0x33d) | 8;
        }
      }
      else {
        iVar5 = (uint)*(byte *)((int)piVar7 + 0x33f) * 0x10;
        FUN_8014d08c((double)*(float *)(puVar10 + iVar5),psVar4,piVar7,puVar10[iVar5 + 8],0,
                     *(uint *)(puVar10 + iVar5 + 4) & 0xff);
        *(char *)(piVar7 + 0xcf) =
             (char)*(undefined4 *)(puVar10 + (uint)*(byte *)((int)piVar7 + 0x33f) * 0x10 + 0xc);
        *(byte *)(psVar4 + 0x72) = *(byte *)(piVar7 + 0xcf) & 1;
        *(undefined *)((int)piVar7 + 0x33f) =
             puVar10[(uint)*(byte *)((int)piVar7 + 0x33f) * 0x10 + 9];
      }
    }
    if (((*(byte *)((int)piVar7 + 0x323) & 8) == 0) &&
       ((*(byte *)((int)piVar7 + 0x33d) & 0x10) == 0)) {
      FUN_8014cf7c((double)*(float *)(iVar8 + 0x68),(double)*(float *)(iVar8 + 0x70),psVar4,piVar7,
                   0xf,0);
    }
  }
  FUN_80157cdc(psVar4,piVar7);
LAB_80158c0c:
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  FUN_80286120();
  return;
}

