// Function: FUN_8019c784
// Entry: 8019c784
// Size: 1396 bytes

/* WARNING: Removing unreachable block (ram,0x8019ccd0) */
/* WARNING: Removing unreachable block (ram,0x8019ccc8) */
/* WARNING: Removing unreachable block (ram,0x8019ccd8) */

void FUN_8019c784(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,int param_6,int param_7,uint param_8)

{
  float fVar1;
  byte bVar2;
  float fVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  double extraout_f1;
  double dVar10;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar13 = FUN_802860d4();
  iVar6 = (int)((ulonglong)uVar13 >> 0x20);
  iVar8 = (int)uVar13;
  dVar11 = extraout_f1;
  iVar7 = FUN_8002b9ec();
  dVar12 = (double)(*(float *)(iVar8 + 0x10) - *(float *)(iVar6 + 0x10));
  if (((double)FLOAT_803e416c <= dVar12) &&
     ((dVar10 = (double)FUN_80021690(iVar8 + 0x18,iVar6 + 0x18),
      dVar10 <= (double)(float)((double)FLOAT_803e4170 + param_2) ||
      ((*(byte *)(param_5 + 0x10) & 0xe0) != 0)))) {
    bVar2 = *(byte *)(param_5 + 0x10);
    if (((bVar2 & 0x80) == 0) || (param_6 == 0)) {
      if (param_2 <= dVar10) {
        if (param_7 == 0) {
          FUN_800378c4(iVar8,0x10,iVar6,param_6);
          *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) & 0xe;
          *(float *)(param_5 + 0xc) = FLOAT_803e416c;
          *(undefined *)(param_5 + 0x11) = 0;
        }
        else {
          FUN_80296220((double)FLOAT_803e416c,iVar8);
        }
      }
      else {
        if (((bVar2 & 0xe0) == 0) || ((bVar2 & 0x80) != 0)) {
          if ((param_6 != 0) &&
             ((uVar5 = countLeadingZeros((uint)bVar2), (uVar5 >> 5 & 0x80) != 0 &&
              (dVar12 < (double)FLOAT_803e4174)))) {
            *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) | 0x80;
            goto LAB_8019ccc8;
          }
          if ((bVar2 & 2) != 0) {
            if ((float)(dVar12 / dVar11) <= FLOAT_803e4178) {
              *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) | 8;
              *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) & 0xfb;
            }
            else {
              *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) | 4;
              *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) & 0xf7;
            }
            *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) & 0xfd;
          }
          if (param_6 == 0) {
            *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) | 0x40;
            *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) & 0xdf;
            FUN_800378c4(iVar8,0xf,iVar6,
                         ((int)(*(byte *)(param_5 + 0x10) & 0xe0) >> 4) << 8 | param_8);
            *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) & 0x7f;
          }
          else {
            if ((double)FLOAT_803e417c < dVar12) {
              FUN_800378c4(iVar8,0xf,iVar6,
                           ((int)(*(byte *)(param_5 + 0x10) & 0xe0) >> 4) << 8 | param_8);
            }
            *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) | 0x20;
            *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) & 0xbf;
          }
        }
        fVar4 = FLOAT_803e4180;
        bVar2 = *(byte *)(param_5 + 0x10);
        if ((((bVar2 & 0xe) != 0) && ((bVar2 & 8) != 0)) && (param_6 == 0)) {
          dVar11 = (double)(float)(dVar11 * (double)FLOAT_803e4184);
        }
        fVar1 = (float)(dVar11 * (double)FLOAT_803e4184);
        if (FLOAT_803e4170 < fVar1) {
          if (dVar12 < (double)FLOAT_803e4188) {
            dVar12 = (double)FLOAT_803e4188;
          }
          if (param_6 == 0) {
            fVar3 = *(float *)(param_5 + 0xc);
            dVar11 = -(double)((fVar1 / FLOAT_803e418c) * fVar3 * fVar3 * fVar3 - fVar1);
            fVar3 = FLOAT_803e416c;
            if ((dVar12 <= dVar11) &&
               (fVar1 = (float)(dVar11 - dVar12), fVar3 = FLOAT_803e4190, fVar1 <= FLOAT_803e4174))
            {
              fVar3 = fVar1 / FLOAT_803e4174;
            }
            *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) | 1;
            if ((((*(float *)(param_5 + 0xc) < FLOAT_803e4194) &&
                 ((*(byte *)(param_5 + 0x11) & 1) != 0)) ||
                ((FLOAT_803e4198 < *(float *)(param_5 + 0xc) &&
                 ((*(byte *)(param_5 + 0x11) & 1) == 0)))) &&
               (((*(byte *)(param_5 + 0x10) & 8) != 0 &&
                (bVar2 = *(byte *)(param_5 + 0x11), *(byte *)(param_5 + 0x11) = bVar2 + 1, 2 < bVar2
                )))) {
              *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) & 0xf7;
              *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) | 4;
            }
          }
          else {
            fVar3 = FLOAT_803e419c;
            if ((bVar2 & 0xe) != 0) {
              fVar3 = FLOAT_803e4168;
            }
            if (fVar3 < *(float *)(param_5 + 0xc)) {
              *(undefined *)(param_5 + 0x11) = 1;
            }
            fVar4 = fVar4 * FLOAT_803e41a0;
            fVar3 = FLOAT_803e41ac;
            if (*(char *)(param_5 + 0x11) == '\0') {
              fVar3 = FLOAT_803e41a8;
              if ((*(byte *)(param_5 + 0x10) & 0xe) != 0) {
                fVar3 = FLOAT_803e41a4;
              }
              fVar1 = FLOAT_803e4190 - (float)(dVar12 / (double)(fVar3 * fVar1));
              if (fVar1 < FLOAT_803e416c) {
                fVar1 = FLOAT_803e416c;
              }
              fVar3 = fVar1 * fVar1;
            }
          }
          *(float *)(param_5 + 8) = fVar4 * fVar3 - FLOAT_803e41b0;
          *(float *)(param_5 + 0xc) = *(float *)(param_5 + 0xc) + *(float *)(param_5 + 8);
          if (FLOAT_803e41b4 < *(float *)(param_5 + 0xc)) {
            *(float *)(param_5 + 0xc) = FLOAT_803e41b4;
          }
          if (FLOAT_803e416c == *(float *)(param_5 + 0xc)) {
            *(float *)(param_5 + 0xc) = FLOAT_803e41b8;
          }
          if ((dVar12 < (double)FLOAT_803e4174) && (param_6 != 0)) {
            *(float *)(param_5 + 0xc) = FLOAT_803e416c;
            *(undefined *)(param_5 + 0x11) = 0;
            FUN_800378c4(iVar8,0x10,iVar6,param_6);
            *(byte *)(param_5 + 0x10) = *(byte *)(param_5 + 0x10) | 0x80;
            if (param_7 != 0) {
              *(float *)(iVar7 + 0x28) = FLOAT_803e416c;
            }
          }
          if (param_7 == 0) {
            *(float *)(iVar8 + 0x10) =
                 *(float *)(param_5 + 0xc) * FLOAT_803db414 + *(float *)(iVar8 + 0x10);
            *(float *)(iVar8 + 0x28) = *(float *)(param_5 + 0xc) * FLOAT_803db414;
          }
          else {
            FUN_80296220((double)*(float *)(param_5 + 0xc),iVar8);
          }
        }
      }
    }
  }
LAB_8019ccc8:
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  FUN_80286120();
  return;
}

