// Function: FUN_8019cd00
// Entry: 8019cd00
// Size: 1396 bytes

/* WARNING: Removing unreachable block (ram,0x8019d254) */
/* WARNING: Removing unreachable block (ram,0x8019d24c) */
/* WARNING: Removing unreachable block (ram,0x8019d244) */
/* WARNING: Removing unreachable block (ram,0x8019cd20) */
/* WARNING: Removing unreachable block (ram,0x8019cd18) */
/* WARNING: Removing unreachable block (ram,0x8019cd10) */

void FUN_8019cd00(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,uint param_12,int param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  byte bVar2;
  float fVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  double dVar10;
  double extraout_f1;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 uVar14;
  
  uVar14 = FUN_80286838();
  uVar5 = (uint)((ulonglong)uVar14 >> 0x20);
  iVar7 = (int)uVar14;
  iVar8 = param_13;
  uVar9 = param_14;
  dVar10 = param_2;
  dVar12 = extraout_f1;
  iVar6 = FUN_8002bac4();
  dVar13 = (double)(*(float *)(iVar7 + 0x10) - *(float *)(uVar5 + 0x10));
  if (((double)FLOAT_803e4e04 <= dVar13) &&
     ((dVar11 = (double)FUN_80021754((float *)(iVar7 + 0x18),(float *)(uVar5 + 0x18)),
      dVar11 <= (double)(float)((double)FLOAT_803e4e08 + dVar10) ||
      ((*(byte *)(param_11 + 0x10) & 0xe0) != 0)))) {
    bVar2 = *(byte *)(param_11 + 0x10);
    if (((bVar2 & 0x80) == 0) || (param_12 == 0)) {
      if (dVar10 <= dVar11) {
        if (param_13 == 0) {
          FUN_800379bc(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7,0x10,
                       uVar5,param_12,iVar8,uVar9,param_15,param_16);
          *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xe;
          *(float *)(param_11 + 0xc) = FLOAT_803e4e04;
          *(undefined *)(param_11 + 0x11) = 0;
        }
        else {
          FUN_80296980((double)FLOAT_803e4e04,iVar7);
        }
      }
      else {
        if (((bVar2 & 0xe0) == 0) || ((bVar2 & 0x80) != 0)) {
          if ((param_12 != 0) &&
             ((uVar4 = countLeadingZeros((uint)bVar2), (uVar4 >> 5 & 0x80) != 0 &&
              (dVar13 < (double)FLOAT_803e4e0c)))) {
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x80;
            goto LAB_8019d244;
          }
          if ((bVar2 & 2) != 0) {
            dVar11 = (double)(float)(dVar13 / dVar12);
            if (dVar11 <= (double)FLOAT_803e4e10) {
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 8;
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xfb;
            }
            else {
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 4;
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xf7;
            }
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xfd;
          }
          if (param_12 == 0) {
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x40;
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xdf;
            FUN_800379bc(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7,0xf,
                         uVar5,((int)(*(byte *)(param_11 + 0x10) & 0xe0) >> 4) << 8 | param_14,iVar8
                         ,uVar9,param_15,param_16);
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0x7f;
          }
          else {
            if ((double)FLOAT_803e4e14 < dVar13) {
              FUN_800379bc(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar7,0xf,
                           uVar5,((int)(*(byte *)(param_11 + 0x10) & 0xe0) >> 4) << 8 | param_14,
                           iVar8,uVar9,param_15,param_16);
            }
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x20;
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xbf;
          }
        }
        dVar10 = (double)FLOAT_803e4e18;
        bVar2 = *(byte *)(param_11 + 0x10);
        if ((((bVar2 & 0xe) != 0) && ((bVar2 & 8) != 0)) && (param_12 == 0)) {
          dVar12 = (double)(float)(dVar12 * (double)FLOAT_803e4e1c);
        }
        fVar1 = (float)(dVar12 * (double)FLOAT_803e4e1c);
        if (FLOAT_803e4e08 < fVar1) {
          if (dVar13 < (double)FLOAT_803e4e20) {
            dVar13 = (double)FLOAT_803e4e20;
          }
          if (param_12 == 0) {
            fVar3 = *(float *)(param_11 + 0xc);
            dVar12 = -(double)((fVar1 / FLOAT_803e4e24) * fVar3 * fVar3 * fVar3 - fVar1);
            if (dVar13 <= dVar12) {
              fVar1 = (float)(dVar12 - dVar13);
              if (fVar1 <= FLOAT_803e4e0c) {
                dVar11 = (double)(fVar1 / FLOAT_803e4e0c);
              }
              else {
                dVar11 = (double)FLOAT_803e4e28;
              }
            }
            else {
              dVar11 = (double)FLOAT_803e4e04;
            }
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 1;
            dVar12 = (double)*(float *)(param_11 + 0xc);
            if ((((dVar12 < (double)FLOAT_803e4e2c) && ((*(byte *)(param_11 + 0x11) & 1) != 0)) ||
                (((double)FLOAT_803e4e30 < dVar12 && ((*(byte *)(param_11 + 0x11) & 1) == 0)))) &&
               (((*(byte *)(param_11 + 0x10) & 8) != 0 &&
                (bVar2 = *(byte *)(param_11 + 0x11), *(byte *)(param_11 + 0x11) = bVar2 + 1,
                2 < bVar2)))) {
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) & 0xf7;
              *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 4;
            }
          }
          else {
            dVar12 = (double)*(float *)(param_11 + 0xc);
            fVar3 = FLOAT_803e4e34;
            if ((bVar2 & 0xe) != 0) {
              fVar3 = FLOAT_803e4e00;
            }
            if ((double)fVar3 < dVar12) {
              *(undefined *)(param_11 + 0x11) = 1;
            }
            dVar10 = (double)(float)(dVar10 * (double)FLOAT_803e4e38);
            if (*(char *)(param_11 + 0x11) == '\0') {
              fVar3 = FLOAT_803e4e40;
              if ((*(byte *)(param_11 + 0x10) & 0xe) != 0) {
                fVar3 = FLOAT_803e4e3c;
              }
              fVar1 = FLOAT_803e4e28 - (float)(dVar13 / (double)(fVar3 * fVar1));
              dVar12 = (double)FLOAT_803e4e28;
              if (fVar1 < FLOAT_803e4e04) {
                fVar1 = FLOAT_803e4e04;
              }
              dVar11 = (double)(fVar1 * fVar1);
            }
            else {
              dVar11 = (double)FLOAT_803e4e44;
            }
          }
          *(float *)(param_11 + 8) = (float)(dVar10 * dVar11 - (double)FLOAT_803e4e48);
          *(float *)(param_11 + 0xc) = *(float *)(param_11 + 0xc) + *(float *)(param_11 + 8);
          if (FLOAT_803e4e4c < *(float *)(param_11 + 0xc)) {
            *(float *)(param_11 + 0xc) = FLOAT_803e4e4c;
          }
          dVar10 = (double)FLOAT_803e4e04;
          if (dVar10 == (double)*(float *)(param_11 + 0xc)) {
            *(float *)(param_11 + 0xc) = FLOAT_803e4e50;
          }
          if ((dVar13 < (double)FLOAT_803e4e0c) && (param_12 != 0)) {
            *(float *)(param_11 + 0xc) = FLOAT_803e4e04;
            *(undefined *)(param_11 + 0x11) = 0;
            FUN_800379bc(dVar10,dVar12,dVar11,param_4,param_5,param_6,param_7,param_8,iVar7,0x10,
                         uVar5,param_12,iVar8,uVar9,param_15,param_16);
            *(byte *)(param_11 + 0x10) = *(byte *)(param_11 + 0x10) | 0x80;
            if (param_13 != 0) {
              *(float *)(iVar6 + 0x28) = FLOAT_803e4e04;
            }
          }
          if (param_13 == 0) {
            *(float *)(iVar7 + 0x10) =
                 *(float *)(param_11 + 0xc) * FLOAT_803dc074 + *(float *)(iVar7 + 0x10);
            *(float *)(iVar7 + 0x28) = *(float *)(param_11 + 0xc) * FLOAT_803dc074;
          }
          else {
            FUN_80296980((double)*(float *)(param_11 + 0xc),iVar7);
          }
        }
      }
    }
  }
LAB_8019d244:
  FUN_80286884();
  return;
}

