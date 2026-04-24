// Function: FUN_80115094
// Entry: 80115094
// Size: 1468 bytes

/* WARNING: Removing unreachable block (ram,0x80115630) */

void FUN_80115094(void)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 uVar8;
  short sVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  double extraout_f1;
  double extraout_f1_00;
  double extraout_f1_01;
  undefined8 in_f31;
  double dVar13;
  undefined8 uVar14;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar14 = FUN_802860dc();
  iVar5 = (int)((ulonglong)uVar14 >> 0x20);
  iVar10 = (int)uVar14;
  local_48 = FLOAT_803e1c8c;
  dVar13 = (double)FLOAT_803e1cd0;
  sVar9 = 0;
  uVar6 = FUN_800394a0();
  dVar12 = (double)FUN_8002b9ec();
  if (*(char *)(iVar10 + 0x601) == '\0') {
    if (((*(byte *)(iVar10 + 0x611) & 1) == 0) || (*(char *)(iVar10 + 0x600) == '\b')) {
      if (((*(byte *)(iVar10 + 0x611) & 1) == 0) &&
         ((*(char *)(iVar10 + 0x600) == '\b' &&
          (*(undefined *)(iVar10 + 0x600) = 0, (*(byte *)(iVar10 + 0x611) & 8) == 0)))) {
        dVar12 = (double)FUN_8003acfc(iVar5,uVar6,*(undefined *)(iVar10 + 0x610),iVar10 + 0x1c);
        *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
      }
    }
    else {
      *(undefined *)(iVar10 + 0x600) = 8;
      if ((*(byte *)(iVar10 + 0x611) & 8) == 0) {
        FUN_8003acfc(iVar5,uVar6,*(undefined *)(iVar10 + 0x610),iVar10 + 0x1c);
        *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
        dVar12 = (double)FUN_8003a9c0(iVar10 + 0x1c,*(undefined *)(iVar10 + 0x610),0,0);
      }
      else {
        uVar8 = FUN_800394a0();
        dVar12 = (double)FUN_8003ac14(iVar5,uVar8,*(undefined *)(iVar10 + 0x610));
      }
    }
    if (*(byte *)(iVar10 + 0x600) < 2) {
      iVar7 = *(int *)(iVar10 + 0x608);
      if (iVar7 == 0) {
        iVar7 = FUN_80036e58(8,iVar5,&local_48);
        dVar12 = extraout_f1;
      }
      if (iVar7 != 0) {
        if ((*(byte *)(iVar10 + 0x611) & 0x20) != 0) {
          local_44 = *(float *)(iVar10 + 0x10) - *(float *)(iVar7 + 0xc);
          local_40 = *(float *)(iVar10 + 0x14) - *(float *)(iVar7 + 0x10);
          local_3c = *(float *)(iVar10 + 0x18) - *(float *)(iVar7 + 0x14);
          dVar12 = (double)FUN_802931a0((double)(local_44 * local_44 + local_3c * local_3c));
          if (dVar12 <= (double)FLOAT_803e1cd4) {
            fVar1 = (float)(dVar12 - (double)FLOAT_803e1cd8) / FLOAT_803e1cd0;
            fVar2 = FLOAT_803e1c90;
            if ((FLOAT_803e1c90 <= fVar1) && (fVar2 = fVar1, FLOAT_803e1ca4 < fVar1)) {
              fVar2 = FLOAT_803e1ca4;
            }
            fVar2 = FLOAT_803e1ca4 - fVar2;
            fVar1 = FLOAT_803e1ca4 - fVar2;
            *(float *)(iVar10 + 0x10) =
                 (float)((double)*(float *)(iVar10 + 0x10) * (double)fVar1 +
                        (double)(*(float *)(iVar5 + 0xc) * fVar2));
            dVar12 = (double)*(float *)(iVar10 + 0x18);
            *(float *)(iVar10 + 0x18) =
                 (float)(dVar12 * (double)fVar1 + (double)(*(float *)(iVar5 + 0x14) * fVar2));
          }
        }
        if ((*(int *)(iVar10 + 0x618) == -1) || (iVar7 != *(int *)(iVar10 + 0x604))) {
          *(int *)(iVar10 + 0x620) = *(int *)(iVar10 + 0x618);
        }
        else {
          iVar4 = *(int *)(iVar10 + 0x620) - (uint)DAT_803db410;
          *(int *)(iVar10 + 0x620) = iVar4;
          if ((iVar4 < 1) && (0 < (int)(*(int *)(iVar10 + 0x620) + (uint)DAT_803db410))) {
            FUN_8003acfc(iVar5,uVar6,*(undefined *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
            FUN_8003a9c0(iVar10 + 0x1c,*(undefined *)(iVar10 + 0x610),0,0);
            *(undefined *)(iVar10 + 0x600) = 0;
            goto LAB_80115630;
          }
          if (*(int *)(iVar10 + 0x5f8) != 0) {
            uVar8 = FUN_8003a8b4(iVar5,uVar6,*(undefined *)(iVar10 + 0x610),iVar10 + 0x1c);
            uVar3 = countLeadingZeros(uVar8);
            *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
            dVar12 = extraout_f1_00;
          }
          if (*(int *)(iVar10 + 0x620) < -*(int *)(iVar10 + 0x61c)) {
            uVar8 = FUN_800221a0(*(int *)(iVar10 + 0x61c),*(undefined4 *)(iVar10 + 0x618));
            *(undefined4 *)(iVar10 + 0x620) = uVar8;
            dVar12 = extraout_f1_01;
          }
          if (*(int *)(iVar10 + 0x620) < 0) goto LAB_80115630;
        }
        if ((iVar7 != *(int *)(iVar10 + 0x604)) && (iVar7 != 0)) {
          iVar4 = *(int *)(iVar7 + 0x54);
          if (iVar4 == 0) {
            dVar13 = (double)FLOAT_803e1cd0;
          }
          else if ((*(byte *)(iVar4 + 0x62) & 2) == 0) {
            if ((*(byte *)(iVar4 + 0x62) & 1) == 0) {
              dVar13 = (double)FLOAT_803e1cd0;
            }
            else {
              uStack52 = (int)*(short *)(iVar4 + 0x5a) ^ 0x80000000;
              local_38 = 0x43300000;
              dVar13 = (double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1c98);
              dVar12 = DOUBLE_803e1c98;
            }
          }
          else {
            uStack52 = (int)*(short *)(iVar4 + 0x5e) ^ 0x80000000;
            local_38 = 0x43300000;
            dVar13 = (double)(FLOAT_803e1cdc *
                             (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1c98));
            dVar12 = DOUBLE_803e1c98;
          }
        }
        if (iVar7 != 0) {
          sVar9 = FUN_800385e8(dVar12,iVar5,iVar7,0);
        }
        if ((*(byte *)(iVar10 + 0x611) & 0x10) != 0) {
          FUN_80038f1c(0,1);
          sVar9 = sVar9 + -0x8000;
        }
        iVar4 = (int)sVar9;
        if (iVar4 < 0) {
          iVar4 = -iVar4;
        }
        if (((0x5555 < iVar4) || (iVar7 == 0)) ||
           (dVar12 = (double)FUN_80021704(iVar5 + 0x18,iVar7 + 0x18),
           (double)*(float *)(iVar10 + 0x614) < dVar12)) {
          if ((*(char *)(iVar10 + 0x600) != '\0') ||
             ((iVar7 == 0 && (*(int *)(iVar10 + 0x604) != 0)))) {
            FUN_8003acfc(iVar5,uVar6,*(undefined *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 10;
            FUN_8003a9c0(iVar10 + 0x1c,*(undefined *)(iVar10 + 0x610),0,0);
            *(undefined *)(iVar10 + 0x600) = 0;
          }
        }
        else {
          if ((iVar7 != *(int *)(iVar10 + 0x604)) || (*(char *)(iVar10 + 0x600) == '\0')) {
            FUN_8003acfc(iVar5,uVar6,*(undefined *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 1;
          }
          if ((*(byte *)(iVar10 + 0x611) & 8) != 0) {
            *(undefined4 *)(iVar10 + 0x5f8) = 0;
          }
          if (*(int *)(iVar10 + 0x5f8) == 0) {
            iVar4 = 0;
          }
          else {
            iVar4 = iVar10 + 0x1c;
          }
          FUN_8003a380(dVar13,iVar5,iVar7,iVar10 + 0x10,iVar4,iVar10 + 0x5bc,8,
                       (int)*(short *)(iVar10 + 0x60c));
          *(undefined *)(iVar10 + 0x600) = 1;
        }
        *(int *)(iVar10 + 0x604) = iVar7;
        if (*(int *)(iVar10 + 0x5f8) == 0) {
          *(undefined4 *)(iVar10 + 0x608) = 0;
        }
        if (((*(byte *)(iVar10 + 0x611) & 8) == 0) && (*(int *)(iVar10 + 0x5f8) != 0)) {
          uVar6 = FUN_8003a8b4(iVar5,uVar6,*(undefined *)(iVar10 + 0x610),iVar10 + 0x1c);
          uVar3 = countLeadingZeros(uVar6);
          *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
        }
      }
    }
    else if ((*(int *)(iVar10 + 0x5f8) == 0) || ((*(byte *)(iVar10 + 0x611) & 8) != 0)) {
      uVar6 = FUN_800394a0();
      FUN_8003ac14(iVar5,uVar6,*(undefined *)(iVar10 + 0x610));
    }
    else {
      uVar6 = FUN_8003a8b4(iVar5,uVar6,*(undefined *)(iVar10 + 0x610),iVar10 + 0x1c);
      uVar3 = countLeadingZeros(uVar6);
      *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
    }
  }
LAB_80115630:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286128();
  return;
}

