// Function: FUN_80232830
// Entry: 80232830
// Size: 1344 bytes

/* WARNING: Removing unreachable block (ram,0x8023290c) */
/* WARNING: Removing unreachable block (ram,0x80232d54) */

void FUN_80232830(void)

{
  byte bVar1;
  float fVar2;
  bool bVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  short *psVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  double local_40;
  double local_30;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  psVar4 = (short *)FUN_802860dc();
  iVar10 = *(int *)(psVar4 + 0x5c);
  iVar8 = *(int *)(psVar4 + 0x26);
  if ((*(char *)(iVar10 + 0x159) == '\x04') || (*(char *)(iVar10 + 0x159) == '\x03'))
  goto LAB_80232d54;
  if (*(char *)(iVar10 + 0x15d) == '\x01') {
    iVar5 = FUN_8022d768();
    if (iVar5 == 0) {
      iVar5 = FUN_8002b9ec();
    }
    fVar2 = *(float *)(psVar4 + 10) - *(float *)(iVar5 + 0x14);
    bVar3 = false;
    if ((fVar2 < FLOAT_803e71b8) && (FLOAT_803e7164 < fVar2)) {
      bVar3 = true;
    }
    if (bVar3) {
      iVar5 = FUN_800221a0(0,1);
      if (iVar5 == 0) {
        FUN_80125ba4(0xd);
      }
      else {
        FUN_80125ba4(0x10);
      }
      *(undefined *)(iVar10 + 0x15d) = 0;
    }
  }
  bVar1 = *(byte *)(iVar10 + 0x159);
  if (bVar1 != 2) {
    if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar8 = *(int *)(psVar4 + 0x26);
        FUN_8022d768();
        psVar9 = psVar4;
        if (0 < *(int *)(iVar8 + 0x20)) {
          if (*(int *)(iVar10 + 0x13c) == 0) {
            uVar7 = FUN_8002e0b4();
            *(undefined4 *)(iVar10 + 0x13c) = uVar7;
          }
          psVar9 = *(short **)(iVar10 + 0x13c);
        }
        if (psVar9 == (short *)0x0) {
LAB_80232a00:
          bVar3 = false;
        }
        else {
          dVar13 = (double)*(float *)(iVar10 + 0x130);
          iVar5 = FUN_8022d768();
          if (iVar5 == 0) {
            iVar5 = FUN_8002b9ec();
          }
          dVar12 = (double)(*(float *)(psVar9 + 10) - *(float *)(iVar5 + 0x14));
          bVar3 = false;
          if ((dVar12 < dVar13) && ((double)FLOAT_803e7164 < dVar12)) {
            bVar3 = true;
          }
          if (!bVar3) goto LAB_80232a00;
          if (*(short *)(iVar8 + 0x32) < 1) {
            dVar13 = (double)*(float *)(iVar10 + 0x134);
            iVar5 = FUN_8022d768();
            if (iVar5 == 0) {
              iVar5 = FUN_8002b9ec();
            }
            dVar12 = (double)(*(float *)(psVar9 + 10) - *(float *)(iVar5 + 0x14));
            bVar3 = false;
            if ((dVar12 < dVar13) && ((double)FLOAT_803e7164 < dVar12)) {
              bVar3 = true;
            }
            if (!bVar3) goto LAB_802329e8;
          }
          else {
LAB_802329e8:
            iVar8 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x32));
            if (iVar8 == 0) goto LAB_80232a00;
          }
          bVar3 = true;
        }
        if (bVar3) {
          psVar4[3] = psVar4[3] & 0xbfff;
          FUN_80035f20(psVar4);
          *(undefined *)(iVar10 + 0x159) = 1;
          iVar8 = *(int *)(psVar4 + 0x26);
          if (*(char *)(iVar10 + 0x15c) == '\x01') {
            *(byte *)(iVar10 + 0x160) = *(byte *)(iVar10 + 0x160) & 0xdf;
            FUN_8008016c(iVar10 + 0x124);
            FUN_80080178(iVar10 + 0x124,*(undefined *)(iVar8 + 0x2c));
          }
        }
        goto LAB_80232d54;
      }
      *(undefined *)(psVar4 + 0x1b) = 0xff;
      iVar5 = *(int *)(psVar4 + 0x26);
      FUN_8022d768();
      psVar9 = psVar4;
      if (*(short **)(iVar10 + 0x13c) != (short *)0x0) {
        psVar9 = *(short **)(iVar10 + 0x13c);
      }
      if (psVar9 == (short *)0x0) {
LAB_80232b3c:
        bVar3 = false;
      }
      else {
        dVar13 = (double)*(float *)(iVar10 + 0x130);
        iVar6 = FUN_8022d768();
        if (iVar6 == 0) {
          iVar6 = FUN_8002b9ec();
        }
        dVar12 = (double)(*(float *)(psVar9 + 10) - *(float *)(iVar6 + 0x14));
        bVar3 = false;
        if ((dVar12 < dVar13) && ((double)FLOAT_803e7164 < dVar12)) {
          bVar3 = true;
        }
        if (bVar3) goto LAB_80232b3c;
        if (*(short *)(iVar5 + 0x32) < 1) {
          dVar13 = (double)*(float *)(iVar10 + 0x134);
          iVar6 = FUN_8022d768();
          if (iVar6 == 0) {
            iVar6 = FUN_8002b9ec();
          }
          dVar12 = (double)(*(float *)(psVar9 + 10) - *(float *)(iVar6 + 0x14));
          bVar3 = false;
          if ((dVar12 < dVar13) && ((double)FLOAT_803e7164 < dVar12)) {
            bVar3 = true;
          }
          if (bVar3) goto LAB_80232b24;
        }
        else {
LAB_80232b24:
          iVar5 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x32));
          if (iVar5 != 0) goto LAB_80232b3c;
        }
        bVar3 = true;
      }
      dVar13 = DOUBLE_803e7178;
      if (bVar3) {
        psVar4[3] = psVar4[3] | 0x4000;
        FUN_80035f00(psVar4);
        *(undefined *)(iVar10 + 0x159) = 4;
        goto LAB_80232d54;
      }
      if (*(char *)(iVar10 + 0x15c) != '\x02') {
        if (*(char *)(iVar8 + 0x2f) != '\x02') {
          *psVar4 = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                          (int)*(short *)(iVar10 + 0x140) ^
                                                          0x80000000) - DOUBLE_803e7178) *
                                 FLOAT_803db414 +
                                (float)((double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000) -
                                       DOUBLE_803e7178));
          local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x142) ^ 0x80000000);
          psVar4[1] = (short)(int)((float)(local_40 - dVar13) * FLOAT_803db414 +
                                  (float)((double)CONCAT44(0x43300000,(int)psVar4[1] ^ 0x80000000) -
                                         dVar13));
        }
        if (((*(byte *)(iVar10 + 0x160) >> 3 & 1) != 0) || (*(char *)(iVar8 + 0x2f) != '\x02')) {
          local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar10 + 0x144) ^ 0x80000000);
          psVar4[2] = (short)(int)((float)(local_30 - DOUBLE_803e7178) * FLOAT_803db414 +
                                  (float)((double)CONCAT44(0x43300000,(int)psVar4[2] ^ 0x80000000) -
                                         DOUBLE_803e7178));
        }
      }
      if (*(int *)(iVar10 + 0x13c) == 0) {
        if ((*(byte *)(iVar10 + 0x160) >> 6 & 1) != 0) {
          FUN_80232138(psVar4,iVar10);
        }
      }
      else {
        FUN_80231e30(psVar4,iVar10);
      }
      if (*(char *)(iVar10 + 0x160) < '\0') {
        uVar7 = *(undefined4 *)(psVar4 + 0x26);
        FUN_80035df4(psVar4,0x13,*(undefined *)(iVar10 + 0x156),0);
        if (*(char *)(iVar10 + 0x15c) == '\x01') {
          FUN_8023267c(psVar4,iVar10,uVar7);
        }
      }
    }
    else if (bVar1 < 5) goto LAB_80232d54;
  }
  FUN_802323ac(psVar4,iVar10);
  if (*(char *)(iVar10 + 0x15c) == '\x01') {
    FUN_80231a90(psVar4,iVar10);
  }
  if (*(int *)(*(int *)(psVar4 + 0x28) + 0x44) == 0) {
    FUN_8002fa48((double)FLOAT_803e71bc,(double)FLOAT_803db414,psVar4,0);
  }
LAB_80232d54:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286128();
  return;
}

