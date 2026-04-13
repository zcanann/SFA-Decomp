// Function: FUN_8028026c
// Entry: 8028026c
// Size: 988 bytes

void FUN_8028026c(void)

{
  float *pfVar1;
  float *pfVar2;
  float *pfVar3;
  float fVar4;
  bool bVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined4 *puVar8;
  int iVar9;
  int iVar10;
  undefined4 *puVar11;
  undefined4 *unaff_r30;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  
  FUN_802801a8();
  iVar10 = 0;
  for (puVar11 = DAT_803defd8; puVar11 != (undefined4 *)0x0; puVar11 = (undefined4 *)*puVar11) {
    iVar10 = iVar10 + 1;
  }
  if (iVar10 != 0) {
    dVar13 = (double)FLOAT_803e852c;
    dVar14 = DOUBLE_803e8520;
    dVar15 = DOUBLE_803e8530;
    for (puVar11 = DAT_803defdc; puVar11 != (undefined4 *)0x0; puVar11 = (undefined4 *)*puVar11) {
      puVar8 = DAT_803defd8;
      fVar4 = FLOAT_803e8518;
      if (*(char *)(puVar11 + 7) == -1) {
        for (; puVar8 != (undefined4 *)0x0; puVar8 = (undefined4 *)*puVar8) {
          pfVar1 = (float *)(puVar8 + 4);
          pfVar2 = (float *)(puVar8 + 5);
          pfVar3 = (float *)(puVar8 + 6);
          fVar4 = fVar4 + ((float)puVar11[5] - *pfVar3) * ((float)puVar11[5] - *pfVar3) +
                          ((float)puVar11[3] - *pfVar1) * ((float)puVar11[3] - *pfVar1) +
                          ((float)puVar11[4] - *pfVar2) * ((float)puVar11[4] - *pfVar2);
        }
        bVar5 = false;
        dVar16 = (double)(fVar4 / (float)((double)CONCAT44(0x43300000,iVar10) - dVar14));
        for (puVar8 = DAT_803defd8; puVar8 != (undefined4 *)0x0; puVar8 = (undefined4 *)*puVar8) {
          if ((undefined4 *)puVar8[2] == puVar11) {
            bVar5 = true;
            break;
          }
        }
        uVar7 = (uint)DAT_803defe9;
        if (~(-1 << uVar7) == (~(-1 << uVar7) & DAT_803defe4)) {
          dVar12 = (double)FLOAT_803e8528;
          for (puVar8 = DAT_803defdc; puVar8 != (undefined4 *)0x0; puVar8 = (undefined4 *)*puVar8) {
            if ((*(char *)(puVar8 + 7) != -1) && (dVar12 < (double)(float)puVar8[6])) {
              unaff_r30 = puVar8;
              dVar12 = (double)(float)puVar8[6];
            }
          }
          puVar8 = DAT_803defd4;
          if ((!bVar5) && (dVar12 <= dVar16)) goto LAB_80280618;
          for (; puVar8 != (undefined4 *)0x0; puVar8 = (undefined4 *)*puVar8) {
            if ((undefined4 *)puVar8[2] == unaff_r30) {
              FUN_80272224(puVar8[0xf]);
              puVar8[4] = puVar8[4] | 0x80000;
              puVar8[0xf] = 0xffffffff;
            }
          }
          if ((code *)unaff_r30[9] != (code *)0x0) {
            (*(code *)unaff_r30[9])(*(undefined *)(unaff_r30 + 7));
          }
          FUN_802734d8((uint)*(byte *)(unaff_r30 + 7));
          *(undefined *)(puVar11 + 7) = *(undefined *)(unaff_r30 + 7);
          *(undefined *)(unaff_r30 + 7) = 0xff;
          unaff_r30[2] = 0;
        }
        else {
          for (iVar9 = 0; (uVar7 != 0 && ((DAT_803defe4 & 1 << iVar9) != 0)); iVar9 = iVar9 + 1) {
            uVar7 = uVar7 - 1;
          }
          DAT_803defe4 = DAT_803defe4 | 1 << iVar9;
          *(char *)(puVar11 + 7) = (char)iVar9 + DAT_803defe8;
        }
        puVar11[6] = (float)dVar16;
        if (bVar5) {
          uVar6 = 0x7f0000;
        }
        else {
          uVar6 = 0;
        }
        puVar11[0xb] = uVar6;
        if ((double)(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,puVar11[0xb]) -
                                                    dVar14)) < dVar15) {
          FUN_80273428((uint)*(byte *)(puVar11 + 7),0,0);
        }
        else {
          FUN_80273428((uint)*(byte *)(puVar11 + 7),1,0);
        }
        if ((code *)puVar11[8] != (code *)0x0) {
          (*(code *)puVar11[8])(*(undefined *)(puVar11 + 7),puVar11[10]);
        }
      }
      else {
        if ((puVar11[2] & 0x80000000) != 0) {
          puVar11[0xb] = puVar11[0xb] + 0x40000;
          if (0x7effff < (uint)puVar11[0xb]) {
            puVar11[0xb] = 0x7f0000;
            puVar11[2] = puVar11[2] & 0x7fffffff;
          }
          if ((double)(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,puVar11[0xb]) -
                                                      dVar14)) < dVar15) {
            FUN_80273428((uint)*(byte *)(puVar11 + 7),0,0);
          }
          else {
            FUN_80273428((uint)*(byte *)(puVar11 + 7),1,0);
          }
        }
        if ((puVar11[2] & 0x40000000) != 0) {
          puVar11[0xb] = puVar11[0xb] + -0x40000;
          if (-1 < (int)puVar11[0xb]) {
            puVar11[0xb] = 0;
            puVar11[2] = puVar11[2] & 0xbfffffff;
          }
          if ((double)(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,puVar11[0xb]) -
                                                      dVar14)) < dVar15) {
            FUN_80273428((uint)*(byte *)(puVar11 + 7),0,0);
          }
          else {
            FUN_80273428((uint)*(byte *)(puVar11 + 7),1,0);
          }
        }
      }
LAB_80280618:
    }
  }
  return;
}

