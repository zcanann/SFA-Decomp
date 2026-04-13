// Function: FUN_80232ef4
// Entry: 80232ef4
// Size: 1344 bytes

/* WARNING: Removing unreachable block (ram,0x80233418) */
/* WARNING: Removing unreachable block (ram,0x80232fd0) */
/* WARNING: Removing unreachable block (ram,0x80232f04) */

void FUN_80232ef4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  bool bVar2;
  ushort *puVar3;
  int iVar4;
  uint uVar5;
  float fVar6;
  int iVar7;
  int iVar8;
  ushort *puVar9;
  float *pfVar10;
  double extraout_f1;
  double dVar11;
  double dVar12;
  undefined8 local_40;
  undefined8 local_30;
  
  puVar3 = (ushort *)FUN_80286840();
  pfVar10 = *(float **)(puVar3 + 0x5c);
  iVar8 = *(int *)(puVar3 + 0x26);
  if ((*(char *)((int)pfVar10 + 0x159) == '\x04') || (*(char *)((int)pfVar10 + 0x159) == '\x03'))
  goto LAB_80233418;
  dVar11 = extraout_f1;
  if (*(char *)((int)pfVar10 + 0x15d) == '\x01') {
    iVar4 = FUN_8022de2c();
    if (iVar4 == 0) {
      iVar4 = FUN_8002bac4();
    }
    dVar11 = (double)(*(float *)(puVar3 + 10) - *(float *)(iVar4 + 0x14));
    bVar2 = false;
    if ((dVar11 < (double)FLOAT_803e7e50) && ((double)FLOAT_803e7dfc < dVar11)) {
      bVar2 = true;
    }
    if (bVar2) {
      uVar5 = FUN_80022264(0,1);
      if (uVar5 == 0) {
        dVar11 = (double)FUN_80125e88(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,0xd);
      }
      else {
        dVar11 = (double)FUN_80125e88(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,0x10);
      }
      *(undefined *)((int)pfVar10 + 0x15d) = 0;
    }
  }
  bVar1 = *(byte *)((int)pfVar10 + 0x159);
  if (bVar1 != 2) {
    if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar8 = *(int *)(puVar3 + 0x26);
        FUN_8022de2c();
        puVar9 = puVar3;
        if (0 < *(int *)(iVar8 + 0x20)) {
          if (pfVar10[0x4f] == 0.0) {
            fVar6 = (float)FUN_8002e1ac(*(int *)(iVar8 + 0x20));
            pfVar10[0x4f] = fVar6;
          }
          puVar9 = (ushort *)pfVar10[0x4f];
        }
        if (puVar9 == (ushort *)0x0) {
LAB_802330c4:
          bVar2 = false;
        }
        else {
          dVar11 = (double)pfVar10[0x4c];
          iVar4 = FUN_8022de2c();
          if (iVar4 == 0) {
            iVar4 = FUN_8002bac4();
          }
          dVar12 = (double)(*(float *)(puVar9 + 10) - *(float *)(iVar4 + 0x14));
          bVar2 = false;
          if ((dVar12 < dVar11) && ((double)FLOAT_803e7dfc < dVar12)) {
            bVar2 = true;
          }
          if (!bVar2) goto LAB_802330c4;
          if (*(short *)(iVar8 + 0x32) < 1) {
            dVar11 = (double)pfVar10[0x4d];
            iVar4 = FUN_8022de2c();
            if (iVar4 == 0) {
              iVar4 = FUN_8002bac4();
            }
            dVar12 = (double)(*(float *)(puVar9 + 10) - *(float *)(iVar4 + 0x14));
            bVar2 = false;
            if ((dVar12 < dVar11) && ((double)FLOAT_803e7dfc < dVar12)) {
              bVar2 = true;
            }
            if (!bVar2) goto LAB_802330ac;
          }
          else {
LAB_802330ac:
            uVar5 = FUN_80020078((int)*(short *)(iVar8 + 0x32));
            if (uVar5 == 0) goto LAB_802330c4;
          }
          bVar2 = true;
        }
        if (bVar2) {
          puVar3[3] = puVar3[3] & 0xbfff;
          FUN_80036018((int)puVar3);
          *(undefined *)((int)pfVar10 + 0x159) = 1;
          iVar8 = *(int *)(puVar3 + 0x26);
          if (*(char *)(pfVar10 + 0x57) == '\x01') {
            *(byte *)(pfVar10 + 0x58) = *(byte *)(pfVar10 + 0x58) & 0xdf;
            FUN_800803f8(pfVar10 + 0x49);
            FUN_80080404(pfVar10 + 0x49,(ushort)*(byte *)(iVar8 + 0x2c));
          }
        }
        goto LAB_80233418;
      }
      *(undefined *)(puVar3 + 0x1b) = 0xff;
      iVar4 = *(int *)(puVar3 + 0x26);
      FUN_8022de2c();
      puVar9 = puVar3;
      if ((ushort *)pfVar10[0x4f] != (ushort *)0x0) {
        puVar9 = (ushort *)pfVar10[0x4f];
      }
      if (puVar9 == (ushort *)0x0) {
LAB_80233200:
        bVar2 = false;
      }
      else {
        dVar12 = (double)pfVar10[0x4c];
        iVar7 = FUN_8022de2c();
        if (iVar7 == 0) {
          iVar7 = FUN_8002bac4();
        }
        dVar11 = (double)(*(float *)(puVar9 + 10) - *(float *)(iVar7 + 0x14));
        bVar2 = false;
        if ((dVar11 < dVar12) && ((double)FLOAT_803e7dfc < dVar11)) {
          bVar2 = true;
        }
        if (bVar2) goto LAB_80233200;
        if (*(short *)(iVar4 + 0x32) < 1) {
          dVar12 = (double)pfVar10[0x4d];
          iVar7 = FUN_8022de2c();
          if (iVar7 == 0) {
            iVar7 = FUN_8002bac4();
          }
          dVar11 = (double)(*(float *)(puVar9 + 10) - *(float *)(iVar7 + 0x14));
          bVar2 = false;
          if ((dVar11 < dVar12) && ((double)FLOAT_803e7dfc < dVar11)) {
            bVar2 = true;
          }
          if (bVar2) goto LAB_802331e8;
        }
        else {
LAB_802331e8:
          uVar5 = FUN_80020078((int)*(short *)(iVar4 + 0x32));
          if (uVar5 != 0) goto LAB_80233200;
        }
        bVar2 = true;
      }
      dVar12 = DOUBLE_803e7e10;
      if (bVar2) {
        puVar3[3] = puVar3[3] | 0x4000;
        FUN_80035ff8((int)puVar3);
        *(undefined *)((int)pfVar10 + 0x159) = 4;
        goto LAB_80233418;
      }
      if (*(char *)(pfVar10 + 0x57) != '\x02') {
        if (*(char *)(iVar8 + 0x2f) != '\x02') {
          *puVar3 = (ushort)(int)((float)((double)CONCAT44(0x43300000,
                                                           (int)*(short *)(pfVar10 + 0x50) ^
                                                           0x80000000) - DOUBLE_803e7e10) *
                                  FLOAT_803dc074 +
                                 (float)((double)CONCAT44(0x43300000,
                                                          (int)(short)*puVar3 ^ 0x80000000) -
                                        DOUBLE_803e7e10));
          local_40 = (double)CONCAT44(0x43300000,(int)*(short *)((int)pfVar10 + 0x142) ^ 0x80000000)
          ;
          param_2 = (double)(float)(local_40 - dVar12);
          dVar11 = (double)FLOAT_803dc074;
          puVar3[1] = (ushort)(int)(param_2 * dVar11 +
                                   (double)(float)((double)CONCAT44(0x43300000,
                                                                    (int)(short)puVar3[1] ^
                                                                    0x80000000) - dVar12));
          param_3 = dVar12;
        }
        dVar12 = DOUBLE_803e7e10;
        if (((*(byte *)(pfVar10 + 0x58) >> 3 & 1) != 0) || (*(char *)(iVar8 + 0x2f) != '\x02')) {
          local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar10 + 0x51) ^ 0x80000000);
          param_2 = (double)(float)(local_30 - DOUBLE_803e7e10);
          dVar11 = (double)FLOAT_803dc074;
          puVar3[2] = (ushort)(int)(param_2 * dVar11 +
                                   (double)(float)((double)CONCAT44(0x43300000,
                                                                    (int)(short)puVar3[2] ^
                                                                    0x80000000) - DOUBLE_803e7e10));
          param_3 = dVar12;
        }
      }
      if (pfVar10[0x4f] == 0.0) {
        if ((*(byte *)(pfVar10 + 0x58) >> 6 & 1) != 0) {
          dVar11 = (double)FUN_802327fc(puVar3,pfVar10);
        }
      }
      else {
        dVar11 = (double)FUN_802324f4();
      }
      if (*(char *)(pfVar10 + 0x58) < '\0') {
        iVar8 = *(int *)(puVar3 + 0x26);
        dVar11 = (double)FUN_80035eec((int)puVar3,0x13,*(undefined *)((int)pfVar10 + 0x156),0);
        if (*(char *)(pfVar10 + 0x57) == '\x01') {
          dVar11 = (double)FUN_80232d40(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,
                                        param_8,(short *)puVar3,(int)pfVar10,iVar8);
        }
      }
    }
    else if (bVar1 < 5) goto LAB_80233418;
  }
  FUN_80232a70(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)puVar3,
               (int)pfVar10);
  if (*(char *)(pfVar10 + 0x57) == '\x01') {
    FUN_80232154((int)puVar3,(int)pfVar10);
  }
  if (*(int *)(*(int *)(puVar3 + 0x28) + 0x44) == 0) {
    FUN_8002fb40((double)FLOAT_803e7e54,(double)FLOAT_803dc074);
  }
LAB_80233418:
  FUN_8028688c();
  return;
}

