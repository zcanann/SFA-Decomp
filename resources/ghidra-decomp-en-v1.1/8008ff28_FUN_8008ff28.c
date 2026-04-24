// Function: FUN_8008ff28
// Entry: 8008ff28
// Size: 988 bytes

/* WARNING: Removing unreachable block (ram,0x800902e4) */
/* WARNING: Removing unreachable block (ram,0x800902dc) */
/* WARNING: Removing unreachable block (ram,0x800902d4) */
/* WARNING: Removing unreachable block (ram,0x800902cc) */
/* WARNING: Removing unreachable block (ram,0x800902c4) */
/* WARNING: Removing unreachable block (ram,0x800902bc) */
/* WARNING: Removing unreachable block (ram,0x8008ff60) */
/* WARNING: Removing unreachable block (ram,0x8008ff58) */
/* WARNING: Removing unreachable block (ram,0x8008ff50) */
/* WARNING: Removing unreachable block (ram,0x8008ff48) */
/* WARNING: Removing unreachable block (ram,0x8008ff40) */
/* WARNING: Removing unreachable block (ram,0x8008ff38) */

void FUN_8008ff28(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  float *pfVar6;
  double extraout_f1;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_8028683c();
  iVar5 = (int)uVar12;
  dVar11 = (double)((float)(extraout_f1 * param_2) * FLOAT_803dfe60);
  iVar4 = 0;
  if (((((((DAT_8039b488 == 0) || (iVar1 = DAT_8039b488, iVar5 != *(int *)(DAT_8039b488 + 0x13f0)))
         && ((iVar4 = 1, DAT_8039b48c == 0 ||
             (iVar1 = DAT_8039b48c, iVar5 != *(int *)(DAT_8039b48c + 0x13f0))))) &&
        ((iVar4 = 2, DAT_8039b490 == 0 ||
         (iVar1 = DAT_8039b490, iVar5 != *(int *)(DAT_8039b490 + 0x13f0))))) &&
       ((iVar4 = 3, DAT_8039b494 == 0 ||
        (iVar1 = DAT_8039b494, iVar5 != *(int *)(DAT_8039b494 + 0x13f0))))) &&
      ((((iVar4 = 4, DAT_8039b498 == 0 ||
         (iVar1 = DAT_8039b498, iVar5 != *(int *)(DAT_8039b498 + 0x13f0))) &&
        ((iVar4 = 5, DAT_8039b49c == 0 ||
         (iVar1 = DAT_8039b49c, iVar5 != *(int *)(DAT_8039b49c + 0x13f0))))) &&
       ((iVar4 = 6, DAT_8039b4a0 == 0 ||
        (iVar1 = DAT_8039b4a0, iVar5 != *(int *)(DAT_8039b4a0 + 0x13f0))))))) &&
     ((iVar4 = 7, iVar1 = DAT_8039b4a4, DAT_8039b4a4 == 0 ||
      (iVar5 != *(int *)(DAT_8039b4a4 + 0x13f0))))) {
    iVar4 = 8;
  }
  iVar2 = (&DAT_8039b488)[iVar4];
  if ((iVar2 != 0) && (dVar7 = (double)FLOAT_803dfe64, dVar7 != (double)FLOAT_803dde2c)) {
    if (iVar5 == *(int *)(iVar2 + 0x13f0)) {
      if (*(int *)(iVar2 + 0x13f4) != 4) {
        dVar7 = (double)FLOAT_803dfe68;
      }
      iVar5 = 0;
      pfVar6 = (float *)(iVar2 + 0x1008);
      dVar10 = -dVar7;
      dVar9 = (double)(float)((double)FLOAT_803dfe6c * dVar10);
      dVar8 = (double)FLOAT_803dfe20;
      do {
        *pfVar6 = (float)dVar10;
        pfVar6[6] = (float)dVar8;
        pfVar6[1] = (float)dVar7;
        pfVar6[7] = (float)dVar8;
        pfVar6[2] = (float)dVar8;
        pfVar6[8] = (float)dVar8;
        if (*(int *)((&DAT_8039b488)[iVar4] + 0x13f4) == 0) {
          pfVar6[3] = (float)dVar10;
          pfVar6[4] = (float)dVar10;
          pfVar6[5] = (float)dVar7;
        }
        else {
          pfVar6[3] = (float)dVar10;
          pfVar6[4] = (float)dVar10;
          pfVar6[5] = (float)dVar9;
        }
        uVar3 = FUN_80022264(0,0xffff);
        *(short *)(pfVar6 + 10) = (short)uVar3;
        uVar3 = FUN_80022264(0,0xffff);
        *(short *)((int)pfVar6 + 0x2a) = (short)uVar3;
        uVar3 = FUN_80022264(0x96,500);
        *(short *)(pfVar6 + 9) = (short)uVar3;
        uVar3 = FUN_80022264(0x96,500);
        *(short *)((int)pfVar6 + 0x26) = (short)uVar3;
        pfVar6 = pfVar6 + 0xb;
        iVar5 = iVar5 + 1;
      } while (iVar5 < 0x14);
      iVar5 = *(int *)((&DAT_8039b488)[iVar4] + 0x1408);
      pfVar6 = (float *)((int)((ulonglong)uVar12 >> 0x20) + iVar5 * 4);
      dVar8 = (double)FLOAT_803dfe78;
      dVar9 = (double)FLOAT_803dfe24;
      dVar7 = DOUBLE_803dfe28;
      while( true ) {
        iVar1 = *(int *)((&DAT_8039b488)[iVar4] + 0x1408) + 4000;
        if (iVar1 <= iVar5) break;
        if (iVar5 == 0x400) {
          *(undefined4 *)((&DAT_8039b488)[iVar4] + 0x1400) = 0;
          *(undefined4 *)((&DAT_8039b488)[iVar4] + 0x1408) = 0;
          goto LAB_800902bc;
        }
        if (iVar5 == 0) {
          DAT_803dde28 = 0;
          FLOAT_803dde2c = FLOAT_803dfe20;
          FLOAT_803dde30 = FLOAT_803dfe20;
        }
        FUN_802945e0();
        FUN_80294964();
        *pfVar6 = (float)((double)FLOAT_803dde2c * dVar11);
        DAT_803dde28 = (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                                     (int)DAT_803dde28 ^ 0x80000000)
                                                   - dVar7) + dVar8);
        FLOAT_803dde2c = (float)((double)FLOAT_803dde2c + dVar9);
        pfVar6 = pfVar6 + 1;
        iVar5 = iVar5 + 1;
      }
      *(int *)((&DAT_8039b488)[iVar4] + 0x1408) = iVar1;
    }
    else {
      FUN_80137c30(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   s_____Error_non_existant_cloud_id___803101b0,iVar5,iVar1,iVar4,in_r7,in_r8,in_r9,
                   in_r10);
    }
  }
LAB_800902bc:
  FUN_80286888();
  return;
}

