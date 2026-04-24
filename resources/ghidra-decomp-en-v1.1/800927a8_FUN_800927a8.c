// Function: FUN_800927a8
// Entry: 800927a8
// Size: 2376 bytes

/* WARNING: Removing unreachable block (ram,0x800930d0) */
/* WARNING: Removing unreachable block (ram,0x800927b8) */

void FUN_800927a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,float *param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short *psVar1;
  int iVar2;
  uint uVar3;
  float *pfVar4;
  undefined4 extraout_r4;
  undefined4 uVar5;
  int *piVar6;
  int iVar7;
  char cVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  double dVar12;
  double in_f31;
  double dVar13;
  double in_ps31_1;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4 [2];
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  ushort local_9c [4];
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float afStack_84 [13];
  undefined8 local_50;
  undefined8 local_48;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  dVar12 = (double)FUN_80286830();
  iVar10 = 0;
  iVar7 = 0;
  uVar5 = extraout_r4;
  psVar1 = FUN_8000facc();
  cVar8 = '\0';
  iVar9 = 0;
  dVar13 = (double)FLOAT_803dfec8;
  if (DAT_803dde40 == '\0') {
    DAT_803dde48 = FUN_80054ed0(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x16a
                                ,uVar5,param_11,param_12,param_13,param_14,param_15,param_16);
    DAT_8039b478 = FUN_80054ed0(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x5da
                                ,uVar5,param_11,param_12,param_13,param_14,param_15,param_16);
    DAT_8039b47c = FUN_80054ed0(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x63f
                                ,uVar5,param_11,param_12,param_13,param_14,param_15,param_16);
    DAT_8039b480 = FUN_80054ed0(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x640
                                ,uVar5,param_11,param_12,param_13,param_14,param_15,param_16);
    DAT_8039b484 = FUN_80054ed0(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x641
                                ,uVar5,param_11,param_12,param_13,param_14,param_15,param_16);
    DAT_803dde44 = FUN_80054ed0(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x151
                                ,uVar5,param_11,param_12,param_13,param_14,param_15,param_16);
    DAT_803dde40 = '\x01';
  }
  iVar2 = FUN_80008b4c(-1);
  if ((short)iVar2 != 1) {
    DAT_803dde4c = DAT_803dde1b;
    DAT_803dde1b = '\0';
    while (iVar10 < 8) {
      piVar11 = (int *)((int)&DAT_8039b488 + iVar7);
      piVar6 = (int *)*piVar11;
      if ((piVar6 == (int *)0x0) || ((*piVar6 != 0 && ((*(ushort *)(*piVar6 + 0xb0) & 0x40) == 0))))
      {
        if ((piVar6 == (int *)0x0) || (piVar6[0x500] == 0)) {
          if ((piVar6 != (int *)0x0) && (*(char *)((int)piVar6 + 0x144f) == '\0')) {
            if (piVar6[0x4fd] == 4) {
              DAT_803dde1b = '\x01';
            }
            if (piVar6[0x4fe] == 0) {
              if ((int)(float)piVar6[0x50d] < piVar6[0x4ff]) {
                local_50 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
                piVar6[0x50d] =
                     (int)((float)(local_50 - DOUBLE_803dfe30) * (float)piVar6[0x50b] +
                          (float)piVar6[0x50d]);
              }
            }
            else {
              local_50 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
              piVar6[0x50d] =
                   (int)((float)(local_50 - DOUBLE_803dfe30) * (float)piVar6[0x50c] +
                        (float)piVar6[0x50d]);
              if (*(float *)(*piVar11 + 0x1434) <= FLOAT_803dfe20) {
                *(undefined *)(*piVar11 + 0x144f) = 1;
              }
            }
            iVar2 = *piVar11;
            local_50 = (double)(longlong)(int)*(float *)(iVar2 + 0x1434);
            if ((int)*(uint *)(iVar2 + 0x13fc) < (int)*(float *)(iVar2 + 0x1434)) {
              local_50 = (double)CONCAT44(0x43300000,*(uint *)(iVar2 + 0x13fc) ^ 0x80000000);
              *(float *)(iVar2 + 0x1434) = (float)(local_50 - DOUBLE_803dfe28);
            }
            if (*(float *)(*piVar11 + 0x1434) < FLOAT_803dfe20) {
              *(float *)(*piVar11 + 0x1434) = FLOAT_803dfe20;
            }
            if (*(int *)*piVar11 != 0) {
              param_12 = &local_b8;
              FUN_8000e12c(*(int *)*piVar11,&local_c0,&local_bc,&local_b8);
            }
            if ((*(char *)(*piVar11 + 0x1452) != '\0') && (psVar1 != (short *)0x0)) {
              if (*(int *)(*piVar11 + 0x13f4) == 4) {
                local_cc = FLOAT_803dfe20;
                local_c8 = FLOAT_803dfe20;
                local_c4 = FLOAT_803dfe7c;
                local_90 = FLOAT_803dfe20;
                local_8c = FLOAT_803dfe20;
                local_88 = FLOAT_803dfe20;
                local_94 = FLOAT_803dfe24;
                local_9c[2] = 0;
                local_9c[1] = 0;
                local_9c[0] = -*psVar1 - 1;
                FUN_80021b8c(local_9c,&local_cc);
                local_c0 = *(float *)(psVar1 + 0x22) + local_cc;
                local_bc = (*(float *)(psVar1 + 0x24) - FLOAT_803dfecc) + local_c8;
                local_b8 = *(float *)(psVar1 + 0x26) + local_c4;
              }
              else {
                local_c0 = *(float *)(psVar1 + 0x22);
                local_bc = *(float *)(psVar1 + 0x24) - FLOAT_803dfecc;
                local_b8 = *(float *)(psVar1 + 0x26);
              }
            }
            iVar2 = *piVar11;
            local_50 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
            param_2 = (double)(float)(local_50 - DOUBLE_803dfe30);
            *(float *)(iVar2 + 0x1440) =
                 (float)(param_2 * (double)*(float *)(iVar2 + 0x1444) +
                        (double)*(float *)(iVar2 + 0x1440));
            iVar2 = *piVar11;
            if ((double)FLOAT_803dfe20 != (double)*(float *)(iVar2 + 0x1438)) {
              param_2 = (double)*(float *)(iVar2 + 0x1440);
              if (param_2 <= (double)*(float *)(iVar2 + 0x143c)) {
                if (param_2 < (double)FLOAT_803dfe20) {
                  *(float *)(iVar2 + 0x1444) = *(float *)(iVar2 + 0x1444) * FLOAT_803dfec4;
                  uVar3 = (uint)(FLOAT_803dfe48 * *(float *)(*piVar11 + 0x1438));
                  local_50 = (double)(longlong)(int)uVar3;
                  uVar3 = FUN_80022264(1,uVar3);
                  local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
                  *(float *)(*piVar11 + 0x143c) = (float)(local_48 - DOUBLE_803dfe28);
                  *(float *)(*piVar11 + 0x1440) = FLOAT_803dfe20;
                }
              }
              else {
                *(float *)(iVar2 + 0x1444) = *(float *)(iVar2 + 0x1444) * FLOAT_803dfec4;
                *(undefined4 *)(*piVar11 + 0x1440) = *(undefined4 *)(*piVar11 + 0x143c);
              }
            }
            param_11 = *piVar11;
            if (*(char *)(param_11 + 0x144d) == '\0') {
              local_a8 = local_c0;
              local_a4 = local_bc;
              local_a0 = local_b8;
              dVar12 = (double)FUN_8009194c((double)*(float *)(param_11 + 0x1438),local_b4,&local_a8
                                           );
              iVar2 = *piVar11;
              if (*(int *)(iVar2 + 0x13f4) == 0) {
                *(float *)(iVar2 + 0x1420) = -local_b4[0];
                *(float *)(*piVar11 + 0x1424) = -local_ac;
              }
              else {
                *(float *)(iVar2 + 0x1420) = -(local_b4[0] + *(float *)(iVar2 + 0x1440));
                dVar12 = (double)local_ac;
                *(float *)(*piVar11 + 0x1424) =
                     -(float)(dVar12 + (double)*(float *)(*piVar11 + 0x1440));
                *(float *)(*piVar11 + 0x1428) = FLOAT_803dfe20;
              }
              *(float *)(*piVar11 + 0x140c) = local_c0;
              *(float *)(*piVar11 + 0x1410) = local_bc;
              *(float *)(*piVar11 + 0x1414) = local_b8;
            }
            else {
              local_a8 = *(float *)(param_11 + 0x140c);
              local_a4 = *(float *)(param_11 + 0x1410);
              local_a0 = *(float *)(param_11 + 0x1414);
              FUN_8009194c((double)*(float *)(param_11 + 0x1438),local_b4,&local_a8);
              *(float *)(*piVar11 + 0x1420) = -local_b4[0] + *(float *)(*piVar11 + 0x1440);
              dVar12 = -(double)local_ac;
              *(float *)(*piVar11 + 0x1424) =
                   (float)(dVar12 + (double)*(float *)(*piVar11 + 0x1440));
              *(float *)(*piVar11 + 0x1428) = FLOAT_803dfe20;
            }
            iVar2 = *piVar11;
            if (*(char *)(iVar2 + 0x1453) == '\0') {
              *(float *)(iVar2 + 0x13e4) = local_c0;
              *(float *)(*piVar11 + 0x13e8) = local_bc;
              *(float *)(*piVar11 + 0x13ec) = local_b8;
              *(undefined *)(*piVar11 + 0x1453) = 1;
            }
            else {
              *(undefined4 *)(iVar2 + 0x13e4) = *(undefined4 *)(iVar2 + 0x13d8);
              *(undefined4 *)(*piVar11 + 0x13e8) = *(undefined4 *)(*piVar11 + 0x13dc);
              *(undefined4 *)(*piVar11 + 0x13ec) = *(undefined4 *)(*piVar11 + 0x13e0);
            }
            *(float *)(*piVar11 + 0x13d8) = local_c0;
            *(float *)(*piVar11 + 0x13dc) = local_bc;
            *(float *)(*piVar11 + 0x13e0) = local_b8;
            FUN_80091214(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            iVar2 = *piVar11;
            dVar12 = (double)*(float *)(iVar2 + 0x1434);
            if ((double)FLOAT_803dfe20 < dVar12) {
              local_d8 = *(float *)(iVar2 + 0x140c) - *(float *)(psVar1 + 6);
              local_d4 = *(float *)(iVar2 + 0x1410) - *(float *)(psVar1 + 8);
              local_d0 = *(float *)(iVar2 + 0x1414) - *(float *)(psVar1 + 10);
              dVar12 = FUN_80247f54(&local_d8);
              if (dVar12 < dVar13) {
                iVar9 = *piVar11;
                dVar13 = dVar12;
              }
            }
          }
        }
        else {
          param_2 = (double)(float)piVar6[0x507];
          dVar12 = (double)FUN_8008ff28((double)(float)piVar6[0x506],param_2,param_3,param_4,param_5
                                        ,param_6,param_7,param_8);
        }
        iVar2 = *piVar11;
        if (((iVar2 != 0) && (*(int *)(iVar2 + 0x13f4) == 4)) && (*(char *)(iVar2 + 0x144d) == '\0')
           ) {
          cVar8 = cVar8 + '\x01';
        }
        iVar10 = iVar10 + 1;
        iVar7 = iVar7 + 4;
      }
      else {
        dVar12 = (double)FUN_80090304(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,piVar6[0x4fc],piVar6,param_11,param_12,param_13,param_14,
                                      param_15,param_16);
        iVar10 = iVar10 + 1;
        iVar7 = iVar7 + 4;
      }
    }
    FLOAT_803dde14 = FLOAT_803dfed0;
    if (cVar8 != '\0') {
      FLOAT_803dde14 = FLOAT_803dfe3c;
    }
    if ((DAT_803dde1c != 0) &&
       (*(short *)(DAT_803dde1c + 0x20) = *(short *)(DAT_803dde1c + 0x20) + 1,
       *(ushort *)(DAT_803dde1c + 0x22) <= *(ushort *)(DAT_803dde1c + 0x20))) {
      FUN_800238c4(DAT_803dde1c);
      DAT_803dde1c = 0;
    }
    FLOAT_803dde3c = FLOAT_803dfed4 * FLOAT_803dc074 + FLOAT_803dde3c;
    if (FLOAT_803dfed8 < FLOAT_803dde3c) {
      FLOAT_803dde3c = FLOAT_803dde3c - FLOAT_803dfed8;
    }
    FLOAT_803dde38 = FLOAT_803dfedc * FLOAT_803dc074 + FLOAT_803dde38;
    if (FLOAT_803dfed8 < FLOAT_803dde38) {
      FLOAT_803dde38 = FLOAT_803dde38 - FLOAT_803dfed8;
    }
    FLOAT_803dde34 = -(FLOAT_803dfee0 * FLOAT_803dc074 - FLOAT_803dde34);
    if (FLOAT_803dde34 < FLOAT_803dfee4) {
      FLOAT_803dde34 = FLOAT_803dde34 + FLOAT_803dfed8;
    }
    FLOAT_803dc3c0 = FLOAT_803dc3c0 + FLOAT_803dde14;
    if (FLOAT_803dc3c0 <= FLOAT_803dfe24) {
      if (FLOAT_803dc3c0 < FLOAT_803dfe20) {
        FLOAT_803dc3c0 = FLOAT_803dfe20;
      }
    }
    else {
      FLOAT_803dc3c0 = FLOAT_803dfe24;
    }
    DAT_803dde18 = 0;
    if ((iVar9 != 0) && (*(int *)(iVar9 + 0x13f4) == 4)) {
      uVar3 = (uint)(FLOAT_803dfe54 * FLOAT_803dc3c0);
      local_48 = (double)(longlong)(int)uVar3;
      DAT_803dde18 = (undefined)uVar3;
      if ((uVar3 & 0xff) != 0) {
        dVar13 = (double)((FLOAT_803dfe44 *
                          FLOAT_803dfe48 *
                          -(FLOAT_803dfe8c * (*(float *)(iVar9 + 0x1440) / FLOAT_803dfe90) +
                           FLOAT_803dfe88)) / FLOAT_803dfee8);
        DAT_8039b550 = FLOAT_803dfe20;
        DAT_8039b554 = FLOAT_803dfec4;
        DAT_8039b558 = FLOAT_803dfe20;
        pfVar4 = (float *)FUN_8000f554();
        if (*(int *)(iVar9 + 0x13f4) == 0) {
          FLOAT_803dde10 = FLOAT_803dfe80 * FLOAT_803dfeec * FLOAT_803dc074 + FLOAT_803dde10;
          FLOAT_803dc3c4 = FLOAT_803dfef0;
          DAT_803dde19 = 0xf9;
          DAT_803dde1a = 0xfd;
          FLOAT_803dc3c8 = FLOAT_803dfef4;
          FUN_802475b8(afStack_84);
        }
        else {
          FLOAT_803dde10 = FLOAT_803dfeec * FLOAT_803dc074 + FLOAT_803dde10;
          FLOAT_803dc3c4 = FLOAT_803dfe24;
          DAT_803dde19 = 0xf8;
          DAT_803dde1a = 0xfc;
          FLOAT_803dc3c8 = FLOAT_803dfe24;
          FUN_8024782c(dVar13,afStack_84,0x7a);
        }
        FUN_80247618(pfVar4,afStack_84,afStack_84);
        FUN_80247bf8(afStack_84,&DAT_8039b550,&DAT_8039b550);
        if (FLOAT_803dde10 < FLOAT_803dfef8) {
          FLOAT_803dde10 = FLOAT_803dde10 + FLOAT_803dfe68;
        }
      }
    }
    if ((DAT_803dde1b == '\0') || (DAT_803dde4c != '\0')) {
      if ((DAT_803dde1b == '\0') && (DAT_803dde4c != '\0')) {
        FUN_8000a538((int *)0xeb,0);
      }
    }
    else {
      FUN_8000a538((int *)0xeb,1);
    }
  }
  FUN_8028687c();
  return;
}

