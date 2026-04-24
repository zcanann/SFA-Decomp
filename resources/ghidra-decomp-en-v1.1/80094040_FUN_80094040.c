// Function: FUN_80094040
// Entry: 80094040
// Size: 1464 bytes

/* WARNING: Removing unreachable block (ram,0x800945d8) */
/* WARNING: Removing unreachable block (ram,0x800945d0) */
/* WARNING: Removing unreachable block (ram,0x80094058) */
/* WARNING: Removing unreachable block (ram,0x80094050) */

void FUN_80094040(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int iVar2;
  float *pfVar3;
  uint uVar4;
  undefined4 extraout_r4;
  undefined4 uVar5;
  undefined4 uVar6;
  float *pfVar7;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  undefined2 *puVar10;
  uint *puVar11;
  undefined8 uVar12;
  double in_f30;
  double dVar13;
  double dVar14;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  float local_c8;
  float local_c4;
  float local_c0;
  float afStack_bc [12];
  float afStack_8c [13];
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  FUN_80286834();
  FUN_8025898c(1,0);
  FUN_80022e00(0);
  uVar6 = 0;
  pfVar3 = (float *)FUN_80023d8c(0x4b0,0x7f7f7fff);
  FUN_80022e00(1);
  iVar8 = 0;
  dVar13 = (double)FLOAT_803dff0c;
  pfVar7 = pfVar3;
  dVar14 = DOUBLE_803dff28;
LAB_800940ac:
  do {
    uVar4 = FUN_80022264(0xffffec78,5000);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_c8 = (float)(local_58 - dVar14);
    uVar4 = FUN_80022264(0xffffec78,5000);
    local_50 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_c4 = (float)(local_50 - dVar14);
    uVar4 = FUN_80022264(0xffffec78,5000);
    local_48 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_c0 = (float)(local_48 - dVar14);
    if ((dVar13 == (double)local_c8) && (dVar13 == (double)local_c4)) {
      if (dVar13 == (double)local_c0) goto LAB_800940ac;
    }
    FUN_80247ef8(&local_c8,&local_c8);
    uVar12 = FUN_80247edc((double)FLOAT_803dff10,&local_c8,&local_c8);
    *pfVar7 = local_c8;
    pfVar7[1] = local_c4;
    pfVar7[2] = local_c0;
    pfVar7 = pfVar7 + 3;
    iVar8 = iVar8 + 1;
    if (99 < iVar8) {
      DAT_803dde58 = 1;
      uVar5 = extraout_r4;
      DAT_803dde50 = FUN_80054ed0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  0xc21,extraout_r4,uVar6,in_r6,in_r7,in_r8,in_r9,in_r10);
      DAT_803dde54 = FUN_80054ed0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  0xc22,uVar5,uVar6,in_r6,in_r7,in_r8,in_r9,in_r10);
      iVar8 = 0;
      puVar11 = &DAT_8039b618;
      puVar10 = &DAT_8039b560;
      do {
        uVar4 = FUN_80023d8c(0x220,0x7f7f7fff);
        *puVar11 = uVar4;
        FUN_802420b0(*puVar11,0x220);
        FUN_8025d4a0(*puVar11,0x220);
        FUN_80258a60();
        pfVar7 = (float *)0x32;
        FUN_80259000(0xb8,0,0x32);
        iVar9 = 0;
        do {
          uVar4 = FUN_80022264(0,9);
          if ((int)uVar4 < 5) {
            dVar13 = (double)FLOAT_803dff0c;
            dVar14 = DOUBLE_803dff28;
            do {
              uVar4 = FUN_80022264(0xffffec78,5000);
              local_48 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
              local_c8 = (float)(local_48 - dVar14);
              uVar4 = FUN_80022264(0xffffec78,5000);
              local_50 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
              local_c4 = (float)(local_50 - dVar14);
              uVar4 = FUN_80022264(0xffffec78,5000);
              local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
              local_c0 = (float)(local_58 - dVar14);
              if ((dVar13 != (double)local_c8) || (dVar13 != (double)local_c4)) break;
            } while (dVar13 == (double)local_c0);
            FUN_80247ef8(&local_c8,&local_c8);
            FUN_80247edc((double)FLOAT_803dff10,&local_c8,&local_c8);
          }
          else {
            uVar4 = FUN_80022264(0,99);
            pfVar7 = pfVar3 + uVar4 * 3;
            local_c8 = *pfVar7;
            local_c4 = pfVar7[1];
            local_c0 = pfVar7[2];
            if (ABS(local_c8) <= FLOAT_803dff14) {
              if (ABS(local_c4) <= FLOAT_803dff14) {
                uVar4 = FUN_80022264(0xffff8000,0x8000);
                local_48 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
                FUN_8024782c((double)((FLOAT_803dff18 *
                                      FLOAT_803dff1c *
                                      FLOAT_803dff20 * (float)(local_48 - DOUBLE_803dff28)) /
                                     FLOAT_803dff24),afStack_8c,0x78);
                uVar4 = FUN_80022264(0xffff8000,0x8000);
                local_50 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
                FUN_8024782c((double)((FLOAT_803dff18 *
                                      FLOAT_803dff1c *
                                      FLOAT_803dff20 * (float)(local_50 - DOUBLE_803dff28)) /
                                     FLOAT_803dff24),afStack_bc,0x79);
              }
              else {
                uVar4 = FUN_80022264(0xffff8000,0x8000);
                local_48 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
                FUN_8024782c((double)((FLOAT_803dff18 *
                                      FLOAT_803dff1c *
                                      FLOAT_803dff20 * (float)(local_48 - DOUBLE_803dff28)) /
                                     FLOAT_803dff24),afStack_8c,0x78);
                uVar4 = FUN_80022264(0xffff8000,0x8000);
                local_50 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
                FUN_8024782c((double)((FLOAT_803dff18 *
                                      FLOAT_803dff1c *
                                      FLOAT_803dff20 * (float)(local_50 - DOUBLE_803dff28)) /
                                     FLOAT_803dff24),afStack_bc,0x7a);
              }
            }
            else {
              uVar4 = FUN_80022264(0xffff8000,0x8000);
              local_48 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
              FUN_8024782c((double)((FLOAT_803dff18 *
                                    FLOAT_803dff1c *
                                    FLOAT_803dff20 * (float)(local_48 - DOUBLE_803dff28)) /
                                   FLOAT_803dff24),afStack_8c,0x79);
              uVar4 = FUN_80022264(0xffff8000,0x8000);
              local_50 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
              FUN_8024782c((double)((FLOAT_803dff18 *
                                    FLOAT_803dff1c *
                                    FLOAT_803dff20 * (float)(local_50 - DOUBLE_803dff28)) /
                                   FLOAT_803dff24),afStack_bc,0x7a);
            }
            FUN_80247618(afStack_bc,afStack_8c,afStack_8c);
            pfVar7 = &local_c8;
            FUN_80247cd8(afStack_8c,pfVar7,pfVar7);
          }
          iVar1 = (int)local_c0;
          local_48 = (double)(longlong)iVar1;
          iVar2 = (int)local_c4;
          local_50 = (double)(longlong)iVar2;
          local_58 = (double)(longlong)(int)local_c8;
          DAT_cc008000._0_2_ = (short)(int)local_c8;
          DAT_cc008000._0_2_ = (short)iVar2;
          DAT_cc008000._0_2_ = (short)iVar1;
          DAT_cc008000._0_2_ = 0;
          DAT_cc008000._0_2_ = 0;
          iVar9 = iVar9 + 1;
        } while (iVar9 < 0x32);
        uVar6 = FUN_8025d568(iVar2,iVar1,(uint)pfVar7);
        *puVar10 = (short)uVar6;
        puVar11 = puVar11 + 1;
        puVar10 = puVar10 + 1;
        iVar8 = iVar8 + 1;
        if (0x5b < iVar8) {
          FUN_800238c4((uint)pfVar3);
          FUN_8025898c(1,8);
          FUN_80286880();
          return;
        }
      } while( true );
    }
  } while( true );
}

