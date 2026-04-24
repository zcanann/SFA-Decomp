// Function: FUN_80093db4
// Entry: 80093db4
// Size: 1464 bytes

/* WARNING: Removing unreachable block (ram,0x80094344) */
/* WARNING: Removing unreachable block (ram,0x8009434c) */

void FUN_80093db4(void)

{
  float *pfVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined2 uVar5;
  float *pfVar6;
  int iVar7;
  int iVar8;
  undefined2 *puVar9;
  undefined4 *puVar10;
  undefined4 uVar11;
  undefined8 in_f30;
  double dVar12;
  double dVar13;
  undefined8 in_f31;
  float local_c8;
  float local_c4;
  float local_c0;
  undefined auStack188 [48];
  undefined auStack140 [52];
  double local_58;
  double local_50;
  double local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  FUN_802860d0();
  FUN_80258228(1,0);
  FUN_80022d3c(0);
  pfVar1 = (float *)FUN_80023cc8(0x4b0,0x7f7f7fff,0);
  FUN_80022d3c(1);
  iVar7 = 0;
  dVar12 = (double)FLOAT_803df28c;
  pfVar6 = pfVar1;
  dVar13 = DOUBLE_803df2a8;
LAB_80093e20:
  do {
    uVar2 = FUN_800221a0(0xffffec78,5000);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_c8 = (float)(local_58 - dVar13);
    uVar2 = FUN_800221a0(0xffffec78,5000);
    local_50 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_c4 = (float)(local_50 - dVar13);
    uVar2 = FUN_800221a0(0xffffec78,5000);
    local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_c0 = (float)(local_48 - dVar13);
    if ((dVar12 == (double)local_c8) && (dVar12 == (double)local_c4)) {
      if (dVar12 == (double)local_c0) goto LAB_80093e20;
    }
    FUN_80247794(&local_c8,&local_c8);
    FUN_80247778((double)FLOAT_803df290,&local_c8,&local_c8);
    *pfVar6 = local_c8;
    pfVar6[1] = local_c4;
    pfVar6[2] = local_c0;
    pfVar6 = pfVar6 + 3;
    iVar7 = iVar7 + 1;
    if (99 < iVar7) {
      DAT_803dd1d8 = 1;
      DAT_803dd1d0 = FUN_80054d54(0xc21);
      DAT_803dd1d4 = FUN_80054d54(0xc22);
      iVar7 = 0;
      puVar10 = &DAT_8039a9b8;
      puVar9 = &DAT_8039a900;
      do {
        uVar3 = FUN_80023cc8(0x220,0x7f7f7fff,0);
        *puVar10 = uVar3;
        FUN_802419b8(*puVar10,0x220);
        FUN_8025cd3c(*puVar10,0x220);
        FUN_802582fc();
        FUN_8025889c(0xb8,0,0x32);
        iVar8 = 0;
        do {
          iVar4 = FUN_800221a0(0,9);
          if (iVar4 < 5) {
            dVar12 = (double)FLOAT_803df28c;
            dVar13 = DOUBLE_803df2a8;
            do {
              uVar2 = FUN_800221a0(0xffffec78,5000);
              local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
              local_c8 = (float)(local_48 - dVar13);
              uVar2 = FUN_800221a0(0xffffec78,5000);
              local_50 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
              local_c4 = (float)(local_50 - dVar13);
              uVar2 = FUN_800221a0(0xffffec78,5000);
              local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
              local_c0 = (float)(local_58 - dVar13);
              if ((dVar12 != (double)local_c8) || (dVar12 != (double)local_c4)) break;
            } while (dVar12 == (double)local_c0);
            FUN_80247794(&local_c8,&local_c8);
            FUN_80247778((double)FLOAT_803df290,&local_c8,&local_c8);
          }
          else {
            iVar4 = FUN_800221a0(0,99);
            pfVar6 = pfVar1 + iVar4 * 3;
            local_c8 = *pfVar6;
            local_c4 = pfVar6[1];
            local_c0 = pfVar6[2];
            if (ABS(local_c8) <= FLOAT_803df294) {
              if (ABS(local_c4) <= FLOAT_803df294) {
                uVar2 = FUN_800221a0(0xffff8000,0x8000);
                local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
                FUN_802470c8((double)((FLOAT_803df298 *
                                      FLOAT_803df29c *
                                      FLOAT_803df2a0 * (float)(local_48 - DOUBLE_803df2a8)) /
                                     FLOAT_803df2a4),auStack140,0x78);
                uVar2 = FUN_800221a0(0xffff8000,0x8000);
                local_50 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
                FUN_802470c8((double)((FLOAT_803df298 *
                                      FLOAT_803df29c *
                                      FLOAT_803df2a0 * (float)(local_50 - DOUBLE_803df2a8)) /
                                     FLOAT_803df2a4),auStack188,0x79);
              }
              else {
                uVar2 = FUN_800221a0(0xffff8000,0x8000);
                local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
                FUN_802470c8((double)((FLOAT_803df298 *
                                      FLOAT_803df29c *
                                      FLOAT_803df2a0 * (float)(local_48 - DOUBLE_803df2a8)) /
                                     FLOAT_803df2a4),auStack140,0x78);
                uVar2 = FUN_800221a0(0xffff8000,0x8000);
                local_50 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
                FUN_802470c8((double)((FLOAT_803df298 *
                                      FLOAT_803df29c *
                                      FLOAT_803df2a0 * (float)(local_50 - DOUBLE_803df2a8)) /
                                     FLOAT_803df2a4),auStack188,0x7a);
              }
            }
            else {
              uVar2 = FUN_800221a0(0xffff8000,0x8000);
              local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
              FUN_802470c8((double)((FLOAT_803df298 *
                                    FLOAT_803df29c *
                                    FLOAT_803df2a0 * (float)(local_48 - DOUBLE_803df2a8)) /
                                   FLOAT_803df2a4),auStack140,0x79);
              uVar2 = FUN_800221a0(0xffff8000,0x8000);
              local_50 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
              FUN_802470c8((double)((FLOAT_803df298 *
                                    FLOAT_803df29c *
                                    FLOAT_803df2a0 * (float)(local_50 - DOUBLE_803df2a8)) /
                                   FLOAT_803df2a4),auStack188,0x7a);
            }
            FUN_80246eb4(auStack188,auStack140,auStack140);
            FUN_80247574(auStack140,&local_c8,&local_c8);
          }
          local_48 = (double)(longlong)(int)local_c0;
          local_50 = (double)(longlong)(int)local_c4;
          local_58 = (double)(longlong)(int)local_c8;
          write_volatile_2(0xcc008000,(short)(int)local_c8);
          write_volatile_2(0xcc008000,(short)(int)local_c4);
          write_volatile_2(0xcc008000,(short)(int)local_c0);
          write_volatile_2(0xcc008000,0);
          write_volatile_2(0xcc008000,0);
          iVar8 = iVar8 + 1;
        } while (iVar8 < 0x32);
        uVar5 = FUN_8025ce04();
        *puVar9 = uVar5;
        puVar10 = puVar10 + 1;
        puVar9 = puVar9 + 1;
        iVar7 = iVar7 + 1;
        if (0x5b < iVar7) {
          FUN_80023800(pfVar1);
          FUN_80258228(1,8);
          __psq_l0(auStack8,uVar11);
          __psq_l1(auStack8,uVar11);
          __psq_l0(auStack24,uVar11);
          __psq_l1(auStack24,uVar11);
          FUN_8028611c();
          return;
        }
      } while( true );
    }
  } while( true );
}

