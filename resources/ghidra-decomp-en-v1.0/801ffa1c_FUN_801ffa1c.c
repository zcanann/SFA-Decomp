// Function: FUN_801ffa1c
// Entry: 801ffa1c
// Size: 864 bytes

/* WARNING: Removing unreachable block (ram,0x801ffd50) */
/* WARNING: Removing unreachable block (ram,0x801ffa7c) */
/* WARNING: Removing unreachable block (ram,0x801ffd58) */

void FUN_801ffa1c(short *param_1)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  float fVar4;
  float *pfVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack104 [12];
  undefined auStack92 [12];
  undefined2 local_50;
  short local_4e;
  undefined2 local_4c;
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  pfVar5 = *(float **)(param_1 + 0x5c);
  iVar3 = FUN_8002b9ec();
  fVar4 = FLOAT_803e627c;
  bVar1 = *(byte *)(pfVar5 + 2);
  if (bVar1 == 3) {
    dVar7 = (double)FUN_80021690(param_1 + 0xc,iVar3 + 0x18);
    if ((double)FLOAT_803dc168 <= dVar7) {
      dVar8 = (double)FLOAT_803dc16c;
      FUN_80221c18((double)(float)(dVar8 / (double)FLOAT_803e6294),iVar3,param_1 + 6,auStack92);
      FUN_80247754(auStack92,param_1 + 6,auStack104);
      FUN_80247794(auStack104,auStack104);
      if (dVar7 < dVar8) {
        dVar8 = dVar7;
      }
      FUN_80247778(dVar8,auStack104,param_1 + 0x12);
      FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                   (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                   (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
      local_4c = 0xff;
      local_4e = 0;
      local_50 = 0xff;
      FUN_80098928((double)FLOAT_803dc174,param_1,1,0xc22,0x14,param_1 + 0x12);
    }
    else {
      FUN_80296afc(iVar3,DAT_803dc170);
      FUN_8000bb18(param_1,0x49);
      *(undefined *)(pfVar5 + 2) = 4;
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      if (FLOAT_803e627c < *pfVar5 - *(float *)(param_1 + 8)) {
        *(float *)(param_1 + 0x14) = FLOAT_803e6280 * -*(float *)(param_1 + 0x14);
        fVar2 = *(float *)(param_1 + 0x14);
        if (fVar2 < fVar4) {
          fVar2 = -fVar2;
        }
        if (fVar2 < FLOAT_803e6284) {
          *(undefined *)(pfVar5 + 2) = 2;
          fVar4 = FLOAT_803e627c;
          *(float *)(param_1 + 0x12) = FLOAT_803e627c;
          *(float *)(param_1 + 0x16) = fVar4;
          goto LAB_801ffd2c;
        }
      }
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803e6288;
      FUN_8002b95c((double)*(float *)(param_1 + 0x12),(double)*(float *)(param_1 + 0x14),
                   (double)*(float *)(param_1 + 0x16),param_1);
      local_4c = 0xff;
      fVar4 = pfVar5[1];
      iVar3 = (int)fVar4 / 0x500 + ((int)fVar4 >> 0x1f);
      local_4e = 0xff - (SUB42(fVar4,0) + ((short)iVar3 - (short)(iVar3 >> 0x1f)) * -0x500);
      local_50 = 0xff;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x357,&local_50,0,0xffffffff,0);
    }
    else if (bVar1 == 0) {
      iVar3 = FUN_8001ffb4((int)*(short *)(*(int *)(param_1 + 0x26) + 0x20));
      if (iVar3 == 1) {
        *(undefined *)(pfVar5 + 2) = 2;
      }
    }
    else {
      uStack52 = (uint)pfVar5[1] ^ 0x80000000;
      local_38 = 0x43300000;
      dVar7 = (double)FUN_80293e80((double)((FLOAT_803e628c *
                                            (float)((double)CONCAT44(0x43300000,uStack52) -
                                                   DOUBLE_803e6298)) / FLOAT_803e6290));
      *(float *)(param_1 + 0x14) = (float)((double)FLOAT_803dc160 * dVar7);
      FUN_8002b95c((double)*(float *)(param_1 + 0x12),(double)*(float *)(param_1 + 0x14),
                   (double)*(float *)(param_1 + 0x16),param_1);
      dVar7 = (double)FUN_80021704(param_1 + 0xc,iVar3 + 0x18);
      if (dVar7 < (double)FLOAT_803dc164) {
        *(undefined *)(pfVar5 + 2) = 3;
      }
      FUN_80098928((double)FLOAT_803dc174,param_1,1,0xc22,0x14,param_1 + 0x12);
    }
  }
  else if (bVar1 == 5) {
    *(undefined *)(pfVar5 + 2) = 0;
  }
LAB_801ffd2c:
  *param_1 = *param_1 + DAT_803dc178;
  pfVar5[1] = (float)((int)pfVar5[1] + (uint)DAT_803db410 * 0x500);
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

