// Function: FUN_80108430
// Entry: 80108430
// Size: 744 bytes

void FUN_80108430(short *param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  float *pfVar4;
  short *psVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  short asStack_28 [2];
  float local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  psVar6 = *(short **)(param_1 + 0x52);
  *(undefined4 *)(DAT_803de1c0 + 0x10) = *(undefined4 *)(param_1 + 0xc);
  fVar1 = FLOAT_803e2444;
  *(float *)(DAT_803de1c0 + 0x18) = FLOAT_803e2444;
  *(float *)(DAT_803de1c0 + 0x1c) = fVar1;
  *(undefined4 *)(DAT_803de1c0 + 0x20) = *(undefined4 *)(param_1 + 0xe);
  *(float *)(DAT_803de1c0 + 0x28) = fVar1;
  *(float *)(DAT_803de1c0 + 0x2c) = fVar1;
  *(undefined4 *)(DAT_803de1c0 + 0x30) = *(undefined4 *)(param_1 + 0x10);
  *(float *)(DAT_803de1c0 + 0x38) = fVar1;
  *(float *)(DAT_803de1c0 + 0x3c) = fVar1;
  pfVar4 = &local_24;
  psVar5 = asStack_28;
  FUN_801039a4((int)param_1,psVar6,pfVar4,psVar5);
  *(float *)(DAT_803de1c0 + 0x14) = local_24;
  *(undefined4 *)(DAT_803de1c0 + 0x24) = local_20;
  *(undefined4 *)(DAT_803de1c0 + 0x34) = local_1c;
  fVar1 = *(float *)(DAT_803de1c0 + 0x14) - *(float *)(DAT_803de1c0 + 0x10);
  fVar2 = *(float *)(DAT_803de1c0 + 0x34) - *(float *)(DAT_803de1c0 + 0x30);
  dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  *(float *)(DAT_803de1c0 + 0x118) = (float)dVar7;
  *(int *)(DAT_803de1c0 + 0xfc) = DAT_803de1c0 + 0x40;
  *(int *)(DAT_803de1c0 + 0x100) = DAT_803de1c0 + 0x50;
  *(undefined4 *)(DAT_803de1c0 + 0x104) = 0;
  *(undefined4 *)(DAT_803de1c0 + 0x108) = 4;
  *(undefined4 *)(DAT_803de1c0 + 0xf8) = 0;
  *(code **)(DAT_803de1c0 + 0x10c) = FUN_80010de0;
  *(undefined **)(DAT_803de1c0 + 0x110) = &LAB_80010d74;
  uStack_14 = (int)*param_1 ^ 0x80000000;
  local_18 = 0x43300000;
  *(float *)(DAT_803de1c0 + 0x40) =
       (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e2458);
  iVar3 = FUN_80021884();
  *(float *)(DAT_803de1c0 + 0x44) =
       (float)((double)CONCAT44(0x43300000,(int)(short)(-0x8000 - (short)iVar3) ^ 0x80000000) -
              DOUBLE_803e2458);
  fVar1 = FLOAT_803e2444;
  *(float *)(DAT_803de1c0 + 0x48) = FLOAT_803e2444;
  *(float *)(DAT_803de1c0 + 0x4c) = fVar1;
  fVar1 = *(float *)(DAT_803de1c0 + 0x40) - *(float *)(DAT_803de1c0 + 0x44);
  if ((FLOAT_803e2448 < fVar1) || (fVar1 < FLOAT_803e244c)) {
    if (FLOAT_803e2444 <= *(float *)(DAT_803de1c0 + 0x40)) {
      if (*(float *)(DAT_803de1c0 + 0x44) < FLOAT_803e2444) {
        *(float *)(DAT_803de1c0 + 0x44) = *(float *)(DAT_803de1c0 + 0x44) + FLOAT_803e2450;
      }
    }
    else {
      *(float *)(DAT_803de1c0 + 0x40) = *(float *)(DAT_803de1c0 + 0x40) + FLOAT_803e2450;
    }
  }
  uStack_c = (int)param_1[1] ^ 0x80000000;
  local_10 = 0x43300000;
  *(float *)(DAT_803de1c0 + 0x50) = (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e2458)
  ;
  fVar1 = FLOAT_803e2444;
  *(float *)(DAT_803de1c0 + 0x54) = FLOAT_803e2444;
  *(float *)(DAT_803de1c0 + 0x58) = fVar1;
  *(float *)(DAT_803de1c0 + 0x5c) = fVar1;
  dVar8 = (double)*(float *)(DAT_803de1c0 + 0x50);
  dVar9 = (double)*(float *)(DAT_803de1c0 + 0x54);
  dVar7 = (double)(float)(dVar8 - dVar9);
  if (((double)FLOAT_803e2448 < dVar7) || (dVar7 < (double)FLOAT_803e244c)) {
    if ((double)FLOAT_803e2444 <= dVar8) {
      if (dVar9 < (double)FLOAT_803e2444) {
        dVar7 = (double)*(float *)(DAT_803de1c0 + 0x54);
        *(float *)(DAT_803de1c0 + 0x54) = (float)(dVar7 + (double)FLOAT_803e2450);
      }
    }
    else {
      dVar7 = (double)*(float *)(DAT_803de1c0 + 0x50);
      *(float *)(DAT_803de1c0 + 0x50) = (float)(dVar7 + (double)FLOAT_803e2450);
    }
  }
  FUN_80010a8c(dVar7,dVar8,dVar9,in_f4,in_f5,in_f6,in_f7,in_f8,(float *)(DAT_803de1c0 + 0x78),
               0x10000,pfVar4,psVar5,in_r7,in_r8,in_r9,in_r10);
  return;
}

