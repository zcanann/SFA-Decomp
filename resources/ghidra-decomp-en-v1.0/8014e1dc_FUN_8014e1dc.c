// Function: FUN_8014e1dc
// Entry: 8014e1dc
// Size: 1368 bytes

/* WARNING: Removing unreachable block (ram,0x8014e710) */

void FUN_8014e1dc(short *param_1,int *param_2)

{
  float fVar1;
  int iVar2;
  char cVar4;
  uint uVar3;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f31;
  undefined auStack136 [32];
  longlong local_68;
  longlong local_60;
  longlong local_58;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  longlong local_40;
  undefined4 local_38;
  uint uStack52;
  double local_30;
  double local_28;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar5 = *param_2;
  iVar2 = FUN_80010320((double)(float)param_2[2],iVar5);
  if ((((iVar2 != 0) || (*(int *)(iVar5 + 0x10) != DAT_803dda58)) &&
      (cVar4 = (**(code **)(*DAT_803dca9c + 0x90))(iVar5), cVar4 != '\0')) &&
     (cVar4 = (**(code **)(*DAT_803dca9c + 0x8c))
                        ((double)FLOAT_803e2608,*param_2,param_1,&DAT_803dbc70,0xffffffff),
     cVar4 != '\0')) {
    *(byte *)((int)param_2 + 0x26) = *(byte *)((int)param_2 + 0x26) & 0xfe;
  }
  DAT_803dda58 = *(undefined4 *)(iVar5 + 0x10);
  local_68 = (longlong)(int)(FLOAT_803e260c * FLOAT_803db414);
  *(short *)(param_2 + 8) = *(short *)(param_2 + 8) + (short)(int)(FLOAT_803e260c * FLOAT_803db414);
  local_60 = (longlong)(int)(FLOAT_803e2610 * FLOAT_803db414);
  *(short *)((int)param_2 + 0x22) =
       *(short *)((int)param_2 + 0x22) + (short)(int)(FLOAT_803e2610 * FLOAT_803db414);
  local_58 = (longlong)(int)(FLOAT_803e2614 * FLOAT_803db414);
  *(short *)(param_2 + 9) = *(short *)(param_2 + 9) + (short)(int)(FLOAT_803e2614 * FLOAT_803db414);
  uStack76 = (uint)*(ushort *)((int)param_2 + 0x22);
  local_50 = 0x43300000;
  dVar7 = (double)FUN_80293e80((double)((FLOAT_803e261c *
                                        (float)((double)CONCAT44(0x43300000,uStack76) -
                                               DOUBLE_803e2640)) / FLOAT_803e2620));
  uStack68 = (uint)*(ushort *)(param_2 + 8);
  local_48 = 0x43300000;
  dVar8 = (double)FUN_80293e80((double)((FLOAT_803e261c *
                                        (float)((double)CONCAT44(0x43300000,uStack68) -
                                               DOUBLE_803e2640)) / FLOAT_803e2620));
  iVar2 = (int)(FLOAT_803e2618 * (float)(dVar8 + dVar7));
  local_40 = (longlong)iVar2;
  param_1[2] = (short)iVar2;
  uStack52 = (uint)*(ushort *)(param_2 + 9);
  local_38 = 0x43300000;
  dVar7 = (double)FUN_80293e80((double)((FLOAT_803e261c *
                                        (float)((double)CONCAT44(0x43300000,uStack52) -
                                               DOUBLE_803e2640)) / FLOAT_803e2620));
  local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 8));
  dVar8 = (double)FUN_80293e80((double)((FLOAT_803e261c * (float)(local_30 - DOUBLE_803e2640)) /
                                       FLOAT_803e2620));
  iVar2 = (int)(FLOAT_803e2618 * (float)(dVar8 + dVar7));
  local_28 = (double)(longlong)iVar2;
  param_1[1] = (short)iVar2;
  fVar1 = FLOAT_803e2624;
  if ((*(byte *)((int)param_2 + 0x26) & 2) == 0) {
    if ((*(byte *)((int)param_2 + 0x26) & 4) == 0) {
      *(float *)(param_1 + 0x12) =
           FLOAT_803e2624 * (*(float *)(iVar5 + 0x68) - *(float *)(param_1 + 6)) +
           *(float *)(param_1 + 0x12);
      local_28 = (double)CONCAT44(0x43300000,(uint)*(ushort *)((int)param_2 + 0x22));
      dVar7 = (double)FUN_80293e80((double)((FLOAT_803e261c * (float)(local_28 - DOUBLE_803e2640)) /
                                           FLOAT_803e2620));
      local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 8));
      dVar8 = (double)FUN_80293e80((double)((FLOAT_803e261c * (float)(local_30 - DOUBLE_803e2640)) /
                                           FLOAT_803e2620));
      fVar1 = FLOAT_803e2624;
      *(float *)(param_1 + 0x14) =
           FLOAT_803e2624 *
           ((FLOAT_803e262c * (float)(dVar8 + dVar7) + *(float *)(iVar5 + 0x6c)) -
           *(float *)(param_1 + 8)) + *(float *)(param_1 + 0x14);
      *(float *)(param_1 + 0x16) =
           fVar1 * (*(float *)(iVar5 + 0x70) - *(float *)(param_1 + 10)) +
           *(float *)(param_1 + 0x16);
    }
    else {
      *(float *)(param_1 + 0x12) =
           FLOAT_803e2624 * (*(float *)(iVar5 + 0x68) - *(float *)(param_1 + 6)) +
           *(float *)(param_1 + 0x12);
      *(float *)(param_1 + 0x14) =
           fVar1 * (*(float *)(iVar5 + 0x6c) - *(float *)(param_1 + 8)) + *(float *)(param_1 + 0x14)
      ;
      *(float *)(param_1 + 0x16) =
           fVar1 * (*(float *)(iVar5 + 0x70) - *(float *)(param_1 + 10)) +
           *(float *)(param_1 + 0x16);
    }
  }
  else {
    *(float *)(param_1 + 0x12) =
         FLOAT_803e2624 * (*(float *)(param_2[1] + 0xc) - *(float *)(param_1 + 6)) +
         *(float *)(param_1 + 0x12);
    *(float *)(param_1 + 0x14) =
         fVar1 * ((FLOAT_803e2628 + *(float *)(param_2[1] + 0x10)) - *(float *)(param_1 + 8)) +
         *(float *)(param_1 + 0x14);
    *(float *)(param_1 + 0x16) =
         fVar1 * (*(float *)(param_2[1] + 0x14) - *(float *)(param_1 + 10)) +
         *(float *)(param_1 + 0x16);
  }
  fVar1 = FLOAT_803e2630;
  *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e2630;
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * fVar1;
  *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar1;
  if (FLOAT_803e2634 < *(float *)(param_1 + 0x12)) {
    *(float *)(param_1 + 0x12) = FLOAT_803e2634;
  }
  if (FLOAT_803e2634 < *(float *)(param_1 + 0x14)) {
    *(float *)(param_1 + 0x14) = FLOAT_803e2634;
  }
  if (FLOAT_803e2634 < *(float *)(param_1 + 0x16)) {
    *(float *)(param_1 + 0x16) = FLOAT_803e2634;
  }
  if (*(float *)(param_1 + 0x12) < FLOAT_803e2638) {
    *(float *)(param_1 + 0x12) = FLOAT_803e2638;
  }
  if (*(float *)(param_1 + 0x14) < FLOAT_803e2638) {
    *(float *)(param_1 + 0x14) = FLOAT_803e2638;
  }
  if (*(float *)(param_1 + 0x16) < FLOAT_803e2638) {
    *(float *)(param_1 + 0x16) = FLOAT_803e2638;
  }
  FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
               (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
               (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
  FUN_8002fa48((double)(float)param_2[3],(double)FLOAT_803db414,param_1,auStack136);
  uVar3 = FUN_800217c0((double)(*(float *)(param_1 + 0xc) - *(float *)(param_2[1] + 0x18)),
                       (double)(*(float *)(param_1 + 0x10) - *(float *)(param_2[1] + 0x20)));
  uVar3 = (uVar3 & 0xffff) - ((int)*param_1 & 0xffffU);
  if (0x8000 < (int)uVar3) {
    uVar3 = uVar3 - 0xffff;
  }
  if ((int)uVar3 < -0x8000) {
    uVar3 = uVar3 + 0xffff;
  }
  local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
  *param_1 = *param_1 +
             (short)(int)(((float)(local_28 - DOUBLE_803e2648) * FLOAT_803db414) / FLOAT_803e263c);
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

