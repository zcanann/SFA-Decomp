// Function: FUN_80062a54
// Entry: 80062a54
// Size: 480 bytes

/* WARNING: Removing unreachable block (ram,0x80062c10) */
/* WARNING: Removing unreachable block (ram,0x80062c08) */
/* WARNING: Removing unreachable block (ram,0x80062c18) */

void FUN_80062a54(double param_1,double param_2,double param_3,uint param_4)

{
  undefined4 uVar1;
  double dVar2;
  double dVar3;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar4;
  float local_68;
  float local_64;
  float local_60;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  local_68 = (float)param_1;
  local_64 = (float)param_2;
  local_60 = (float)param_3;
  FUN_80247794(&local_68,&local_68);
  DAT_803db65a = (undefined2)param_4;
  uStack84 = param_4 ^ 0x80000000;
  local_58 = 0x43300000;
  FLOAT_803dced8 =
       (float)(param_1 * (double)(float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dec60));
  local_50 = 0x43300000;
  FLOAT_803db650 =
       (float)(param_2 * (double)(float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dec60));
  FLOAT_803db654 = FLOAT_803dec68;
  if (FLOAT_803db650 < FLOAT_803dec94) {
    FLOAT_803db650 = FLOAT_803dec94;
  }
  uStack68 = param_4 ^ 0x80000000;
  local_48 = 0x43300000;
  FLOAT_803dcedc =
       (float)(param_3 * (double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dec60));
  dVar4 = (double)(local_60 * DAT_803879b8 + local_68 * DAT_803879b0 + local_64 * DAT_803879b4);
  dVar3 = (double)(DAT_803879b8 * DAT_803879b8 +
                  DAT_803879b0 * DAT_803879b0 + DAT_803879b4 * DAT_803879b4);
  if ((float)((double)(local_60 * local_60 + local_68 * local_68 + local_64 * local_64) * dVar3) !=
      FLOAT_803dec58) {
    uStack76 = uStack84;
    dVar3 = (double)FUN_802931a0();
  }
  dVar2 = (double)FLOAT_803dec58;
  if (dVar3 != dVar2) {
    dVar2 = (double)(float)(dVar4 / dVar3);
  }
  FLOAT_803dcf00 = (float)dVar2;
  if ((float)dVar2 < FLOAT_803dec58) {
    FLOAT_803dcf00 = (float)dVar2 * FLOAT_803dec98;
  }
  if (FLOAT_803dcf00 <= FLOAT_803dec9c) {
    DAT_803db65c = 1;
  }
  if (DAT_803db65c != 0) {
    DAT_803879b0 = local_68;
    DAT_803879b4 = local_64;
    DAT_803879b8 = local_60;
    DAT_803db65c = 0;
    DAT_803db658 = 1;
  }
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  __psq_l0(auStack24,uVar1);
  __psq_l1(auStack24,uVar1);
  __psq_l0(auStack40,uVar1);
  __psq_l1(auStack40,uVar1);
  return;
}

