// Function: FUN_80062bd0
// Entry: 80062bd0
// Size: 480 bytes

/* WARNING: Removing unreachable block (ram,0x80062d94) */
/* WARNING: Removing unreachable block (ram,0x80062d8c) */
/* WARNING: Removing unreachable block (ram,0x80062d84) */
/* WARNING: Removing unreachable block (ram,0x80062bf0) */
/* WARNING: Removing unreachable block (ram,0x80062be8) */
/* WARNING: Removing unreachable block (ram,0x80062be0) */

void FUN_80062bd0(double param_1,double param_2,double param_3,uint param_4)

{
  double dVar1;
  double dVar2;
  double dVar3;
  float local_68;
  float local_64;
  float local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  
  local_68 = (float)param_1;
  local_64 = (float)param_2;
  local_60 = (float)param_3;
  FUN_80247ef8(&local_68,&local_68);
  DAT_803dc2ba = (undefined2)param_4;
  uStack_54 = param_4 ^ 0x80000000;
  local_58 = 0x43300000;
  FLOAT_803ddb58 =
       (float)(param_1 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803df8e0));
  local_50 = 0x43300000;
  FLOAT_803dc2b0 =
       (float)(param_2 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803df8e0));
  FLOAT_803dc2b4 = FLOAT_803df8e8;
  if (FLOAT_803dc2b0 < FLOAT_803df914) {
    FLOAT_803dc2b0 = FLOAT_803df914;
  }
  uStack_44 = param_4 ^ 0x80000000;
  local_48 = 0x43300000;
  FLOAT_803ddb5c =
       (float)(param_3 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df8e0));
  dVar3 = (double)(local_60 * DAT_80388618 + local_68 * DAT_80388610 + local_64 * DAT_80388614);
  dVar2 = (double)(DAT_80388618 * DAT_80388618 +
                  DAT_80388610 * DAT_80388610 + DAT_80388614 * DAT_80388614);
  dVar1 = (double)(float)((double)(local_60 * local_60 + local_68 * local_68 + local_64 * local_64)
                         * dVar2);
  if (dVar1 != (double)FLOAT_803df8d8) {
    uStack_4c = uStack_54;
    dVar2 = FUN_80293900(dVar1);
  }
  dVar1 = (double)FLOAT_803df8d8;
  if (dVar2 != dVar1) {
    dVar1 = (double)(float)(dVar3 / dVar2);
  }
  FLOAT_803ddb80 = (float)dVar1;
  if ((float)dVar1 < FLOAT_803df8d8) {
    FLOAT_803ddb80 = (float)dVar1 * FLOAT_803df918;
  }
  if (FLOAT_803ddb80 <= FLOAT_803df91c) {
    DAT_803dc2bc = 1;
  }
  if (DAT_803dc2bc != 0) {
    DAT_80388610 = local_68;
    DAT_80388614 = local_64;
    DAT_80388618 = local_60;
    DAT_803dc2bc = 0;
    DAT_803dc2b8 = 1;
  }
  return;
}

