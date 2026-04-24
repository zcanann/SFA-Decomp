// Function: FUN_80039834
// Entry: 80039834
// Size: 396 bytes

/* WARNING: Removing unreachable block (ram,0x800399a0) */

undefined4 FUN_80039834(double param_1,double param_2,int param_3,short *param_4)

{
  undefined4 uVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f31;
  double dVar4;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  double local_28;
  undefined4 local_20;
  uint uStack28;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  local_48 = (float)param_1;
  local_44 = (float)param_1;
  local_40 = (float)param_2;
  local_3c = (float)-param_2;
  if ((int)*(short *)(param_3 + 0x14) == (int)*(short *)(param_3 + 0x16)) {
    uVar1 = 1;
  }
  else {
    uStack52 = (int)*param_4 ^ 0x80000000;
    local_38 = 0x43300000;
    uStack44 = (int)*(short *)(param_3 + 0x16) ^ 0x80000000;
    local_30 = 0x43300000;
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x14) ^ 0x80000000);
    local_20 = 0x43300000;
    dVar4 = (double)(((float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803de9d0) -
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de9d0)) /
                    ((float)(local_28 - DOUBLE_803de9d0) -
                    (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de9d0)));
    dVar3 = (double)FLOAT_803de99c;
    if ((dVar4 <= dVar3) && (dVar3 = dVar4, dVar4 < (double)FLOAT_803de9a4)) {
      dVar3 = (double)FLOAT_803de9a4;
    }
    uStack28 = uStack44;
    dVar4 = (double)FUN_80010dc0(dVar3,&local_48,0);
    if (*(short *)(param_3 + 0x14) < *(short *)(param_3 + 0x16)) {
      dVar4 = -dVar4;
    }
    *param_4 = (short)(int)(dVar4 * (double)FLOAT_803db414 +
                           (double)(float)((double)CONCAT44(0x43300000,(int)*param_4 ^ 0x80000000) -
                                          DOUBLE_803de9d0));
    if ((((double)FLOAT_803de99c == dVar3) || (0x1ffe < *param_4)) || (*param_4 < -0x1ffe)) {
      *param_4 = *(short *)(param_3 + 0x14);
      uVar1 = 1;
    }
    else {
      uVar1 = 0;
    }
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return uVar1;
}

