// Function: FUN_8003992c
// Entry: 8003992c
// Size: 396 bytes

/* WARNING: Removing unreachable block (ram,0x80039a98) */
/* WARNING: Removing unreachable block (ram,0x8003993c) */

undefined4 FUN_8003992c(double param_1,double param_2,int param_3,short *param_4)

{
  undefined4 uVar1;
  double dVar2;
  double dVar3;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  local_48 = (float)param_1;
  local_44 = (float)param_1;
  local_40 = (float)param_2;
  local_3c = (float)-param_2;
  if ((int)*(short *)(param_3 + 0x14) == (int)*(short *)(param_3 + 0x16)) {
    uVar1 = 1;
  }
  else {
    uStack_34 = (int)*param_4 ^ 0x80000000;
    local_38 = 0x43300000;
    uStack_2c = (int)*(short *)(param_3 + 0x16) ^ 0x80000000;
    local_30 = 0x43300000;
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x14) ^ 0x80000000);
    local_20 = 0x43300000;
    dVar3 = (double)(((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df650) -
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df650)) /
                    ((float)(local_28 - DOUBLE_803df650) -
                    (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df650)));
    dVar2 = (double)FLOAT_803df61c;
    if ((dVar3 <= dVar2) && (dVar2 = dVar3, dVar3 < (double)FLOAT_803df624)) {
      dVar2 = (double)FLOAT_803df624;
    }
    uStack_1c = uStack_2c;
    dVar3 = FUN_80010de0(dVar2,&local_48,(float *)0x0);
    if (*(short *)(param_3 + 0x14) < *(short *)(param_3 + 0x16)) {
      dVar3 = -dVar3;
    }
    *param_4 = (short)(int)(dVar3 * (double)FLOAT_803dc074 +
                           (double)(float)((double)CONCAT44(0x43300000,(int)*param_4 ^ 0x80000000) -
                                          DOUBLE_803df650));
    if ((((double)FLOAT_803df61c == dVar2) || (0x1ffe < *param_4)) || (*param_4 < -0x1ffe)) {
      *param_4 = *(short *)(param_3 + 0x14);
      uVar1 = 1;
    }
    else {
      uVar1 = 0;
    }
  }
  return uVar1;
}

