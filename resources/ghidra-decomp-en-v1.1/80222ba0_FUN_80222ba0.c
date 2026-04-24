// Function: FUN_80222ba0
// Entry: 80222ba0
// Size: 668 bytes

/* WARNING: Removing unreachable block (ram,0x80222e1c) */
/* WARNING: Removing unreachable block (ram,0x80222e14) */
/* WARNING: Removing unreachable block (ram,0x80222e0c) */
/* WARNING: Removing unreachable block (ram,0x80222bc0) */
/* WARNING: Removing unreachable block (ram,0x80222bb8) */
/* WARNING: Removing unreachable block (ram,0x80222bb0) */

void FUN_80222ba0(double param_1,double param_2,ushort *param_3,float *param_4,uint param_5)

{
  ushort uVar1;
  uint uVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  
  dVar5 = (double)(FLOAT_803dc074 /
                  (float)((double)CONCAT44(0x43300000,param_5 & 0xffff) - DOUBLE_803e78e0));
  if ((double)FLOAT_803e7904 < dVar5) {
    dVar5 = (double)FLOAT_803e7904;
  }
  uVar2 = FUN_80021884();
  local_50 = (double)CONCAT44(0x43300000,(uVar2 & 0xffff) - (uint)*param_3 ^ 0x80000000);
  dVar3 = (double)(float)(local_50 - DOUBLE_803e78e8);
  if ((double)FLOAT_803e78fc < dVar3) {
    dVar3 = (double)(float)((double)FLOAT_803e791c + dVar3);
  }
  if (dVar3 < (double)FLOAT_803e7924) {
    dVar3 = (double)(float)((double)FLOAT_803e7920 + dVar3);
  }
  dVar4 = (double)(float)(dVar3 * dVar5);
  dVar3 = (double)FLOAT_803e7928;
  if ((dVar3 <= dVar4) && (dVar3 = dVar4, (double)FLOAT_803e792c < dVar4)) {
    dVar3 = (double)FLOAT_803e792c;
  }
  *param_3 = *param_3 + (short)(int)dVar3;
  dVar4 = DOUBLE_803e78e8;
  if (param_1 != (double)FLOAT_803e78d0) {
    local_48 = (double)CONCAT44(0x43300000,(int)(short)param_3[2] ^ 0x80000000);
    param_3[2] = (ushort)(int)(FLOAT_803e7930 * (float)(local_48 - DOUBLE_803e78e8));
    param_3[2] = (ushort)(int)(FLOAT_803dc078 * FLOAT_803e78f4 * (float)(dVar3 * param_1) +
                              (float)((double)CONCAT44(0x43300000,
                                                       (int)(short)param_3[2] ^ 0x80000000) - dVar4)
                              );
    uVar1 = param_3[2];
    if ((short)uVar1 < -0x2000) {
      uVar1 = 0xe000;
    }
    else if (0x2000 < (short)uVar1) {
      uVar1 = 0x2000;
    }
    param_3[2] = uVar1;
  }
  if ((double)FLOAT_803e78d0 != param_2) {
    FUN_80293900((double)(*param_4 * *param_4 + param_4[2] * param_4[2]));
    uVar2 = FUN_80021884();
    local_40 = (double)CONCAT44(0x43300000,(uVar2 & 0xffff) - (uint)param_3[1] ^ 0x80000000);
    dVar3 = (double)(float)(local_40 - DOUBLE_803e78e8);
    if ((double)FLOAT_803e78fc < dVar3) {
      dVar3 = (double)(float)((double)FLOAT_803e791c + dVar3);
    }
    if (dVar3 < (double)FLOAT_803e7924) {
      dVar3 = (double)(float)((double)FLOAT_803e7920 + dVar3);
    }
    param_3[1] = param_3[1] + (short)(int)(dVar3 * dVar5);
  }
  return;
}

