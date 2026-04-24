// Function: FUN_8014d194
// Entry: 8014d194
// Size: 608 bytes

/* WARNING: Removing unreachable block (ram,0x8014d3d0) */
/* WARNING: Removing unreachable block (ram,0x8014d3c8) */
/* WARNING: Removing unreachable block (ram,0x8014d3c0) */
/* WARNING: Removing unreachable block (ram,0x8014d1b4) */
/* WARNING: Removing unreachable block (ram,0x8014d1ac) */
/* WARNING: Removing unreachable block (ram,0x8014d1a4) */

void FUN_8014d194(double param_1,double param_2,ushort *param_3,int param_4,uint param_5,
                 char param_6)

{
  uint uVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  undefined8 local_50;
  undefined8 local_48;
  
  dVar4 = (double)(FLOAT_803dc074 /
                  (float)((double)CONCAT44(0x43300000,param_5 & 0xffff) - DOUBLE_803e3278));
  if ((double)FLOAT_803e3200 < dVar4) {
    dVar4 = (double)FLOAT_803e3200;
  }
  uVar1 = FUN_80021884();
  local_50 = (double)CONCAT44(0x43300000,(uVar1 & 0xffff) - (uint)*param_3 ^ 0x80000000);
  dVar2 = (double)(float)(local_50 - DOUBLE_803e3218);
  if ((double)FLOAT_803e324c < dVar2) {
    dVar2 = (double)(float)((double)FLOAT_803e3284 + dVar2);
  }
  if (dVar2 < (double)FLOAT_803e328c) {
    dVar2 = (double)(float)((double)FLOAT_803e3288 + dVar2);
  }
  dVar3 = (double)(float)(dVar2 * dVar4);
  *param_3 = *param_3 + (short)(int)(dVar2 * dVar4);
  if (param_1 != (double)FLOAT_803e31fc) {
    if (param_6 == '\0') {
      param_3[2] = (ushort)(int)(FLOAT_803dc078 * (float)(dVar3 * param_1));
      if ((short)param_3[2] < 0x2001) {
        if ((short)param_3[2] < -0x2000) {
          param_3[2] = 0xe000;
        }
      }
      else {
        param_3[2] = 0x2000;
      }
    }
    else {
      param_3[2] = param_3[2] + (short)(int)(param_1 * (double)(float)(dVar3 * dVar4));
    }
  }
  if ((double)FLOAT_803e31fc != param_2) {
    FUN_80293900((double)(*(float *)(param_4 + 0x2c0) * *(float *)(param_4 + 0x2c0) +
                         *(float *)(param_4 + 0x2b8) * *(float *)(param_4 + 0x2b8)));
    uVar1 = FUN_80021884();
    local_48 = (double)CONCAT44(0x43300000,(uVar1 & 0xffff) - (uint)param_3[1] ^ 0x80000000);
    dVar2 = (double)(float)(local_48 - DOUBLE_803e3218);
    if ((double)FLOAT_803e324c < dVar2) {
      dVar2 = (double)(float)((double)FLOAT_803e3284 + dVar2);
    }
    if (dVar2 < (double)FLOAT_803e328c) {
      dVar2 = (double)(float)((double)FLOAT_803e3288 + dVar2);
    }
    param_3[1] = param_3[1] + (short)(int)(dVar2 * dVar4);
  }
  return;
}

