// Function: FUN_80022264
// Entry: 80022264
// Size: 192 bytes

uint FUN_80022264(uint param_1,uint param_2)

{
  undefined4 uVar1;
  
  if (param_1 != param_2) {
    uVar1 = FUN_80293520();
    param_1 = (uint)(((float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803df480) / FLOAT_803df478
                     ) * ((FLOAT_803df444 +
                          (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) -
                                 DOUBLE_803df460)) -
                         (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803df460
                                )) +
                    (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803df460));
  }
  return param_1;
}

