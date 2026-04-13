// Function: FUN_8017f88c
// Entry: 8017f88c
// Size: 448 bytes

/* WARNING: Removing unreachable block (ram,0x8017fa24) */
/* WARNING: Removing unreachable block (ram,0x8017f89c) */

void FUN_8017f88c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,int *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  
  FUN_8002bac4();
  FUN_8000b7dc(param_9,0x40);
  iVar2 = *param_11;
  if (((iVar2 != 0) && (*(int *)(iVar2 + 0xc4) != 0)) &&
     (FLOAT_803e4508 <= *(float *)(param_9 + 0x98))) {
    *param_11 = 0;
    FUN_80037da8(param_9,iVar2);
    uVar1 = FUN_80022264(0x27,0x2c);
    dVar4 = (double)((float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e44f8) /
                    FLOAT_803e450c);
    uVar1 = FUN_80021884();
    FUN_80022264((uVar1 & 0xffff) - 0x1000,(uVar1 & 0xffff) + 0x1000);
    dVar3 = (double)FUN_802945e0();
    *(float *)(iVar2 + 0x24) = (float)(dVar4 * dVar3);
    param_2 = (double)FLOAT_803e4510;
    dVar3 = (double)FUN_80294964();
    *(float *)(iVar2 + 0x2c) = (float)(dVar4 * dVar3);
    FUN_8000bb38(param_9,0x5e);
  }
  if (FLOAT_803e44f0 <= *(float *)(param_9 + 0x98)) {
    *(undefined *)((int)param_11 + 0xf) = 2;
    param_11[2] = (int)FLOAT_803e4518;
    FUN_8003042c((double)FLOAT_803e44f4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,2,0,param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

