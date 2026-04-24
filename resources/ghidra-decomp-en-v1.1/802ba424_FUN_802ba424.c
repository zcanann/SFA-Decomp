// Function: FUN_802ba424
// Entry: 802ba424
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x802ba574) */
/* WARNING: Removing unreachable block (ram,0x802ba434) */

undefined4
FUN_802ba424(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  float local_28 [3];
  
  local_28[0] = FLOAT_803e8ed8;
  iVar1 = FUN_80036f50(0x13,param_9,local_28);
  iVar3 = *(int *)(param_9 + 0xb8);
  *param_10 = *param_10 | 0x200000;
  if ((*(short *)(param_10 + 0xcd) < *(short *)(iVar3 + 0xa86)) ||
     (FLOAT_803e8ecc == (float)param_10[0xa6])) {
    uVar2 = 8;
  }
  else {
    if (*(short *)((int)param_10 + 0x336) < -0xaf) {
      *(short *)((int)param_10 + 0x336) = -*(short *)((int)param_10 + 0x336);
    }
    if ((*(short *)((int)param_10 + 0x336) < 1) || (*(short *)(param_9 + 0xa0) == 0x201)) {
      if ((*(short *)((int)param_10 + 0x336) < 1) && (*(short *)(param_9 + 0xa0) != 0x200)) {
        FUN_8003042c((double)FLOAT_803e8ecc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x200,0,param_12,param_13,param_14,param_15,param_16);
      }
    }
    else {
      FUN_8003042c((double)FLOAT_803e8ecc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x201,0,param_12,param_13,param_14,param_15,param_16);
    }
    param_10[0xa8] = (uint)FLOAT_803e8f10;
    (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,8);
    if (((param_10[199] & 0x100) == 0) || ((iVar1 != 0 && ((*(byte *)(iVar1 + 0xaf) & 4) != 0)))) {
      uVar2 = 0;
    }
    else {
      uVar2 = 0xc;
    }
  }
  return uVar2;
}

