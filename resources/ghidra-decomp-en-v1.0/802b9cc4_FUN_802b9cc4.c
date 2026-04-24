// Function: FUN_802b9cc4
// Entry: 802b9cc4
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x802b9e14) */

undefined4 FUN_802b9cc4(undefined8 param_1,int param_2,uint *param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  float local_28 [3];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  local_28[0] = FLOAT_803e8240;
  iVar1 = FUN_80036e58(0x13,param_2,local_28);
  iVar3 = *(int *)(param_2 + 0xb8);
  *param_3 = *param_3 | 0x200000;
  if ((*(short *)(param_3 + 0xcd) < *(short *)(iVar3 + 0xa86)) ||
     (FLOAT_803e8234 == (float)param_3[0xa6])) {
    uVar2 = 8;
  }
  else {
    if (*(short *)((int)param_3 + 0x336) < -0xaf) {
      *(short *)((int)param_3 + 0x336) = -*(short *)((int)param_3 + 0x336);
    }
    if ((*(short *)((int)param_3 + 0x336) < 1) || (*(short *)(param_2 + 0xa0) == 0x201)) {
      if ((*(short *)((int)param_3 + 0x336) < 1) && (*(short *)(param_2 + 0xa0) != 0x200)) {
        FUN_80030334((double)FLOAT_803e8234,param_2,0x200,0);
      }
    }
    else {
      FUN_80030334((double)FLOAT_803e8234,param_2,0x201,0);
    }
    param_3[0xa8] = (uint)FLOAT_803e8278;
    (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,8);
    if (((param_3[199] & 0x100) == 0) || ((iVar1 != 0 && ((*(byte *)(iVar1 + 0xaf) & 4) != 0)))) {
      uVar2 = 0;
    }
    else {
      uVar2 = 0xc;
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return uVar2;
}

