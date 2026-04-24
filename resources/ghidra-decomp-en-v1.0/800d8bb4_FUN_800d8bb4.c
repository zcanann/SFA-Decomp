// Function: FUN_800d8bb4
// Entry: 800d8bb4
// Size: 168 bytes

/* WARNING: Removing unreachable block (ram,0x800d8c3c) */

void FUN_800d8bb4(undefined8 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (*(int *)(param_3 + 0x33c) == -1) {
    *(float *)(param_3 + 700) = FLOAT_803e0570;
  }
  else {
    iVar1 = (**(code **)(*DAT_803dca9c + 0x1c))();
    if (iVar1 == 0) {
      *(float *)(param_3 + 700) = FLOAT_803e0570;
    }
    else {
      FUN_800d816c((double)*(float *)(iVar1 + 8),(double)*(float *)(iVar1 + 0x10),param_1,param_2,
                   param_3,1);
    }
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

