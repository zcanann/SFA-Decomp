// Function: FUN_802b7b0c
// Entry: 802b7b0c
// Size: 228 bytes

/* WARNING: Removing unreachable block (ram,0x802b7bd0) */

undefined4 FUN_802b7b0c(undefined8 param_1,short *param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    FUN_8000bb18(param_2,*(undefined2 *)(*(int *)(*(int *)(param_2 + 0x5c) + 0x40c) + 0x2a));
    iVar1 = FUN_800221a0(0,1);
    if (iVar1 == 0) {
      *param_2 = *param_2 + 0x7557;
    }
    else {
      *param_2 = *param_2 + -0x7557;
    }
    FUN_80030334((double)FLOAT_803e8180,param_2,0x23,0);
  }
  *(float *)(param_3 + 0x2a0) = FLOAT_803e81a8;
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return 0;
}

