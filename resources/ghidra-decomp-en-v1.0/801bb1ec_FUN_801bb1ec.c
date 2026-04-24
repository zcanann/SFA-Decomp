// Function: FUN_801bb1ec
// Entry: 801bb1ec
// Size: 196 bytes

/* WARNING: Removing unreachable block (ram,0x801bb290) */

undefined4 FUN_801bb1ec(undefined8 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e4bd8,param_2,2,0);
    *(undefined *)(param_3 + 0x346) = 0;
  }
  *(float *)(param_3 + 0x2a0) = FLOAT_803e4c24;
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
  (**(code **)(*DAT_803dca8c + 0x30))(param_1,param_2,param_3,4);
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  return 0;
}

