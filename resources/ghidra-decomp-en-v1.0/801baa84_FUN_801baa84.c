// Function: FUN_801baa84
// Entry: 801baa84
// Size: 260 bytes

/* WARNING: Removing unreachable block (ram,0x801bab68) */

undefined4 FUN_801baa84(undefined8 param_1,int param_2,int param_3)

{
  float fVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_80035df4(param_2,9,1,0xffffffff);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    *(float *)(param_3 + 0x2a0) = FLOAT_803e4c04;
    if (*(char *)(param_3 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e4bd8,param_2,0x13,0);
      *(undefined *)(param_3 + 0x346) = 0;
    }
    *(undefined2 *)(param_2 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e4bd8;
    *(float *)(param_3 + 0x280) = FLOAT_803e4bd8;
    *(float *)(param_3 + 0x284) = fVar1;
  }
  (**(code **)(*DAT_803dca8c + 0x34))(param_2,param_3,0,1,&DAT_80325aa0);
  (**(code **)(*DAT_803dca8c + 0x30))(param_1,param_2,param_3,0xf0);
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return 0;
}

