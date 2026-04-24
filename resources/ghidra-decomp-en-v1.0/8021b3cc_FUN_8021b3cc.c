// Function: FUN_8021b3cc
// Entry: 8021b3cc
// Size: 180 bytes

/* WARNING: Removing unreachable block (ram,0x8021b460) */

void FUN_8021b3cc(double param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar1 = FUN_800383a0(param_2,0);
  local_2c = FLOAT_803e6a3c;
  local_28 = FLOAT_803e6a40;
  local_24 = FLOAT_803e6a3c;
  local_38 = 0;
  local_36 = 0;
  local_34 = 0;
  local_30 = (float)(param_1 / (double)*(float *)(*(int *)(param_2 + 0x50) + 4));
  FUN_80021ee8(&DAT_803ad1c8,&local_38);
  FUN_800222e4(&DAT_803ad1c8,uVar1,&DAT_803ad1c8);
  FUN_8003b950(&DAT_803ad1c8);
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

