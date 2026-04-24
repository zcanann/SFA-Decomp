// Function: FUN_8021e748
// Entry: 8021e748
// Size: 212 bytes

/* WARNING: Removing unreachable block (ram,0x8021e7fc) */

void FUN_8021e748(double param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined2 local_3c;
  undefined2 local_3a;
  undefined2 local_38;
  float local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar1 = FUN_800383a0(param_2,2);
  FUN_800382f0(param_2,2,&local_40,&local_44,&local_48);
  local_30 = local_40;
  local_2c = local_44;
  local_28 = local_48;
  local_3c = 0x8000;
  local_3a = 0;
  local_38 = 0;
  local_34 = (float)(param_1 / (double)*(float *)(*(int *)(param_2 + 0x50) + 4));
  FUN_80021ee8(&DAT_803ad208,&local_3c);
  FUN_800222e4(&DAT_803ad208,uVar1,&DAT_803ad208);
  FUN_8003b950(&DAT_803ad208);
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

