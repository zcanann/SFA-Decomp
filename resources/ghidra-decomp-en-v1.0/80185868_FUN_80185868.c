// Function: FUN_80185868
// Entry: 80185868
// Size: 348 bytes

/* WARNING: Removing unreachable block (ram,0x801859a4) */

void FUN_80185868(double param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  undefined auStack56 [8];
  undefined4 local_30;
  longlong local_20;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = *(int *)(param_2 + 0xb8);
  local_30 = *(undefined4 *)(iVar3 + 8);
  (**(code **)(*DAT_803ddad0 + 4))(param_2,0xf,0,2,0xffffffff,0);
  (**(code **)(*DAT_803ddad4 + 4))(param_2,0,auStack56,2,0xffffffff,0);
  FUN_8000bb18(param_2,0x71);
  fVar1 = FLOAT_803e3a58;
  *(float *)(param_2 + 0x24) = FLOAT_803e3a58;
  *(float *)(param_2 + 0x2c) = fVar1;
  *(undefined2 *)(iVar3 + 0x10) = 0x32;
  *(undefined2 *)(iVar3 + 0x1a) = 800;
  *(undefined *)(iVar3 + 0x23) = 0;
  *(undefined *)(iVar3 + 0x21) = 0;
  *(undefined4 *)(param_2 + 0xf8) = 0;
  *(undefined4 *)(param_2 + 0xf4) = 2;
  FUN_80035f20(param_2);
  FUN_80035e8c(param_2);
  *(undefined2 *)(iVar3 + 0x1e) = 0;
  if (param_1 < (double)*(float *)(iVar3 + 8)) {
    uVar2 = FUN_8002b9ec();
    FUN_800378c4(uVar2,0x60004,param_2,0);
  }
  local_20 = (longlong)(int)*(float *)(iVar3 + 8);
  FUN_80035b50(param_2,(int)*(float *)(iVar3 + 8),0xfffffffb,10);
  FUN_80035df4(param_2,0xe,1,0);
  FUN_80035f20(param_2);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

