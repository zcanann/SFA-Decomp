// Function: FUN_80221c18
// Entry: 80221c18
// Size: 340 bytes

/* WARNING: Removing unreachable block (ram,0x80221d44) */

uint FUN_80221c18(double param_1,int param_2,undefined4 param_3,undefined4 *param_4)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f31;
  undefined auStack104 [8];
  undefined auStack96 [8];
  undefined auStack88 [8];
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined auStack68 [12];
  undefined4 local_38;
  float local_34;
  undefined4 local_30;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = FUN_8002b9ec();
  if (param_2 == iVar1) {
    local_50 = *(undefined4 *)(param_2 + 0x24);
    local_4c = *(undefined4 *)(param_2 + 0x28);
    local_48 = *(undefined4 *)(param_2 + 0x2c);
  }
  else {
    FUN_80247754(param_2 + 0xc,param_2 + 0x80,&local_50);
  }
  FUN_80247778((double)FLOAT_803db418,&local_50,&local_50);
  local_38 = *(undefined4 *)(param_2 + 0xc);
  local_34 = FLOAT_803e6c58 + *(float *)(param_2 + 0x10);
  local_30 = *(undefined4 *)(param_2 + 0x14);
  iVar1 = 0;
  do {
    dVar4 = (double)FUN_80247984(&local_38,param_3);
    FUN_80247778((double)(float)(dVar4 / param_1),&local_50,auStack68);
    FUN_80247730(param_2 + 0xc,auStack68,&local_38);
    iVar1 = iVar1 + 1;
  } while (iVar1 < 5);
  *param_4 = local_38;
  param_4[1] = local_34;
  param_4[2] = local_30;
  FUN_80012d00(param_3,auStack104);
  FUN_80012d00(&local_38,auStack96);
  uVar2 = FUN_800128dc(auStack104,auStack96,auStack88,0,0);
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return (-uVar2 | uVar2) >> 0x1f;
}

