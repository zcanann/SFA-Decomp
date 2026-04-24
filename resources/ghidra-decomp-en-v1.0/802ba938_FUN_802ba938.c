// Function: FUN_802ba938
// Entry: 802ba938
// Size: 284 bytes

/* WARNING: Removing unreachable block (ram,0x802baa34) */

undefined4 FUN_802ba938(double param_1,int param_2,uint *param_3)

{
  float fVar1;
  short sVar2;
  undefined2 uVar4;
  undefined4 uVar3;
  int iVar5;
  undefined4 uVar6;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  fVar1 = FLOAT_803e8234;
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar5 = *(int *)(param_2 + 0xb8);
  param_3[0xa5] = (uint)FLOAT_803e8234;
  param_3[0xa1] = (uint)fVar1;
  param_3[0xa0] = (uint)fVar1;
  *(float *)(param_2 + 0x24) = fVar1;
  *(float *)(param_2 + 0x28) = fVar1;
  *(float *)(param_2 + 0x2c) = fVar1;
  *param_3 = *param_3 | 0x200000;
  param_3[0xa8] = (uint)FLOAT_803e827c;
  if ((int)*(short *)(param_2 + 0xa0) != (int)DAT_803dc748) {
    FUN_80030334(param_2,(int)DAT_803dc748,0);
  }
  uVar4 = FUN_800221a0(0x4b0,0x960);
  *(undefined2 *)(iVar5 + 0xa84) = uVar4;
  sVar2 = *(short *)(iVar5 + 0xa84) - (short)(int)param_1;
  *(short *)(iVar5 + 0xa84) = sVar2;
  if (sVar2 < 1) {
    uVar3 = 0xfffffffc;
  }
  else {
    if ((*(byte *)(param_2 + 0xaf) & 1) != 0) {
      iVar5 = FUN_800221a0(0,2);
      (**(code **)(*DAT_803dca54 + 0x48))(iVar5 + 6,param_2,0xffffffff);
      FUN_80014b3c(0,0x100);
    }
    uVar3 = 0;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return uVar3;
}

