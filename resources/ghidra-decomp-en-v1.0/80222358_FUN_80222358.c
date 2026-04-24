// Function: FUN_80222358
// Entry: 80222358
// Size: 504 bytes

/* WARNING: Removing unreachable block (ram,0x80222520) */
/* WARNING: Removing unreachable block (ram,0x80222518) */
/* WARNING: Removing unreachable block (ram,0x80222528) */

int FUN_80222358(double param_1,double param_2,double param_3,int param_4,int param_5,char param_6)

{
  int iVar1;
  char cVar3;
  short sVar2;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  float local_58;
  float local_54;
  float local_50;
  undefined4 local_48;
  uint uStack68;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar4 = 0;
  local_58 = *(float *)(param_4 + 0xc) - *(float *)(param_5 + 0x68);
  local_50 = *(float *)(param_4 + 0x14) - *(float *)(param_5 + 0x70);
  dVar6 = (double)FUN_802931a0((double)(local_58 * local_58 + local_50 * local_50));
  if (dVar6 < param_2) {
    iVar1 = FUN_80010320(param_1,param_5);
    if ((iVar1 != 0) || (*(int *)(param_5 + 0x10) != 0)) {
      cVar3 = (**(code **)(*DAT_803dca9c + 0x90))(param_5);
      if (cVar3 == '\0') {
        iVar4 = (int)*(char *)(*(int *)(param_5 + 0x9c) + 0x18);
      }
      else {
        iVar4 = -1;
      }
    }
    param_3 = (double)(float)((double)FLOAT_803e6c78 * param_1);
  }
  local_58 = *(float *)(param_5 + 0x68) - *(float *)(param_4 + 0xc);
  local_54 = *(float *)(param_5 + 0x6c) - *(float *)(param_4 + 0x10);
  local_50 = *(float *)(param_5 + 0x70) - *(float *)(param_4 + 0x14);
  if (param_6 == '\0') {
    iVar1 = *(int *)(param_4 + 0xb8);
    local_58 = *(float *)(param_4 + 0xc) - *(float *)(param_5 + 0x68);
    local_50 = *(float *)(param_4 + 0x14) - *(float *)(param_5 + 0x70);
    sVar2 = FUN_800217c0();
    uStack68 = -(int)sVar2 ^ 0x80000000;
    local_48 = 0x43300000;
    dVar7 = (double)((FLOAT_803e6c60 *
                     (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e6c50)) /
                    FLOAT_803e6c64);
    dVar6 = (double)FUN_80293e80(dVar7);
    *(float *)(iVar1 + 0x290) = (float)(param_3 * -dVar6);
    dVar6 = (double)FUN_80294204(dVar7);
    *(float *)(iVar1 + 0x28c) = (float)(param_3 * -dVar6);
  }
  else {
    FUN_80221f14(param_3,(double)(float)(param_3 / (double)FLOAT_803e6c7c),(double)FLOAT_803e6c80,
                 param_4,param_4 + 0x24,&local_58);
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  return iVar4;
}

