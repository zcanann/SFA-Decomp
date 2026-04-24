// Function: FUN_80222160
// Entry: 80222160
// Size: 504 bytes

/* WARNING: Removing unreachable block (ram,0x80222330) */
/* WARNING: Removing unreachable block (ram,0x80222328) */
/* WARNING: Removing unreachable block (ram,0x80222338) */

void FUN_80222160(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6,undefined4 *param_7)

{
  int iVar1;
  int iVar2;
  char cVar4;
  short sVar3;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  double extraout_f1;
  double dVar8;
  double dVar9;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar10;
  float local_68;
  float local_64;
  float local_60;
  undefined4 local_58;
  uint uStack84;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar10 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  iVar6 = 0;
  local_68 = *(float *)(iVar1 + 0xc) - *(float *)(iVar5 + 0x68);
  local_60 = *(float *)(iVar1 + 0x14) - *(float *)(iVar5 + 0x70);
  dVar9 = extraout_f1;
  dVar8 = (double)FUN_802931a0((double)(local_68 * local_68 + local_60 * local_60));
  if (dVar8 < param_2) {
    iVar2 = FUN_80010320(dVar9,iVar5);
    if ((iVar2 != 0) || (*(int *)(iVar5 + 0x10) != 0)) {
      cVar4 = (**(code **)(*DAT_803dca9c + 0x9c))(iVar5,*param_7);
      if (cVar4 == '\0') {
        iVar6 = (int)*(char *)(*(int *)(iVar5 + 0x9c) + 0x18);
      }
      else {
        iVar6 = -1;
      }
      *param_7 = 0;
    }
    param_3 = (double)(float)((double)FLOAT_803e6c78 * dVar9);
  }
  local_68 = *(float *)(iVar5 + 0x68) - *(float *)(iVar1 + 0xc);
  local_64 = *(float *)(iVar5 + 0x6c) - *(float *)(iVar1 + 0x10);
  local_60 = *(float *)(iVar5 + 0x70) - *(float *)(iVar1 + 0x14);
  if ((param_6 & 0xff) == 0) {
    iVar2 = *(int *)(iVar1 + 0xb8);
    local_68 = *(float *)(iVar1 + 0xc) - *(float *)(iVar5 + 0x68);
    local_60 = *(float *)(iVar1 + 0x14) - *(float *)(iVar5 + 0x70);
    sVar3 = FUN_800217c0();
    uStack84 = -(int)sVar3 ^ 0x80000000;
    local_58 = 0x43300000;
    dVar8 = (double)((FLOAT_803e6c60 *
                     (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e6c50)) /
                    FLOAT_803e6c64);
    dVar9 = (double)FUN_80293e80(dVar8);
    *(float *)(iVar2 + 0x290) = (float)(param_3 * -dVar9);
    dVar9 = (double)FUN_80294204(dVar8);
    *(float *)(iVar2 + 0x28c) = (float)(param_3 * -dVar9);
  }
  else {
    FUN_80221f14(param_3,(double)(float)(param_3 / (double)FLOAT_803e6c7c),(double)FLOAT_803e6c80,
                 iVar1,iVar1 + 0x24,&local_68);
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  FUN_80286128(iVar6);
  return;
}

