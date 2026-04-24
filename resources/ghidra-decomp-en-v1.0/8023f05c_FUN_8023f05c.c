// Function: FUN_8023f05c
// Entry: 8023f05c
// Size: 416 bytes

/* WARNING: Removing unreachable block (ram,0x8023f1d0) */
/* WARNING: Removing unreachable block (ram,0x8023f1c8) */
/* WARNING: Removing unreachable block (ram,0x8023f1d8) */

void FUN_8023f05c(short *param_1,int param_2)

{
  char cVar4;
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar5;
  undefined8 uVar6;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  float local_58;
  float local_54;
  float local_50 [2];
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
  cVar4 = FUN_8002e04c();
  if (cVar4 != '\0') {
    FUN_8003842c(param_1,0,&local_58,&local_54,local_50,0);
    dVar8 = (double)(local_58 - *(float *)(*(int *)(param_2 + 4) + 0xc));
    dVar7 = (double)(local_50[0] - *(float *)(*(int *)(param_2 + 4) + 0x14));
    uVar6 = FUN_802931a0((double)(float)(dVar8 * dVar8 + (double)(float)(dVar7 * dVar7)));
    uVar1 = FUN_800217c0(dVar8,dVar7);
    uVar2 = FUN_800217c0((double)(local_54 - *(float *)(*(int *)(param_2 + 4) + 0x10)),uVar6);
    DAT_803dddd0 = (int)(uVar2 & 0xffff) >> 8;
    iVar3 = FUN_8002bdf4(0x20,0x7e4);
    *(float *)(iVar3 + 8) = local_58;
    *(float *)(iVar3 + 0xc) = local_54;
    *(float *)(iVar3 + 0x10) = local_50[0];
    *(char *)(iVar3 + 0x1a) = (char)((int)*param_1 + (uVar1 & 0xffff) + 0x8000 >> 8);
    *(char *)(iVar3 + 0x19) = (char)DAT_803dddd0;
    *(undefined *)(iVar3 + 0x18) = 0;
    *(undefined *)(iVar3 + 4) = 1;
    *(undefined *)(iVar3 + 5) = 1;
    iVar3 = FUN_8002b5a0(param_1);
    if (iVar3 != 0) {
      FUN_8022e600(iVar3,DAT_803dc510);
      uStack68 = DAT_803dc50c ^ 0x80000000;
      local_48 = 0x43300000;
      FUN_8022e54c((double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e75a0),iVar3);
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  return;
}

