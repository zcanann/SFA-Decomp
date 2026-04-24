// Function: FUN_801a43c8
// Entry: 801a43c8
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x801a44d4) */
/* WARNING: Removing unreachable block (ram,0x801a44dc) */

void FUN_801a43c8(int param_1)

{
  int iVar1;
  int iVar2;
  short sVar3;
  undefined uVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8002b9ec();
  uVar4 = 0xff;
  iVar2 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x20));
  if (iVar2 != 0) {
    sVar3 = FUN_800385e8(param_1,iVar1,0);
    iVar2 = (int)sVar3;
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (iVar2 < 0x4001) {
      dVar9 = (double)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1a) ^ 0x80000000
                                              ) - DOUBLE_803e43e0);
      dVar7 = (double)FUN_80021704(param_1 + 0x18,iVar1 + 0x18);
      dVar8 = (double)FUN_8000f480((double)*(float *)(param_1 + 0xc),
                                   (double)*(float *)(param_1 + 0x10),
                                   (double)*(float *)(param_1 + 0x14));
      if (dVar8 < dVar7) {
        dVar7 = (double)FUN_8000f480((double)*(float *)(param_1 + 0xc),
                                     (double)*(float *)(param_1 + 0x10),
                                     (double)*(float *)(param_1 + 0x14));
      }
      if (dVar7 < dVar9) {
        uVar4 = (undefined)(int)(FLOAT_803e43dc * (float)(dVar7 / dVar9));
      }
      *(undefined *)(param_1 + 0x36) = uVar4;
    }
    else {
      *(undefined *)(param_1 + 0x36) = 0;
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

