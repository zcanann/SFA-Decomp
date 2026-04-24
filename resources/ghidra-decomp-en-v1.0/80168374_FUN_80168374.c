// Function: FUN_80168374
// Entry: 80168374
// Size: 488 bytes

/* WARNING: Removing unreachable block (ram,0x8016852c) */
/* WARNING: Removing unreachable block (ram,0x80168534) */

void FUN_80168374(int param_1,int param_2,char param_3)

{
  char cVar2;
  uint uVar1;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar4 = *(int *)(param_2 + 0x40c);
  iVar3 = *(int *)(param_1 + 0x4c);
  cVar2 = FUN_8002e04c();
  if (cVar2 != '\0') {
    dVar6 = (double)(FLOAT_803e30a0 +
                    (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar3 + 0x28) ^ 0x80000000) -
                           DOUBLE_803e3070) / FLOAT_803e30a4);
    iVar3 = FUN_8002bdf4(0x24,0x51b);
    if (param_3 == '\0') {
      *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar4 + 0x28);
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar4 + 0x2c);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar4 + 0x30);
    }
    else {
      *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar4 + 0x14);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar4 + 0x18);
    }
    *(undefined *)(iVar3 + 4) = 1;
    *(undefined *)(iVar3 + 5) = 4;
    *(undefined *)(iVar3 + 6) = 0xff;
    *(undefined *)(iVar3 + 7) = 0xff;
    iVar4 = FUN_8002df90(iVar3,5,0xffffffff,0xffffffff,0);
    if (iVar4 != 0) {
      dVar7 = (double)(FLOAT_803e30ac *
                      (*(float *)(param_2 + 0x2c0) /
                      (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x3fe)) -
                             DOUBLE_803e3068)));
      *(float *)(iVar4 + 0x24) =
           (float)((double)(*(float *)(*(int *)(param_2 + 0x2d0) + 0xc) - *(float *)(iVar3 + 8)) /
                  dVar7);
      uVar1 = FUN_800221a0(0xfffffff6,10);
      *(float *)(iVar4 + 0x28) =
           (float)((double)(((float)((double)FLOAT_803e30a8 * dVar6 +
                                    (double)*(float *)(*(int *)(param_2 + 0x2d0) + 0x10)) +
                            (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                   DOUBLE_803e3070)) - *(float *)(iVar3 + 0xc)) / dVar7);
      *(float *)(iVar4 + 0x2c) =
           (float)((double)(*(float *)(*(int *)(param_2 + 0x2d0) + 0x14) - *(float *)(iVar3 + 0x10))
                  / dVar7);
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  return;
}

