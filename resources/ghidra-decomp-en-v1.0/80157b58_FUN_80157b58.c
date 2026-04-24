// Function: FUN_80157b58
// Entry: 80157b58
// Size: 388 bytes

/* WARNING: Removing unreachable block (ram,0x80157cb4) */

void FUN_80157b58(undefined4 param_1,int param_2)

{
  char cVar4;
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar5;
  undefined8 in_f31;
  double dVar6;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  cVar4 = FUN_8002e04c();
  if (cVar4 != '\0') {
    iVar1 = FUN_8002bdf4(0x24,0x869);
    FUN_8003842c(param_1,0,iVar1 + 8,iVar1 + 0xc,iVar1 + 0x10,0);
    *(undefined *)(iVar1 + 4) = 1;
    *(undefined *)(iVar1 + 5) = 4;
    *(undefined *)(iVar1 + 6) = 0xff;
    *(undefined *)(iVar1 + 7) = 0xff;
    iVar2 = FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
    if (iVar2 != 0) {
      dVar6 = (double)(FLOAT_803e2b84 *
                      ((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a4)) -
                              DOUBLE_803e2b90) / *(float *)(param_2 + 0x2a8)));
      *(float *)(iVar2 + 0x24) =
           (float)((double)(*(float *)(*(int *)(param_2 + 0x29c) + 0xc) - *(float *)(iVar1 + 8)) /
                  dVar6);
      uVar3 = FUN_800221a0(0xfffffff6,10);
      *(float *)(iVar2 + 0x28) =
           (float)((double)((FLOAT_803e2b88 + *(float *)(*(int *)(param_2 + 0x29c) + 0x10) +
                            (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) -
                                   DOUBLE_803e2b98)) - *(float *)(iVar1 + 0xc)) / dVar6);
      *(float *)(iVar2 + 0x2c) =
           (float)((double)(*(float *)(*(int *)(param_2 + 0x29c) + 0x14) - *(float *)(iVar1 + 0x10))
                  / dVar6);
    }
    FUN_8000bb18(param_1,0x4ae);
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

