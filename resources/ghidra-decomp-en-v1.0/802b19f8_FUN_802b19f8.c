// Function: FUN_802b19f8
// Entry: 802b19f8
// Size: 304 bytes

/* WARNING: Removing unreachable block (ram,0x802b1b08) */

void FUN_802b19f8(undefined8 param_1,undefined4 param_2,int param_3)

{
  double dVar1;
  char cVar3;
  undefined2 uVar2;
  undefined4 uVar4;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  *(undefined4 *)(param_3 + 0x6d0) = 0;
  *(undefined4 *)(param_3 + 0x6d4) = 0;
  *(undefined2 *)(param_3 + 0x6e0) = 0;
  *(undefined2 *)(param_3 + 0x6e2) = 0;
  *(undefined2 *)(param_3 + 0x6e4) = 0;
  if (((((*(uint *)(param_3 + 0x360) & 0x200000) == 0) && (*(short *)(param_3 + 0x81a) != -1)) &&
      (*(char *)(param_3 + 0x8c8) != 'D')) && (*(char *)(param_3 + 0x8c8) != 'N')) {
    cVar3 = FUN_80014cc0(0);
    *(int *)(param_3 + 0x6d0) = (int)cVar3;
    cVar3 = FUN_80014c6c(0);
    *(int *)(param_3 + 0x6d4) = (int)cVar3;
    uVar2 = FUN_80014ee8(0);
    *(undefined2 *)(param_3 + 0x6e0) = uVar2;
    uVar2 = FUN_80014e70(0);
    *(undefined2 *)(param_3 + 0x6e2) = uVar2;
    uVar2 = FUN_80014e14(0);
    *(undefined2 *)(param_3 + 0x6e4) = uVar2;
  }
  dVar1 = DOUBLE_803e7ec0;
  *(float *)(param_3 + 0x6dc) =
       (float)((double)CONCAT44(0x43300000,*(uint *)(param_3 + 0x6d0) ^ 0x80000000) -
              DOUBLE_803e7ec0);
  *(float *)(param_3 + 0x6d8) =
       (float)((double)CONCAT44(0x43300000,*(uint *)(param_3 + 0x6d4) ^ 0x80000000) - dVar1);
  FUN_802b18bc(param_1,param_2,param_3);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

