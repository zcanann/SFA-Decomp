// Function: FUN_801e8ee0
// Entry: 801e8ee0
// Size: 588 bytes

void FUN_801e8ee0(undefined2 *param_1)

{
  int iVar1;
  undefined2 uVar2;
  int iVar3;
  float *pfVar4;
  double dVar5;
  float local_80;
  undefined4 local_7c [2];
  undefined4 local_74;
  undefined auStack112 [28];
  undefined auStack84 [72];
  
  pfVar4 = *(float **)(param_1 + 0x5c);
  iVar3 = *(int *)(param_1 + 0x26);
  if (*pfVar4 < *(float *)(param_1 + 8)) {
    *(float *)(param_1 + 0x14) = -(FLOAT_803e5a74 * FLOAT_803db414 - *(float *)(param_1 + 0x14));
  }
  FUN_8002b95c((double)(FLOAT_803db414 * *(float *)(param_1 + 0x12) * pfVar4[1]),
               (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
               (double)(FLOAT_803db414 * *(float *)(param_1 + 0x16) * pfVar4[1]),param_1);
  FUN_802931a0((double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                       *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)));
  FUN_8002f5d4(param_1,&local_80);
  FUN_8002fa48((double)local_80,(double)FLOAT_803db414,param_1,0);
  if (*(float *)(param_1 + 8) < *pfVar4) {
    *(float *)(param_1 + 8) = *pfVar4;
    *(float *)(param_1 + 0x14) = FLOAT_803e5a78;
  }
  iVar1 = FUN_800640cc((double)FLOAT_803e5a7c,param_1 + 0x40,param_1 + 6,0,auStack112,param_1,8,
                       0xffffffff,0xff,10);
  if (iVar1 != 0) {
    FUN_8002273c(auStack84,param_1 + 0x12,local_7c);
    *(undefined4 *)(param_1 + 0x12) = local_7c[0];
    *(undefined4 *)(param_1 + 0x16) = local_74;
    uVar2 = FUN_800217c0(-(double)*(float *)(param_1 + 0x12),-(double)*(float *)(param_1 + 0x16));
    *param_1 = uVar2;
  }
  iVar1 = FUN_8002b9ec();
  dVar5 = (double)FUN_8002166c(iVar1 + 0x18,param_1 + 0xc);
  if (dVar5 < (double)FLOAT_803e5a80) {
    FUN_8000bb18(param_1,*(undefined2 *)(pfVar4 + 3));
    FUN_800999b4((double)FLOAT_803e5a84,param_1,(int)*(short *)((int)pfVar4 + 0xe),0x28);
    param_1[0x58] = param_1[0x58] | 0x8000;
    param_1[3] = param_1[3] | 0x4000;
    (**(code **)(**(int **)((int)pfVar4[2] + 0x68) + 0x50))
              (pfVar4[2],*(char *)(iVar3 + 0x19) != '\0',*(char *)(iVar3 + 0x19) == '\0');
  }
  if (((param_1[0x58] & 0x800) != 0) && (*(ushort *)(pfVar4 + 4) != 0)) {
    FUN_800972dc((double)FLOAT_803e5a84,(double)FLOAT_803e5a88,param_1,5,
                 *(ushort *)(pfVar4 + 4) & 0xff,1,0x14,0,0);
  }
  return;
}

