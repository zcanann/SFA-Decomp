// Function: FUN_801ae364
// Entry: 801ae364
// Size: 728 bytes

void FUN_801ae364(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,int param_12,uint *param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  undefined2 *puVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  int iVar7;
  int *piVar8;
  double dVar9;
  undefined auStack_38 [4];
  float local_34;
  undefined auStack_30 [4];
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  undefined8 local_18;
  
  piVar8 = *(int **)(param_9 + 0xb8);
  local_28 = DAT_802c2a88;
  local_24 = DAT_802c2a8c;
  local_20 = DAT_802c2a90;
  if (*(char *)((int)piVar8 + 0x21) != *(char *)((int)piVar8 + 0x22)) {
    if (*(int *)(param_9 + 200) != 0) {
      param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *(int *)(param_9 + 200));
      *(undefined4 *)(param_9 + 200) = 0;
      *(undefined *)(param_9 + 0xeb) = 0;
    }
    uVar3 = FUN_8002e144();
    if ((uVar3 & 0xff) == 0) {
      *(undefined *)((int)piVar8 + 0x22) = 0;
    }
    else {
      if (0 < *(char *)((int)piVar8 + 0x21)) {
        puVar4 = FUN_8002becc(0x18,*(undefined2 *)
                                    ((int)&local_2c + *(char *)((int)piVar8 + 0x21) * 2 + 2));
        param_12 = -1;
        param_13 = *(uint **)(param_9 + 0x30);
        uVar5 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,
                             4,0xff,0xffffffff,param_13,param_14,param_15,param_16);
        *(undefined4 *)(param_9 + 200) = uVar5;
        *(undefined *)(param_9 + 0xeb) = 1;
      }
      *(undefined *)((int)piVar8 + 0x22) = *(undefined *)((int)piVar8 + 0x21);
    }
  }
  if (*piVar8 == 0) {
    puVar6 = FUN_80037048(10,&local_2c);
    if (*(short *)(param_9 + 0x46) == 0x170) {
      param_12 = 0x16f;
    }
    else {
      param_12 = 0x16c;
    }
    for (iVar7 = 0; iVar7 < local_2c; iVar7 = iVar7 + 1) {
      if (param_12 == *(short *)(puVar6[iVar7] + 0x46)) {
        *piVar8 = puVar6[iVar7];
        iVar7 = local_2c;
      }
    }
  }
  if ((*(short *)(param_9 + 0x46) == 0x373) || (uVar3 = FUN_80020078(0x3a2), uVar3 != 0)) {
    iVar7 = *piVar8;
    if (*(short *)(param_9 + 0xa0) != 0x100) {
      FUN_8003042c((double)FLOAT_803e53e0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x100,0,param_12,param_13,param_14,param_15,param_16);
    }
    (**(code **)(**(int **)(iVar7 + 0x68) + 0x44))(iVar7,&local_34);
    local_34 = FLOAT_803e53e4;
    (**(code **)(**(int **)(iVar7 + 0x68) + 0x40))(iVar7,auStack_38,auStack_30);
    local_18 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
    FUN_8002fb40((double)local_34,(double)(float)(local_18 - DOUBLE_803e53e8));
    if (*piVar8 == 0) {
      *(undefined *)(piVar8 + 8) = 0xff;
      iVar7 = *(int *)(param_9 + 100);
      if (iVar7 != 0) {
        *(uint *)(iVar7 + 0x30) = *(uint *)(iVar7 + 0x30) & 0xffffefff;
      }
    }
    else {
      iVar7 = FUN_8002bac4();
      dVar9 = (double)FUN_800217c8((float *)(*piVar8 + 0x18),(float *)(iVar7 + 0x18));
      fVar1 = (float)(dVar9 - (double)FLOAT_803e53f4) / FLOAT_803e53f8;
      fVar2 = FLOAT_803e53e0;
      if ((FLOAT_803e53e0 <= fVar1) && (fVar2 = fVar1, FLOAT_803e53f0 < fVar1)) {
        fVar2 = FLOAT_803e53f0;
      }
      *(char *)(piVar8 + 8) = (char)(int)(FLOAT_803e53fc * (FLOAT_803e53f0 - fVar2));
      iVar7 = *(int *)(param_9 + 100);
      if (iVar7 != 0) {
        *(uint *)(iVar7 + 0x30) = *(uint *)(iVar7 + 0x30) | 0x1000;
      }
    }
  }
  return;
}

