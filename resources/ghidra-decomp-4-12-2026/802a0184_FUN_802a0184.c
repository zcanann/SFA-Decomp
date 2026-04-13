// Function: FUN_802a0184
// Entry: 802a0184
// Size: 1452 bytes

void FUN_802a0184(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint *puVar5;
  int in_r6;
  float *pfVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  int in_r10;
  int *piVar7;
  undefined2 *puVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 uVar13;
  short asStack_48 [4];
  float local_40;
  float local_3c;
  float local_38;
  float fStack_34;
  float local_30;
  float afStack_28 [10];
  
  uVar13 = FUN_8028683c();
  iVar4 = (int)((ulonglong)uVar13 >> 0x20);
  puVar5 = (uint *)uVar13;
  iVar9 = *(int *)(iVar4 + 0xb8);
  puVar8 = *(undefined2 **)(iVar9 + 0x7f0);
  *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) & 0xfffffffd;
  *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) | 0x2000;
  puVar5[1] = puVar5[1] | 0x100000;
  fVar2 = FLOAT_803e8b3c;
  puVar5[0xa0] = (uint)FLOAT_803e8b3c;
  puVar5[0xa1] = (uint)fVar2;
  *puVar5 = *puVar5 | 0x200000;
  *(float *)(iVar4 + 0x24) = fVar2;
  *(float *)(iVar4 + 0x2c) = fVar2;
  *(undefined *)((int)puVar5 + 0x25f) = 0;
  if (*(char *)((int)puVar5 + 0x27a) != '\0') {
    *(undefined2 *)(puVar5 + 0x9e) = 0x16;
    *(undefined4 *)(iVar9 + 0x898) = 0;
  }
  FUN_80035ff8(iVar4);
  *(float *)(iVar4 + 0x28) = FLOAT_803e8b3c;
  if (*(char *)((int)puVar5 + 0x27a) == '\0') goto LAB_802a05d8;
  if ((DAT_803df0cc != 0) && ((*(byte *)(iVar9 + 0x3f4) >> 6 & 1) != 0)) {
    *(undefined *)(iVar9 + 0x8b4) = 1;
    *(byte *)(iVar9 + 0x3f4) = *(byte *)(iVar9 + 0x3f4) & 0xf7 | 8;
  }
  sVar1 = puVar8[0x23];
  if (sVar1 == 0x38c) {
    *(undefined **)(iVar9 + 0x6e8) = &DAT_80333f10;
    *(undefined *)(iVar9 + 0x6ec) = 3;
    (**(code **)(*DAT_803dd6d0 + 0x28))(puVar8,0);
    in_r6 = 0;
    in_r7 = 0;
    in_r8 = 0;
    in_r9 = 0xff;
    in_r10 = *DAT_803dd6d0;
    (**(code **)(in_r10 + 0x1c))(0x45,1,0);
  }
  else if (sVar1 < 0x38c) {
    if (sVar1 == 0x8c) {
      *(undefined **)(iVar9 + 0x6e8) = &DAT_80333f28;
      *(undefined *)(iVar9 + 0x6ec) = 4;
    }
    else if ((sVar1 < 0x8c) && (sVar1 == 0x72)) {
      *(undefined **)(iVar9 + 0x6e8) = &DAT_80333f10;
      *(undefined *)(iVar9 + 0x6ec) = 3;
      param_2 = (double)*(float *)(iVar4 + 0x14);
      iVar3 = FUN_8005b128();
      if (iVar3 == 0x13) {
        FUN_800201ac(0xf0a,1);
      }
      in_r6 = 0;
      in_r7 = 0;
      in_r8 = 0;
      in_r9 = 0xff;
      in_r10 = *DAT_803dd6d0;
      (**(code **)(in_r10 + 0x1c))(0x45,1,0);
    }
    else {
LAB_802a0410:
      *(undefined2 **)(iVar9 + 0x6e8) = &DAT_80333f40;
      *(undefined *)(iVar9 + 0x6ec) = 4;
      in_r6 = *DAT_803dd6d0;
      (**(code **)(in_r6 + 0x24))(0,0x1d,0);
    }
  }
  else if (sVar1 == 0x419) {
    *(undefined2 **)(iVar9 + 0x6e8) = &DAT_80333f40;
    in_r6 = 0;
    in_r7 = 0;
    in_r8 = 0x2d;
    in_r9 = 0xff;
    in_r10 = *DAT_803dd6d0;
    (**(code **)(in_r10 + 0x1c))(0x53,1,0);
  }
  else {
    if ((0x418 < sVar1) || (sVar1 != 0x416)) goto LAB_802a0410;
    *(undefined2 **)(iVar9 + 0x6e8) = &DAT_80333f58;
    *(undefined *)(iVar9 + 0x6ec) = 8;
    (**(code **)(*DAT_803dd6d0 + 0x28))(puVar8,0);
    in_r6 = *DAT_803dd6d0;
    (**(code **)(in_r6 + 0x24))(0,0x69,0);
  }
  iVar3 = (**(code **)(**(int **)(puVar8 + 0x34) + 0x24))(puVar8);
  (**(code **)(**(int **)(puVar8 + 0x34) + 0x3c))(puVar8,1);
  if (((iVar3 == 2) || (1 < iVar3)) || (iVar3 < 1)) {
    iVar3 = 7;
  }
  else {
    iVar3 = 6;
  }
  *(undefined2 *)(iVar9 + 0x478) = *puVar8;
  *(undefined2 *)(iVar9 + 0x484) = *(undefined2 *)(iVar9 + 0x478);
  FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
               (int)*(short *)(*(int *)(iVar9 + 0x6e8) + iVar3 * 2),4,in_r6,in_r7,in_r8,in_r9,in_r10
              );
  piVar7 = *(int **)(*(int *)(iVar4 + 0x7c) + *(char *)(iVar4 + 0xad) * 4);
  FUN_80027ec4((double)FLOAT_803e8b3c,(double)*(float *)(iVar4 + 8),piVar7,0,0,afStack_28,asStack_48
              );
  FUN_80027ec4((double)FLOAT_803e8b78,(double)*(float *)(iVar4 + 8),piVar7,0,0,&fStack_34,asStack_48
              );
  (**(code **)(**(int **)(puVar8 + 0x34) + 0x28))(puVar8,&local_40,&local_3c,&local_38);
  local_40 = local_40 - *(float *)(iVar4 + 0xc);
  local_3c = local_3c - *(float *)(iVar4 + 0x10);
  local_38 = local_38 - *(float *)(iVar4 + 0x14);
  *(float *)(iVar9 + 0x6b4) = *(float *)(iVar4 + 0xc);
  *(undefined4 *)(iVar9 + 0x6b8) = *(undefined4 *)(iVar4 + 0x10);
  *(undefined4 *)(iVar9 + 0x6bc) = *(undefined4 *)(iVar4 + 0x14);
  *(float *)(iVar9 + 0x6c0) = local_40;
  *(float *)(iVar9 + 0x6c4) = local_3c - local_30;
  *(float *)(iVar9 + 0x6c8) = local_38;
  *(ushort *)(iVar4 + 6) = *(ushort *)(iVar4 + 6) | 8;
  *(uint *)(*(int *)(iVar4 + 100) + 0x30) = *(uint *)(*(int *)(iVar4 + 100) + 0x30) | 0x1000;
  *(undefined2 *)(*(int *)(iVar4 + 100) + 0x36) = 0;
  puVar5[0xa8] = (uint)FLOAT_803e8c70;
LAB_802a05d8:
  *(float *)(iVar4 + 0xc) =
       *(float *)(iVar4 + 0x98) * *(float *)(iVar9 + 0x6c0) + *(float *)(iVar9 + 0x6b4);
  *(float *)(iVar4 + 0x10) =
       *(float *)(iVar4 + 0x98) * *(float *)(iVar9 + 0x6c4) + *(float *)(iVar9 + 0x6b8);
  *(float *)(iVar4 + 0x14) =
       *(float *)(iVar4 + 0x98) * *(float *)(iVar9 + 0x6c8) + *(float *)(iVar9 + 0x6bc);
  pfVar6 = &local_38;
  iVar3 = **(int **)(puVar8 + 0x34);
  (**(code **)(iVar3 + 0x34))(puVar8,&local_40,&local_3c);
  dVar12 = (double)*(float *)(iVar4 + 0x98);
  dVar10 = (double)(float)(dVar12 * (double)(float)((double)local_3c -
                                                   (double)*(float *)(iVar9 + 0x6b8)) +
                          (double)*(float *)(iVar9 + 0x6b8));
  dVar11 = (double)(float)(dVar12 * (double)(float)((double)local_38 -
                                                   (double)*(float *)(iVar9 + 0x6bc)) +
                          (double)*(float *)(iVar9 + 0x6bc));
  (**(code **)(*DAT_803dd6d0 + 0x2c))
            ((double)(float)(dVar12 * (double)(float)((double)local_40 -
                                                     (double)*(float *)(iVar9 + 0x6b4)) +
                            (double)*(float *)(iVar9 + 0x6b4)));
  if ((*(char *)((int)puVar5 + 0x27a) == '\0') && (*(char *)((int)puVar5 + 0x346) != '\0')) {
    FUN_8003042c((double)FLOAT_803e8b3c,dVar10,dVar11,dVar12,param_5,param_6,param_7,param_8,iVar4,
                 (int)**(short **)(iVar9 + 0x6e8),1,pfVar6,iVar3,in_r8,in_r9,in_r10);
    (**(code **)(**(int **)(puVar8 + 0x34) + 0x3c))(puVar8,2);
    iVar4 = FUN_80080100((int *)&DAT_80333c80,4,(int)(short)puVar8[0x23]);
    if (iVar4 == -1) {
      puVar5[0xc2] = (uint)FUN_8029fddc;
    }
    else {
      puVar5[0xc2] = (uint)FUN_8029fddc;
    }
  }
  FUN_80286888();
  return;
}

