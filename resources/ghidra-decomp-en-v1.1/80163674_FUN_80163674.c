// Function: FUN_80163674
// Entry: 80163674
// Size: 756 bytes

void FUN_80163674(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined2 *puVar7;
  undefined4 uVar8;
  int iVar9;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar10;
  int unaff_r29;
  int iVar11;
  int iVar12;
  double dVar13;
  undefined auStack_28 [4];
  int local_24;
  int local_20 [8];
  
  iVar4 = FUN_80286840();
  iVar12 = *(int *)(iVar4 + 0xb8);
  iVar11 = *(int *)(iVar4 + 0x4c);
  sVar1 = *(short *)(iVar4 + 0x46);
  if (sVar1 == 0x4b9) {
    unaff_r29 = 0x4ba;
  }
  else if (sVar1 < 0x4b9) {
    if (sVar1 == 0x3fd) {
      unaff_r29 = 0x3fb;
    }
    else if ((sVar1 < 0x3fd) && (sVar1 == 0x28d)) {
      iVar5 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28);
      if (iVar5 == 0) goto LAB_80163950;
      unaff_r29 = 0x39d;
    }
  }
  else if (sVar1 == 0x4be) {
    unaff_r29 = 0x4c1;
  }
  local_20[0] = 0;
  iVar10 = -1;
  iVar5 = iVar12;
  while ((local_20[0] < (int)(uint)*(byte *)(iVar12 + 0x50) && (iVar10 == -1))) {
    if (*(int *)(iVar5 + 0xc) == 0) {
      iVar10 = local_20[0];
    }
    iVar5 = iVar5 + 4;
    local_20[0] = local_20[0] + 1;
  }
  if (iVar10 != -1) {
    iVar5 = FUN_8002e1f4(local_20,&local_24);
    iVar9 = 0;
    while (local_20[0] < local_24) {
      iVar3 = local_20[0] + 1;
      iVar2 = local_20[0] * 4;
      local_20[0] = iVar3;
      if (unaff_r29 == *(short *)(*(int *)(iVar5 + iVar2) + 0x46)) {
        iVar9 = iVar9 + 1;
      }
    }
    if ((iVar9 < 7) && (uVar6 = FUN_8002e144(), (uVar6 & 0xff) != 0)) {
      puVar7 = FUN_8002becc(0x20,(short)unaff_r29);
      iVar5 = iVar12 + iVar10 * 0xc;
      *(float *)(puVar7 + 4) = *(float *)(iVar4 + 0xc) + *(float *)(iVar5 + 0x1c);
      *(float *)(puVar7 + 6) = *(float *)(iVar4 + 0x10) + *(float *)(iVar5 + 0x20);
      dVar13 = (double)*(float *)(iVar4 + 0x14);
      *(float *)(puVar7 + 8) = (float)(dVar13 + (double)*(float *)(iVar5 + 0x24));
      *(undefined *)(puVar7 + 2) = *(undefined *)(iVar11 + 4);
      *(undefined *)((int)puVar7 + 5) = *(undefined *)(iVar11 + 5);
      *(undefined *)(puVar7 + 3) = *(undefined *)(iVar11 + 6);
      *(undefined *)((int)puVar7 + 7) = *(undefined *)(iVar11 + 7);
      *(float *)(puVar7 + 0xe) = FLOAT_803e3bd8;
      if (((*(byte *)(iVar12 + 0x4c) & 1) != 0) &&
         ((*(int *)(*(int *)(iVar4 + 0x4c) + 0x14) == 0x292c && (*(short *)(iVar12 + 0x4e) == 6))))
      {
        *(undefined *)((int)puVar7 + 0x1b) = 1;
        iVar11 = FUN_8002e1f4(local_20,&local_24);
        for (; local_20[0] < local_24; local_20[0] = local_20[0] + 1) {
          iVar5 = *(int *)(iVar11 + local_20[0] * 4);
          if (*(short *)(iVar5 + 0x46) == 0x27f) {
            *(undefined4 *)(puVar7 + 4) = *(undefined4 *)(iVar5 + 0xc);
            *(undefined4 *)(puVar7 + 6) = *(undefined4 *)(*(int *)(iVar11 + local_20[0] * 4) + 0x10)
            ;
            *(undefined4 *)(puVar7 + 8) = *(undefined4 *)(*(int *)(iVar11 + local_20[0] * 4) + 0x14)
            ;
            local_20[0] = local_24;
          }
        }
      }
      uVar8 = FUN_8002e088(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar7,5,
                           *(undefined *)(iVar4 + 0xac),0xffffffff,*(uint **)(iVar4 + 0x30),in_r8,
                           in_r9,in_r10);
      iVar11 = iVar12 + iVar10 * 4;
      *(undefined4 *)(iVar11 + 0xc) = uVar8;
      (**(code **)(**(int **)(*(int *)(iVar11 + 0xc) + 0x68) + 0x24))
                ((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x14));
      *(short *)(iVar12 + 0x4e) = *(short *)(iVar12 + 0x4e) + 1;
    }
  }
LAB_80163950:
  FUN_8028688c();
  return;
}

