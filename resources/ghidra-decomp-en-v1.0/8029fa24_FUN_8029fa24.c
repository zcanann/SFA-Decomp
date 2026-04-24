// Function: FUN_8029fa24
// Entry: 8029fa24
// Size: 1452 bytes

void FUN_8029fa24(void)

{
  float fVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  uint *puVar5;
  undefined4 uVar6;
  undefined2 *puVar7;
  int iVar8;
  undefined8 uVar9;
  undefined auStack72 [8];
  float local_40;
  float local_3c;
  float local_38;
  undefined auStack52 [4];
  float local_30;
  undefined auStack40 [40];
  
  uVar9 = FUN_802860d8();
  iVar4 = (int)((ulonglong)uVar9 >> 0x20);
  puVar5 = (uint *)uVar9;
  iVar8 = *(int *)(iVar4 + 0xb8);
  puVar7 = *(undefined2 **)(iVar8 + 0x7f0);
  *(uint *)(iVar8 + 0x360) = *(uint *)(iVar8 + 0x360) & 0xfffffffd;
  *(uint *)(iVar8 + 0x360) = *(uint *)(iVar8 + 0x360) | 0x2000;
  puVar5[1] = puVar5[1] | 0x100000;
  fVar1 = FLOAT_803e7ea4;
  puVar5[0xa0] = (uint)FLOAT_803e7ea4;
  puVar5[0xa1] = (uint)fVar1;
  *puVar5 = *puVar5 | 0x200000;
  *(float *)(iVar4 + 0x24) = fVar1;
  *(float *)(iVar4 + 0x2c) = fVar1;
  *(undefined *)((int)puVar5 + 0x25f) = 0;
  if (*(char *)((int)puVar5 + 0x27a) != '\0') {
    *(undefined2 *)(puVar5 + 0x9e) = 0x16;
    *(undefined4 *)(iVar8 + 0x898) = 0;
  }
  FUN_80035f00(iVar4);
  *(float *)(iVar4 + 0x28) = FLOAT_803e7ea4;
  if (*(char *)((int)puVar5 + 0x27a) == '\0') goto LAB_8029fe78;
  if ((DAT_803de44c != 0) && ((*(byte *)(iVar8 + 0x3f4) >> 6 & 1) != 0)) {
    *(undefined *)(iVar8 + 0x8b4) = 1;
    *(byte *)(iVar8 + 0x3f4) = *(byte *)(iVar8 + 0x3f4) & 0xf7 | 8;
  }
  sVar2 = puVar7[0x23];
  if (sVar2 == 0x38c) {
    *(undefined **)(iVar8 + 0x6e8) = &DAT_803332b0;
    *(undefined *)(iVar8 + 0x6ec) = 3;
    (**(code **)(*DAT_803dca50 + 0x28))(puVar7,0);
    (**(code **)(*DAT_803dca50 + 0x1c))(0x45,1,0,0,0,0,0xff);
  }
  else if (sVar2 < 0x38c) {
    if (sVar2 == 0x8c) {
      *(undefined **)(iVar8 + 0x6e8) = &DAT_803332c8;
      *(undefined *)(iVar8 + 0x6ec) = 4;
    }
    else if ((sVar2 < 0x8c) && (sVar2 == 0x72)) {
      *(undefined **)(iVar8 + 0x6e8) = &DAT_803332b0;
      *(undefined *)(iVar8 + 0x6ec) = 3;
      iVar3 = FUN_8005afac((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x14));
      if (iVar3 == 0x13) {
        FUN_800200e8(0xf0a,1);
      }
      (**(code **)(*DAT_803dca50 + 0x1c))(0x45,1,0,0,0,0,0xff);
    }
    else {
LAB_8029fcb0:
      *(undefined **)(iVar8 + 0x6e8) = &DAT_803332e0;
      *(undefined *)(iVar8 + 0x6ec) = 4;
      (**(code **)(*DAT_803dca50 + 0x24))(0,0x1d,0);
    }
  }
  else if (sVar2 == 0x419) {
    *(undefined **)(iVar8 + 0x6e8) = &DAT_803332e0;
    (**(code **)(*DAT_803dca50 + 0x1c))(0x53,1,0,0,0,0x2d,0xff);
  }
  else {
    if ((0x418 < sVar2) || (sVar2 != 0x416)) goto LAB_8029fcb0;
    *(undefined2 **)(iVar8 + 0x6e8) = &DAT_803332f8;
    *(undefined *)(iVar8 + 0x6ec) = 8;
    (**(code **)(*DAT_803dca50 + 0x28))(puVar7,0);
    (**(code **)(*DAT_803dca50 + 0x24))(0,0x69,0);
  }
  iVar3 = (**(code **)(**(int **)(puVar7 + 0x34) + 0x24))(puVar7);
  (**(code **)(**(int **)(puVar7 + 0x34) + 0x3c))(puVar7,1);
  if (((iVar3 == 2) || (1 < iVar3)) || (iVar3 < 1)) {
    iVar3 = 7;
  }
  else {
    iVar3 = 6;
  }
  *(undefined2 *)(iVar8 + 0x478) = *puVar7;
  *(undefined2 *)(iVar8 + 0x484) = *(undefined2 *)(iVar8 + 0x478);
  FUN_80030334((double)FLOAT_803e7ea4,iVar4,(int)*(short *)(*(int *)(iVar8 + 0x6e8) + iVar3 * 2),4);
  uVar6 = *(undefined4 *)(*(int *)(iVar4 + 0x7c) + *(char *)(iVar4 + 0xad) * 4);
  FUN_80027e00((double)FLOAT_803e7ea4,(double)*(float *)(iVar4 + 8),uVar6,0,0,auStack40,auStack72);
  FUN_80027e00((double)FLOAT_803e7ee0,(double)*(float *)(iVar4 + 8),uVar6,0,0,auStack52,auStack72);
  (**(code **)(**(int **)(puVar7 + 0x34) + 0x28))(puVar7,&local_40,&local_3c,&local_38);
  local_40 = local_40 - *(float *)(iVar4 + 0xc);
  local_3c = local_3c - *(float *)(iVar4 + 0x10);
  local_38 = local_38 - *(float *)(iVar4 + 0x14);
  *(float *)(iVar8 + 0x6b4) = *(float *)(iVar4 + 0xc);
  *(undefined4 *)(iVar8 + 0x6b8) = *(undefined4 *)(iVar4 + 0x10);
  *(undefined4 *)(iVar8 + 0x6bc) = *(undefined4 *)(iVar4 + 0x14);
  *(float *)(iVar8 + 0x6c0) = local_40;
  *(float *)(iVar8 + 0x6c4) = local_3c - local_30;
  *(float *)(iVar8 + 0x6c8) = local_38;
  *(ushort *)(iVar4 + 6) = *(ushort *)(iVar4 + 6) | 8;
  *(uint *)(*(int *)(iVar4 + 100) + 0x30) = *(uint *)(*(int *)(iVar4 + 100) + 0x30) | 0x1000;
  *(undefined2 *)(*(int *)(iVar4 + 100) + 0x36) = 0;
  puVar5[0xa8] = (uint)FLOAT_803e7fd8;
LAB_8029fe78:
  *(float *)(iVar4 + 0xc) =
       *(float *)(iVar4 + 0x98) * *(float *)(iVar8 + 0x6c0) + *(float *)(iVar8 + 0x6b4);
  *(float *)(iVar4 + 0x10) =
       *(float *)(iVar4 + 0x98) * *(float *)(iVar8 + 0x6c4) + *(float *)(iVar8 + 0x6b8);
  *(float *)(iVar4 + 0x14) =
       *(float *)(iVar4 + 0x98) * *(float *)(iVar8 + 0x6c8) + *(float *)(iVar8 + 0x6bc);
  (**(code **)(**(int **)(puVar7 + 0x34) + 0x34))(puVar7,&local_40,&local_3c,&local_38);
  fVar1 = *(float *)(iVar4 + 0x98);
  (**(code **)(*DAT_803dca50 + 0x2c))
            ((double)(fVar1 * (local_40 - *(float *)(iVar8 + 0x6b4)) + *(float *)(iVar8 + 0x6b4)),
             (double)(fVar1 * (local_3c - *(float *)(iVar8 + 0x6b8)) + *(float *)(iVar8 + 0x6b8)),
             (double)(fVar1 * (local_38 - *(float *)(iVar8 + 0x6bc)) + *(float *)(iVar8 + 0x6bc)));
  if ((*(char *)((int)puVar5 + 0x27a) == '\0') && (*(char *)((int)puVar5 + 0x346) != '\0')) {
    FUN_80030334((double)FLOAT_803e7ea4,iVar4,(int)**(short **)(iVar8 + 0x6e8),1);
    (**(code **)(**(int **)(puVar7 + 0x34) + 0x3c))(puVar7,2);
    iVar4 = FUN_8007fe74(&DAT_80333020,4,(int)(short)puVar7[0x23]);
    if (iVar4 == -1) {
      puVar5[0xc2] = (uint)FUN_8029f67c;
      uVar6 = 0x19;
    }
    else {
      puVar5[0xc2] = (uint)FUN_8029f67c;
      uVar6 = 0x1b;
    }
  }
  else {
    uVar6 = 0;
  }
  FUN_80286124(uVar6);
  return;
}

