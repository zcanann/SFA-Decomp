// Function: FUN_8029f108
// Entry: 8029f108
// Size: 1396 bytes

/* WARNING: Removing unreachable block (ram,0x8029f65c) */

void FUN_8029f108(void)

{
  float fVar1;
  short sVar2;
  int iVar3;
  undefined2 *puVar4;
  uint *puVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  undefined2 *puVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined8 uVar14;
  undefined auStack120 [4];
  undefined2 local_74;
  undefined2 local_72;
  undefined2 local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60 [2];
  float local_58;
  undefined auStack84 [4];
  float local_50;
  undefined4 local_48;
  uint uStack68;
  longlong local_40;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar14 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar14 >> 0x20);
  puVar5 = (uint *)uVar14;
  iVar10 = *(int *)(iVar3 + 0xb8);
  puVar9 = *(undefined2 **)(iVar10 + 0x7f0);
  if (*(char *)((int)puVar5 + 0x27a) != '\0') {
    *(undefined2 *)(puVar5 + 0x9e) = 0x19;
    *(undefined4 *)(iVar10 + 0x898) = 0;
  }
  iVar6 = *(int *)(iVar3 + 0xb8);
  *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) & 0xfffffffd;
  *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) | 0x2000;
  puVar5[1] = puVar5[1] | 0x100000;
  fVar1 = FLOAT_803e7ea4;
  puVar5[0xa0] = (uint)FLOAT_803e7ea4;
  puVar5[0xa1] = (uint)fVar1;
  *puVar5 = *puVar5 | 0x200000;
  *(float *)(iVar3 + 0x24) = fVar1;
  *(float *)(iVar3 + 0x2c) = fVar1;
  *(undefined *)((int)puVar5 + 0x25f) = 0;
  FUN_80035f00(iVar3);
  *(float *)(iVar3 + 0x28) = FLOAT_803e7ea4;
  if (*(char *)((int)puVar5 + 0x27a) != '\0') {
    (**(code **)(**(int **)(puVar9 + 0x34) + 0x28))(puVar9,iVar3 + 0xc,iVar3 + 0x10,iVar3 + 0x14);
    sVar2 = puVar9[0x23];
    if ((sVar2 == 0x38c) || ((sVar2 < 0x38c && (sVar2 == 0x72)))) {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,100,0xff);
    }
    else {
      (**(code **)(*DAT_803dca50 + 0x24))(0,1,0);
    }
    iVar6 = (**(code **)(**(int **)(puVar9 + 0x34) + 0x30))(puVar9);
    (**(code **)(**(int **)(puVar9 + 0x34) + 0x3c))(puVar9,3);
    if (((iVar6 == 2) || (1 < iVar6)) || (iVar6 < 1)) {
      iVar7 = 9;
    }
    else {
      iVar7 = 8;
    }
    *(undefined2 *)(iVar10 + 0x478) = *puVar9;
    *(undefined2 *)(iVar10 + 0x484) = *(undefined2 *)(iVar10 + 0x478);
    *(undefined2 *)(iVar3 + 2) = 0;
    *(undefined2 *)(iVar3 + 4) = 0;
    FUN_80030334((double)FLOAT_803e7ea4,iVar3,(int)*(short *)(*(int *)(iVar10 + 0x6e8) + iVar7 * 2),
                 1);
    uVar8 = *(undefined4 *)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4);
    FUN_80027e00((double)FLOAT_803e7ea4,(double)*(float *)(iVar3 + 8),uVar8,0,0,auStack84,&local_74)
    ;
    FUN_80027e00((double)FLOAT_803e7ee0,(double)*(float *)(iVar3 + 8),uVar8,0,0,local_60,&local_74);
    local_74 = *(undefined2 *)(iVar10 + 0x478);
    local_72 = 0;
    local_70 = 0;
    FUN_80021ac8(&local_74,local_60);
    local_60[0] = local_60[0] + *(float *)(iVar3 + 0xc);
    local_58 = local_58 + *(float *)(iVar3 + 0x14);
    *(float *)(iVar3 + 0x10) = *(float *)(iVar3 + 0x10) - local_50;
    dVar12 = (double)(**(code **)(*DAT_803dcaa8 + 0x24))
                               ((double)local_60[0],(double)*(float *)(iVar3 + 0x10),
                                (double)local_58,(double)FLOAT_803e7fa4,iVar3);
    *(float *)(iVar10 + 0x6b4) = local_60[0];
    *(float *)(iVar10 + 0x6b8) = (float)dVar12;
    *(float *)(iVar10 + 0x6bc) = local_58;
    *(float *)(iVar10 + 0x6c4) = (float)((double)*(float *)(iVar3 + 0x10) - dVar12);
    *(char *)(iVar10 + 0x6cc) = (char)iVar6;
    *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xfff7;
    *(undefined2 *)(iVar3 + 0xa2) = 0xffff;
    puVar5[0xa8] = (uint)FLOAT_803e7fe8;
  }
  dVar13 = (double)(FLOAT_803e7ee0 - *(float *)(iVar3 + 0x98));
  *(float *)(iVar3 + 0x10) =
       (float)((double)*(float *)(iVar10 + 0x6c4) * dVar13 + (double)*(float *)(iVar10 + 0x6b8));
  puVar4 = (undefined2 *)FUN_800395d8(iVar3,5);
  dVar12 = DOUBLE_803e7ec0;
  if (puVar4 != (undefined2 *)0x0) {
    uStack68 = (int)(short)puVar9[1] ^ 0x80000000;
    local_48 = 0x43300000;
    iVar6 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e7ec0) * dVar13)
    ;
    local_40 = (longlong)iVar6;
    *puVar4 = (short)iVar6;
    uStack52 = (int)(short)puVar9[2] ^ 0x80000000;
    local_38 = 0x43300000;
    iVar6 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack52) - dVar12) * dVar13);
    local_30 = (longlong)iVar6;
    puVar4[2] = (short)iVar6;
  }
  (**(code **)(**(int **)(puVar9 + 0x34) + 0x34))(puVar9,&local_6c,&local_68,&local_64);
  fVar1 = *(float *)(iVar3 + 0x98);
  (**(code **)(*DAT_803dca50 + 0x2c))
            ((double)(fVar1 * (*(float *)(iVar10 + 0x6b4) - local_6c) + local_6c),
             (double)(fVar1 * (*(float *)(iVar10 + 0x6b8) - local_68) + local_68),
             (double)(fVar1 * (*(float *)(iVar10 + 0x6bc) - local_64) + local_64));
  if ((*(char *)((int)puVar5 + 0x27a) == '\0') && (*(char *)((int)puVar5 + 0x346) != '\0')) {
    if (puVar4 != (undefined2 *)0x0) {
      *puVar4 = 0;
      puVar4[2] = 0;
    }
    *(uint *)(*(int *)(iVar3 + 100) + 0x30) = *(uint *)(*(int *)(iVar3 + 100) + 0x30) & 0xffffefff;
    *(undefined4 *)(iVar3 + 0x18) = *(undefined4 *)(iVar10 + 0x768);
    *(undefined4 *)(iVar3 + 0x20) = *(undefined4 *)(iVar10 + 0x770);
    if (*(int *)(iVar3 + 0x30) != 0) {
      *(float *)(iVar3 + 0x18) = *(float *)(iVar3 + 0x18) + FLOAT_803dcdd8;
      *(float *)(iVar3 + 0x20) = *(float *)(iVar3 + 0x20) + FLOAT_803dcddc;
    }
    FUN_8000e034((double)*(float *)(iVar3 + 0x18),(double)FLOAT_803e7ea4,
                 (double)*(float *)(iVar3 + 0x20),iVar3 + 0xc,auStack120,iVar3 + 0x14,
                 *(undefined4 *)(iVar3 + 0x30));
    if (*(char *)(iVar10 + 0x6cc) == '\x01') {
      *(short *)(iVar10 + 0x478) = *(short *)(iVar10 + 0x478) + 0x4000;
      *(undefined2 *)(iVar10 + 0x484) = *(undefined2 *)(iVar10 + 0x478);
    }
    else {
      *(short *)(iVar10 + 0x478) = *(short *)(iVar10 + 0x478) + -0x4000;
      *(undefined2 *)(iVar10 + 0x484) = *(undefined2 *)(iVar10 + 0x478);
    }
    FUN_80030334((double)FLOAT_803e7ea4,iVar3,0,1);
    FUN_8002f52c(iVar3,0,0,0);
    (**(code **)(**(int **)(puVar9 + 0x34) + 0x3c))(puVar9,0);
    FUN_802ab5a4(iVar3,iVar10,7);
    FUN_80035f20(iVar3);
    *(undefined4 *)(iVar10 + 0x7f0) = 0;
    puVar5[0xc2] = (uint)FUN_802a514c;
    uVar8 = 2;
  }
  else {
    uVar8 = 0;
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  FUN_80286124(uVar8);
  return;
}

