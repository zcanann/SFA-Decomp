// Function: FUN_8029f868
// Entry: 8029f868
// Size: 1396 bytes

/* WARNING: Removing unreachable block (ram,0x8029fdbc) */
/* WARNING: Removing unreachable block (ram,0x8029f878) */

void FUN_8029f868(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined2 *puVar5;
  uint *puVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined4 in_r8;
  undefined4 in_r9;
  int in_r10;
  int *piVar10;
  undefined2 *puVar11;
  int iVar12;
  double dVar13;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps31_1;
  undefined8 uVar16;
  float fStack_78;
  ushort local_74 [4];
  float local_6c;
  float local_68;
  float local_64;
  float local_60 [2];
  float local_58;
  float fStack_54;
  float local_50;
  undefined4 local_48;
  uint uStack_44;
  longlong local_40;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar16 = FUN_8028683c();
  iVar3 = (int)((ulonglong)uVar16 >> 0x20);
  puVar6 = (uint *)uVar16;
  iVar12 = *(int *)(iVar3 + 0xb8);
  puVar11 = *(undefined2 **)(iVar12 + 0x7f0);
  if (*(char *)((int)puVar6 + 0x27a) != '\0') {
    *(undefined2 *)(puVar6 + 0x9e) = 0x19;
    *(undefined4 *)(iVar12 + 0x898) = 0;
  }
  iVar7 = *(int *)(iVar3 + 0xb8);
  *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) & 0xfffffffd;
  *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) | 0x2000;
  puVar6[1] = puVar6[1] | 0x100000;
  fVar2 = FLOAT_803e8b3c;
  puVar6[0xa0] = (uint)FLOAT_803e8b3c;
  puVar6[0xa1] = (uint)fVar2;
  *puVar6 = *puVar6 | 0x200000;
  *(float *)(iVar3 + 0x24) = fVar2;
  *(float *)(iVar3 + 0x2c) = fVar2;
  *(undefined *)((int)puVar6 + 0x25f) = 0;
  FUN_80035ff8(iVar3);
  *(float *)(iVar3 + 0x28) = FLOAT_803e8b3c;
  if (*(char *)((int)puVar6 + 0x27a) != '\0') {
    iVar7 = **(int **)(puVar11 + 0x34);
    (**(code **)(iVar7 + 0x28))(puVar11,iVar3 + 0xc,iVar3 + 0x10,iVar3 + 0x14);
    sVar1 = puVar11[0x23];
    if ((sVar1 == 0x38c) || ((sVar1 < 0x38c && (sVar1 == 0x72)))) {
      iVar9 = 0;
      iVar7 = 0;
      in_r8 = 100;
      in_r9 = 0xff;
      in_r10 = *DAT_803dd6d0;
      (**(code **)(in_r10 + 0x1c))(0x42,0,1);
    }
    else {
      iVar9 = *DAT_803dd6d0;
      (**(code **)(iVar9 + 0x24))(0,1,0);
    }
    iVar4 = (**(code **)(**(int **)(puVar11 + 0x34) + 0x30))(puVar11);
    (**(code **)(**(int **)(puVar11 + 0x34) + 0x3c))(puVar11,3);
    if (((iVar4 == 2) || (1 < iVar4)) || (iVar4 < 1)) {
      iVar8 = 9;
    }
    else {
      iVar8 = 8;
    }
    *(undefined2 *)(iVar12 + 0x478) = *puVar11;
    *(undefined2 *)(iVar12 + 0x484) = *(undefined2 *)(iVar12 + 0x478);
    *(undefined2 *)(iVar3 + 2) = 0;
    *(undefined2 *)(iVar3 + 4) = 0;
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 iVar3,(int)*(short *)(*(int *)(iVar12 + 0x6e8) + iVar8 * 2),1,iVar9,iVar7,in_r8,
                 in_r9,in_r10);
    piVar10 = *(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4);
    FUN_80027ec4((double)FLOAT_803e8b3c,(double)*(float *)(iVar3 + 8),piVar10,0,0,&fStack_54,
                 (short *)local_74);
    FUN_80027ec4((double)FLOAT_803e8b78,(double)*(float *)(iVar3 + 8),piVar10,0,0,local_60,
                 (short *)local_74);
    local_74[0] = *(ushort *)(iVar12 + 0x478);
    local_74[1] = 0;
    local_74[2] = 0;
    FUN_80021b8c(local_74,local_60);
    local_60[0] = local_60[0] + *(float *)(iVar3 + 0xc);
    local_58 = local_58 + *(float *)(iVar3 + 0x14);
    *(float *)(iVar3 + 0x10) = *(float *)(iVar3 + 0x10) - local_50;
    dVar13 = (double)(**(code **)(*DAT_803dd728 + 0x24))
                               ((double)local_60[0],(double)*(float *)(iVar3 + 0x10),
                                (double)local_58,(double)FLOAT_803e8c3c,iVar3);
    *(float *)(iVar12 + 0x6b4) = local_60[0];
    *(float *)(iVar12 + 0x6b8) = (float)dVar13;
    *(float *)(iVar12 + 0x6bc) = local_58;
    *(float *)(iVar12 + 0x6c4) = (float)((double)*(float *)(iVar3 + 0x10) - dVar13);
    *(char *)(iVar12 + 0x6cc) = (char)iVar4;
    *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xfff7;
    *(undefined2 *)(iVar3 + 0xa2) = 0xffff;
    puVar6[0xa8] = (uint)FLOAT_803e8c80;
  }
  dVar15 = (double)(FLOAT_803e8b78 - *(float *)(iVar3 + 0x98));
  *(float *)(iVar3 + 0x10) =
       (float)((double)*(float *)(iVar12 + 0x6c4) * dVar15 + (double)*(float *)(iVar12 + 0x6b8));
  puVar5 = (undefined2 *)FUN_800396d0(iVar3,5);
  dVar13 = DOUBLE_803e8b58;
  if (puVar5 != (undefined2 *)0x0) {
    uStack_44 = (int)(short)puVar11[1] ^ 0x80000000;
    local_48 = 0x43300000;
    iVar7 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e8b58) * dVar15
                 );
    local_40 = (longlong)iVar7;
    *puVar5 = (short)iVar7;
    uStack_34 = (int)(short)puVar11[2] ^ 0x80000000;
    local_38 = 0x43300000;
    iVar7 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_34) - dVar13) * dVar15);
    local_30 = (longlong)iVar7;
    puVar5[2] = (short)iVar7;
  }
  iVar7 = **(int **)(puVar11 + 0x34);
  (**(code **)(iVar7 + 0x34))(puVar11,&local_6c,&local_68,&local_64);
  dVar13 = (double)*(float *)(iVar3 + 0x98);
  (**(code **)(*DAT_803dd6d0 + 0x2c))
            ((double)(float)(dVar13 * (double)(float)((double)*(float *)(iVar12 + 0x6b4) -
                                                     (double)local_6c) + (double)local_6c),
             (double)(float)(dVar13 * (double)(float)((double)*(float *)(iVar12 + 0x6b8) -
                                                     (double)local_68) + (double)local_68),
             (double)(float)(dVar13 * (double)(float)((double)*(float *)(iVar12 + 0x6bc) -
                                                     (double)local_64) + (double)local_64));
  if ((*(char *)((int)puVar6 + 0x27a) == '\0') && (*(char *)((int)puVar6 + 0x346) != '\0')) {
    if (puVar5 != (undefined2 *)0x0) {
      *puVar5 = 0;
      puVar5[2] = 0;
    }
    *(uint *)(*(int *)(iVar3 + 100) + 0x30) = *(uint *)(*(int *)(iVar3 + 100) + 0x30) & 0xffffefff;
    *(undefined4 *)(iVar3 + 0x18) = *(undefined4 *)(iVar12 + 0x768);
    *(undefined4 *)(iVar3 + 0x20) = *(undefined4 *)(iVar12 + 0x770);
    if (*(int *)(iVar3 + 0x30) != 0) {
      *(float *)(iVar3 + 0x18) = *(float *)(iVar3 + 0x18) + FLOAT_803dda58;
      *(float *)(iVar3 + 0x20) = *(float *)(iVar3 + 0x20) + FLOAT_803dda5c;
    }
    dVar15 = (double)FLOAT_803e8b3c;
    dVar14 = (double)*(float *)(iVar3 + 0x20);
    iVar9 = *(int *)(iVar3 + 0x30);
    FUN_8000e054((double)*(float *)(iVar3 + 0x18),dVar15,dVar14,(float *)(iVar3 + 0xc),&fStack_78,
                 (float *)(iVar3 + 0x14),iVar9);
    if (*(char *)(iVar12 + 0x6cc) == '\x01') {
      *(short *)(iVar12 + 0x478) = *(short *)(iVar12 + 0x478) + 0x4000;
      *(undefined2 *)(iVar12 + 0x484) = *(undefined2 *)(iVar12 + 0x478);
    }
    else {
      *(short *)(iVar12 + 0x478) = *(short *)(iVar12 + 0x478) + -0x4000;
      *(undefined2 *)(iVar12 + 0x484) = *(undefined2 *)(iVar12 + 0x478);
    }
    FUN_8003042c((double)FLOAT_803e8b3c,dVar15,dVar14,dVar13,param_5,param_6,param_7,param_8,iVar3,0
                 ,1,iVar9,iVar7,in_r8,in_r9,in_r10);
    FUN_8002f624(iVar3,0,0,0);
    (**(code **)(**(int **)(puVar11 + 0x34) + 0x3c))(puVar11,0);
    FUN_802abd04(iVar3,iVar12,7);
    FUN_80036018(iVar3);
    *(undefined4 *)(iVar12 + 0x7f0) = 0;
    puVar6[0xc2] = (uint)FUN_802a58ac;
  }
  FUN_80286888();
  return;
}

