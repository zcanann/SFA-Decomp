// Function: FUN_80062088
// Entry: 80062088
// Size: 1132 bytes

/* WARNING: Removing unreachable block (ram,0x800624d4) */
/* WARNING: Removing unreachable block (ram,0x800624cc) */
/* WARNING: Removing unreachable block (ram,0x800620a0) */
/* WARNING: Removing unreachable block (ram,0x80062098) */

void FUN_80062088(undefined4 param_1,undefined4 param_2,ushort *param_3,int param_4)

{
  ushort uVar1;
  ushort uVar2;
  ushort uVar3;
  float fVar4;
  float *pfVar5;
  float *pfVar6;
  ushort *puVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  undefined4 *puVar11;
  int iVar12;
  uint uVar13;
  undefined2 *puVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar17;
  uint local_108;
  uint local_104;
  uint local_100;
  uint local_fc;
  uint local_f8;
  undefined auStack_f4 [12];
  undefined auStack_e8 [12];
  float afStack_dc [16];
  float afStack_9c [17];
  longlong local_58;
  longlong local_50;
  longlong local_48;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar17 = FUN_80286838();
  pfVar5 = (float *)((ulonglong)uVar17 >> 0x20);
  iVar10 = (int)uVar17;
  FUN_80257b5c();
  FUN_802570dc(9,1);
  local_f8 = (uint)*(byte *)(*(int *)(iVar10 + 0xc) + 100);
  dVar16 = (double)*(float *)(param_3 + 4);
  uVar1 = *param_3;
  uVar2 = param_3[2];
  uVar3 = param_3[1];
  if ((*(int *)(iVar10 + 0x10) == 0) || (*(int *)(iVar10 + 0x10) != -1)) {
    *(float *)(param_3 + 4) = FLOAT_803df8f8;
  }
  else {
    *(float *)(param_3 + 4) = FLOAT_803df8e8;
  }
  *param_3 = 0;
  param_3[1] = 0;
  if ((*(uint *)(iVar10 + 0x30) & 0x2000) == 0) {
    param_3[2] = 0;
  }
  if ((*(uint *)(iVar10 + 0x30) & 0x20) != 0) {
    FUN_80003494((uint)auStack_f4,(uint)(param_3 + 6),0xc);
    FUN_80003494((uint)auStack_e8,(uint)(param_3 + 0xc),0xc);
    FUN_80003494((uint)(param_3 + 0xc),iVar10 + 0x20,0xc);
    FUN_80003494((uint)(param_3 + 6),iVar10 + 0x20,0xc);
  }
  FUN_8002b554(param_3,afStack_9c,'\0');
  pfVar6 = (float *)FUN_8000f56c();
  FUN_80247618(pfVar6,afStack_9c,afStack_dc);
  FUN_8025d80c(afStack_dc,0);
  if ((*(byte *)(*(int *)(param_3 + 0x28) + 0x5f) & 4) == 0) {
    puVar7 = (ushort *)FUN_8002bac4();
    fVar4 = FLOAT_803df8fc;
    if (param_3 != puVar7) {
      fVar4 = *(float *)(param_3 + 0x54) * *(float *)(param_3 + 4);
    }
    dVar15 = (double)fVar4;
    if (*(int *)(iVar10 + 0x10) == -1) {
      iVar8 = FUN_8006c740();
      if (*(int *)(*(int *)(iVar10 + 0xc) + 0x60) != iVar8) {
        if (*(char *)(*(int *)(iVar10 + 0xc) + 0x65) == -1) {
          local_104 = local_f8;
          FUN_80077c54(dVar15,*(float **)(iVar10 + 0xc),(int)&local_104,afStack_9c);
        }
        else {
          local_108 = local_f8;
          FUN_80078074(*(undefined4 *)(iVar10 + 0xc),&local_108,afStack_9c);
        }
        goto LAB_80062298;
      }
    }
    local_100 = local_f8;
    FUN_80077a08(*(float **)(iVar10 + 0xc),&local_100,afStack_9c);
  }
  else {
    local_fc = local_f8;
    FUN_80077780(*(float **)(iVar10 + 0xc),&local_fc,afStack_9c);
  }
LAB_80062298:
  FUN_80259288(1);
  FUN_8025d888(0);
  *(float *)(param_3 + 4) = (float)dVar16;
  *param_3 = uVar1;
  param_3[1] = uVar3;
  param_3[2] = uVar2;
  if (*(int *)(iVar10 + 0x10) == 0) {
    iVar8 = FUN_80023d8c(param_4 * 0x12 + 8,0x18);
    *(int *)(iVar10 + 0x10) = iVar8;
    piVar9 = *(int **)(iVar10 + 0x10);
    if (piVar9 == (int *)0x0) goto LAB_800624cc;
    *piVar9 = (int)(piVar9 + 2);
    *(int *)(*(int *)(iVar10 + 0x10) + 4) = param_4 * 3;
    fVar4 = FLOAT_803df900;
    iVar8 = 0;
    pfVar6 = pfVar5;
    for (uVar13 = 0; uVar13 < (uint)(*(int **)(iVar10 + 0x10))[1]; uVar13 = uVar13 + 1) {
      local_58 = (longlong)(int)(fVar4 * *pfVar6);
      *(short *)(**(int **)(iVar10 + 0x10) + iVar8) = (short)(int)(fVar4 * *pfVar6);
      local_50 = (longlong)(int)(fVar4 * pfVar6[1]);
      *(short *)(**(int **)(iVar10 + 0x10) + iVar8 + 2) = (short)(int)(fVar4 * pfVar6[1]);
      local_48 = (longlong)(int)(fVar4 * pfVar6[2]);
      *(short *)(**(int **)(iVar10 + 0x10) + iVar8 + 4) = (short)(int)(fVar4 * pfVar6[2]);
      pfVar6 = pfVar6 + 3;
      iVar8 = iVar8 + 6;
    }
  }
  if (*(int *)(iVar10 + 0x10) == -1) {
    FUN_80259000(0x90,2,param_4 * 3 & 0xffff);
    iVar12 = 0;
    iVar8 = 0;
    if (0 < param_4) {
      do {
        puVar11 = (undefined4 *)((int)pfVar5 + iVar8);
        DAT_cc008000 = *puVar11;
        DAT_cc008000 = puVar11[1];
        DAT_cc008000 = puVar11[2];
        pfVar6 = pfVar5 + (iVar12 + 1) * 3;
        DAT_cc008000 = *pfVar6;
        DAT_cc008000 = pfVar6[1];
        DAT_cc008000 = pfVar6[2];
        pfVar6 = pfVar5 + (iVar12 + 2) * 3;
        DAT_cc008000 = *pfVar6;
        DAT_cc008000 = pfVar6[1];
        DAT_cc008000 = pfVar6[2];
        iVar12 = iVar12 + 3;
        iVar8 = iVar8 + 0x24;
        param_4 = param_4 + -1;
      } while (param_4 != 0);
    }
  }
  else {
    FUN_80259000(0x90,0,*(uint *)(*(int *)(iVar10 + 0x10) + 4) & 0xffff);
    iVar8 = 0;
    for (uVar13 = 0; uVar13 < (uint)(*(int **)(iVar10 + 0x10))[1]; uVar13 = uVar13 + 1) {
      puVar14 = (undefined2 *)(**(int **)(iVar10 + 0x10) + iVar8);
      DAT_cc008000._0_2_ = *puVar14;
      DAT_cc008000._0_2_ = puVar14[1];
      DAT_cc008000._0_2_ = puVar14[2];
      iVar8 = iVar8 + 6;
    }
  }
  if ((*(uint *)(iVar10 + 0x30) & 0x20) != 0) {
    FUN_80003494((uint)(param_3 + 6),(uint)auStack_f4,0xc);
    FUN_80003494((uint)(param_3 + 0xc),(uint)auStack_e8,0xc);
  }
LAB_800624cc:
  FUN_80286884();
  return;
}

