// Function: FUN_80061f0c
// Entry: 80061f0c
// Size: 1132 bytes

/* WARNING: Removing unreachable block (ram,0x80062350) */
/* WARNING: Removing unreachable block (ram,0x80062358) */

void FUN_80061f0c(undefined4 param_1,undefined4 param_2,undefined2 *param_3,int param_4)

{
  undefined2 uVar1;
  undefined2 uVar2;
  undefined2 uVar3;
  float fVar4;
  float *pfVar5;
  undefined4 uVar6;
  int *piVar7;
  int iVar8;
  float *pfVar9;
  undefined4 *puVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  undefined2 *puVar14;
  undefined4 uVar15;
  double extraout_f1;
  double dVar16;
  undefined8 in_f30;
  double dVar17;
  undefined8 in_f31;
  double dVar18;
  undefined8 uVar19;
  uint local_108;
  uint local_104;
  uint local_100;
  uint local_fc;
  uint local_f8;
  undefined auStack244 [12];
  undefined auStack232 [12];
  undefined auStack220 [64];
  undefined auStack156 [68];
  longlong local_58;
  longlong local_50;
  longlong local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar19 = FUN_802860d4();
  pfVar5 = (float *)((ulonglong)uVar19 >> 0x20);
  iVar8 = (int)uVar19;
  FUN_802573f8();
  FUN_80256978(9,1);
  local_f8 = (uint)*(byte *)(*(int *)(iVar8 + 0xc) + 100);
  dVar18 = (double)*(float *)(param_3 + 4);
  uVar1 = *param_3;
  uVar2 = param_3[2];
  uVar3 = param_3[1];
  if ((*(int *)(iVar8 + 0x10) == 0) || (*(int *)(iVar8 + 0x10) != -1)) {
    *(float *)(param_3 + 4) = FLOAT_803dec78;
  }
  else {
    *(float *)(param_3 + 4) = FLOAT_803dec68;
  }
  *param_3 = 0;
  param_3[1] = 0;
  if ((*(uint *)(iVar8 + 0x30) & 0x2000) == 0) {
    param_3[2] = 0;
  }
  if ((*(uint *)(iVar8 + 0x30) & 0x20) != 0) {
    FUN_80003494(auStack244,param_3 + 6,0xc);
    FUN_80003494(auStack232,param_3 + 0xc,0xc);
    FUN_80003494(param_3 + 0xc,iVar8 + 0x20,0xc);
    FUN_80003494(param_3 + 6,iVar8 + 0x20,0xc);
  }
  FUN_8002b47c(param_3,auStack156,0);
  uVar6 = FUN_8000f54c();
  FUN_80246eb4(uVar6,auStack156,auStack220);
  FUN_8025d0a8(auStack220,0);
  if ((*(byte *)(*(int *)(param_3 + 0x28) + 0x5f) & 4) == 0) {
    puVar14 = (undefined2 *)FUN_8002b9ec();
    dVar16 = extraout_f1;
    fVar4 = FLOAT_803dec7c;
    if (param_3 != puVar14) {
      dVar16 = (double)*(float *)(param_3 + 0x54);
      fVar4 = (float)(dVar16 * (double)*(float *)(param_3 + 4));
    }
    dVar17 = (double)fVar4;
    if (*(int *)(iVar8 + 0x10) == -1) {
      iVar11 = FUN_8006c5c4(dVar16);
      if (*(int *)(*(int *)(iVar8 + 0xc) + 0x60) != iVar11) {
        if (*(char *)(*(int *)(iVar8 + 0xc) + 0x65) == -1) {
          local_104 = local_f8;
          FUN_80077ad8(dVar17,*(undefined4 *)(iVar8 + 0xc),&local_104,auStack156);
        }
        else {
          local_108 = local_f8;
          FUN_80077ef8(dVar17,*(undefined4 *)(iVar8 + 0xc),&local_108,auStack156);
        }
        goto LAB_8006211c;
      }
    }
    local_100 = local_f8;
    FUN_8007788c(*(undefined4 *)(iVar8 + 0xc),&local_100,auStack156);
  }
  else {
    local_fc = local_f8;
    FUN_80077604(*(undefined4 *)(iVar8 + 0xc),&local_fc,auStack156);
  }
LAB_8006211c:
  FUN_80258b24(1);
  FUN_8025d124(0);
  *(float *)(param_3 + 4) = (float)dVar18;
  *param_3 = uVar1;
  param_3[1] = uVar3;
  param_3[2] = uVar2;
  if (*(int *)(iVar8 + 0x10) == 0) {
    uVar6 = FUN_80023cc8(param_4 * 0x12 + 8,0x18,0);
    *(undefined4 *)(iVar8 + 0x10) = uVar6;
    piVar7 = *(int **)(iVar8 + 0x10);
    if (piVar7 == (int *)0x0) goto LAB_80062350;
    *piVar7 = (int)(piVar7 + 2);
    *(int *)(*(int *)(iVar8 + 0x10) + 4) = param_4 * 3;
    fVar4 = FLOAT_803dec80;
    iVar11 = 0;
    pfVar9 = pfVar5;
    for (uVar13 = 0; uVar13 < (uint)(*(int **)(iVar8 + 0x10))[1]; uVar13 = uVar13 + 1) {
      local_58 = (longlong)(int)(fVar4 * *pfVar9);
      *(short *)(**(int **)(iVar8 + 0x10) + iVar11) = (short)(int)(fVar4 * *pfVar9);
      local_50 = (longlong)(int)(fVar4 * pfVar9[1]);
      *(short *)(**(int **)(iVar8 + 0x10) + iVar11 + 2) = (short)(int)(fVar4 * pfVar9[1]);
      local_48 = (longlong)(int)(fVar4 * pfVar9[2]);
      *(short *)(**(int **)(iVar8 + 0x10) + iVar11 + 4) = (short)(int)(fVar4 * pfVar9[2]);
      pfVar9 = pfVar9 + 3;
      iVar11 = iVar11 + 6;
    }
  }
  if (*(int *)(iVar8 + 0x10) == -1) {
    FUN_8025889c(0x90,2,param_4 * 3 & 0xffff);
    iVar12 = 0;
    iVar11 = 0;
    if (0 < param_4) {
      do {
        puVar10 = (undefined4 *)((int)pfVar5 + iVar11);
        write_volatile_4(0xcc008000,*puVar10);
        write_volatile_4(0xcc008000,puVar10[1]);
        write_volatile_4(0xcc008000,puVar10[2]);
        pfVar9 = pfVar5 + (iVar12 + 1) * 3;
        write_volatile_4(0xcc008000,*pfVar9);
        write_volatile_4(0xcc008000,pfVar9[1]);
        write_volatile_4(0xcc008000,pfVar9[2]);
        pfVar9 = pfVar5 + (iVar12 + 2) * 3;
        write_volatile_4(0xcc008000,*pfVar9);
        write_volatile_4(0xcc008000,pfVar9[1]);
        write_volatile_4(0xcc008000,pfVar9[2]);
        iVar12 = iVar12 + 3;
        iVar11 = iVar11 + 0x24;
        param_4 = param_4 + -1;
      } while (param_4 != 0);
    }
  }
  else {
    FUN_8025889c(0x90,0,*(uint *)(*(int *)(iVar8 + 0x10) + 4) & 0xffff);
    iVar11 = 0;
    for (uVar13 = 0; uVar13 < (uint)(*(int **)(iVar8 + 0x10))[1]; uVar13 = uVar13 + 1) {
      puVar14 = (undefined2 *)(**(int **)(iVar8 + 0x10) + iVar11);
      write_volatile_2(0xcc008000,*puVar14);
      write_volatile_2(0xcc008000,puVar14[1]);
      write_volatile_2(0xcc008000,puVar14[2]);
      iVar11 = iVar11 + 6;
    }
  }
  if ((*(uint *)(iVar8 + 0x30) & 0x20) != 0) {
    FUN_80003494(param_3 + 6,auStack244,0xc);
    FUN_80003494(param_3 + 0xc,auStack232,0xc);
  }
LAB_80062350:
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  FUN_80286120();
  return;
}

