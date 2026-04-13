// Function: FUN_801e32d4
// Entry: 801e32d4
// Size: 1384 bytes

/* WARNING: Removing unreachable block (ram,0x801e381c) */
/* WARNING: Removing unreachable block (ram,0x801e3814) */
/* WARNING: Removing unreachable block (ram,0x801e380c) */
/* WARNING: Removing unreachable block (ram,0x801e32f4) */
/* WARNING: Removing unreachable block (ram,0x801e32ec) */
/* WARNING: Removing unreachable block (ram,0x801e32e4) */

void FUN_801e32d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined2 *puVar6;
  int iVar7;
  uint *puVar8;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar9;
  int iVar10;
  int iVar11;
  double dVar12;
  double in_f29;
  double dVar13;
  double in_f30;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  uint local_88;
  int local_84;
  int local_80;
  float local_7c;
  float local_78;
  float local_74;
  uint uStack_70;
  int local_6c;
  uint auStack_68 [2];
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar1 = FUN_8028683c();
  iVar11 = 0;
  iVar2 = FUN_8002bac4();
  iVar10 = *(int *)(uVar1 + 0x30);
  iVar3 = DAT_803de8c8;
  if (iVar10 != 0) {
    iVar3 = FUN_801e2398();
    iVar3 = FUN_801e18cc(iVar3);
    if (iVar3 == 2) {
      dVar12 = (double)FUN_800217c8((float *)(iVar2 + 0x18),(float *)(uVar1 + 0x18));
      if ((double)FLOAT_803e64d8 <= dVar12) {
        FUN_8000b7dc(uVar1,0x40);
      }
      else {
        FUN_8000bb38(uVar1,0x312);
      }
    }
    iVar3 = *(int *)(iVar10 + 0xf4);
    piVar9 = *(int **)(uVar1 + 0xb8);
    if (*piVar9 == 0) {
      iVar4 = FUN_8002e1f4(&local_80,&local_84);
      for (; local_80 < local_84; local_80 = local_80 + 1) {
        iVar7 = *(int *)(iVar4 + local_80 * 4);
        if (*(short *)(iVar7 + 0x46) == 0x8c) {
          *piVar9 = iVar7;
          local_80 = local_84;
        }
      }
    }
    puVar8 = &uStack_70;
    iVar4 = FUN_800375e4(uVar1,&local_88,auStack_68,puVar8);
    if (iVar4 != 0) {
      if (local_88 == 0x130002) {
        iVar11 = 1;
      }
      else if ((0x130001 < (int)local_88) && ((int)local_88 < 0x130004)) {
        iVar11 = 2;
      }
    }
    iVar4 = (**(code **)(**(int **)(iVar10 + 0x68) + 0x28))(iVar10);
    if (((1 < iVar4) && (*(int *)(uVar1 + 0xf8) < 1)) && ((iVar3 - 3U < 2 || (iVar3 == 5)))) {
      puVar8 = (uint *)0x0;
      iVar4 = FUN_80036974(uVar1,&local_6c,(int *)0x0,(uint *)0x0);
      if ((iVar4 != 0) && (*(short *)(local_6c + 0x46) != 0x114)) {
        puVar8 = (uint *)0x0;
        in_r7 = 0;
        in_r8 = 1;
        FUN_8002ad08(uVar1,0xf,200,0,0,1);
        FUN_8000bb38(uVar1,0x37);
        *(char *)(piVar9 + 1) = *(char *)(piVar9 + 1) + -1;
        if (*(char *)(piVar9 + 1) < '\x01') {
          (**(code **)(**(int **)(iVar10 + 0x68) + 0x20))(iVar10);
          *(undefined4 *)(uVar1 + 0xf8) = 300;
          FUN_80035ff8(uVar1);
        }
      }
    }
    if (0 < *(int *)(uVar1 + 0xf8)) {
      *(uint *)(uVar1 + 0xf8) = *(int *)(uVar1 + 0xf8) - (uint)DAT_803dc070;
    }
    if ((iVar3 == 8) &&
       (*(int *)(uVar1 + 0xf4) = *(int *)(uVar1 + 0xf4) + 1, 10 < *(int *)(uVar1 + 0xf4))) {
      *(undefined4 *)(uVar1 + 0xf4) = 0;
    }
    if ((iVar3 == 5) && (DAT_803de8c8 != 5)) {
      FUN_8003042c((double)FLOAT_803e64cc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   uVar1,1,0,puVar8,in_r7,in_r8,in_r9,in_r10);
      DAT_803dccf8 = '\0';
    }
    if ((((*(short *)(uVar1 + 0xa0) == 1) && (FLOAT_803e64dc <= *(float *)(uVar1 + 0x98))) &&
        (DAT_803dccf8 == '\0')) && (uVar5 = FUN_8002e144(), (uVar5 & 0xff) != 0)) {
      DAT_803dccf8 = '\x01';
      *(uint *)(uVar1 + 0xf4) = *(int *)(uVar1 + 0xf4) + (uint)DAT_803dc070;
      FUN_8000bb38(uVar1,0x38);
      *(float *)(uVar1 + 0x10) = *(float *)(uVar1 + 0x10) + FLOAT_803e64e0;
      *(float *)(uVar1 + 0x14) = *(float *)(uVar1 + 0x14) - FLOAT_803e64e4;
      FUN_8000e12c(uVar1,&local_74,&local_78,&local_7c);
      *(float *)(uVar1 + 0x10) = *(float *)(uVar1 + 0x10) - FLOAT_803e64e0;
      dVar12 = (double)*(float *)(uVar1 + 0x14);
      *(float *)(uVar1 + 0x14) = (float)(dVar12 + (double)FLOAT_803e64e4);
      puVar6 = FUN_8002becc(0x18,0x114);
      *(undefined *)(puVar6 + 3) = 0xff;
      *(undefined *)((int)puVar6 + 7) = 0xff;
      *(undefined *)(puVar6 + 2) = 2;
      *(undefined *)((int)puVar6 + 5) = 1;
      *(float *)(puVar6 + 4) = local_74;
      *(float *)(puVar6 + 6) = local_78;
      *(float *)(puVar6 + 8) = local_7c;
      puVar8 = (uint *)0xffffffff;
      in_r7 = 0;
      iVar10 = FUN_8002e088(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar6,5,
                            0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      dVar15 = (double)(*(float *)(iVar2 + 0x18) - *(float *)(iVar10 + 0xc));
      dVar14 = (double)((*(float *)(iVar2 + 0x1c) - FLOAT_803e64e8) - *(float *)(iVar10 + 0x10));
      dVar13 = (double)(*(float *)(iVar2 + 0x20) - *(float *)(iVar10 + 0x14));
      dVar12 = FUN_80293900((double)(float)(dVar13 * dVar13 +
                                           (double)(float)(dVar15 * dVar15 +
                                                          (double)(float)(dVar14 * dVar14))));
      dVar12 = (double)(float)((double)FLOAT_803e64e8 / dVar12);
      *(float *)(iVar10 + 0x24) = (float)(dVar15 * dVar12);
      *(float *)(iVar10 + 0x28) = (float)(dVar14 * dVar12);
      *(float *)(iVar10 + 0x2c) = (float)(dVar13 * dVar12);
      *(undefined4 *)(iVar10 + 0xf4) = 0x78;
      *(int *)(iVar10 + 0xf8) = *piVar9;
    }
    if ((iVar11 == 1) && (uVar5 = FUN_8002e144(), (uVar5 & 0xff) != 0)) {
      FUN_8000bb38(uVar1,0x38);
      iVar2 = FUN_8002bac4();
      puVar6 = FUN_8002becc(0x18,0x138);
      *(float *)(puVar6 + 4) = FLOAT_803e64ec + *(float *)(iVar2 + 0x18);
      uStack_5c = FUN_80022264(0xfffffffa,6);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      *(float *)(puVar6 + 6) =
           FLOAT_803e64e0 +
           *(float *)(iVar2 + 0x1c) +
           (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e64f8);
      uStack_54 = FUN_80022264(0xfffffffa,6);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      dVar12 = (double)(*(float *)(iVar2 + 0x20) +
                       (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e64f8));
      *(float *)(puVar6 + 8) = (float)((double)FLOAT_803e64f0 + dVar12);
      *(undefined *)(puVar6 + 2) = 2;
      *(undefined *)((int)puVar6 + 5) = 1;
      *(undefined *)(puVar6 + 3) = 0xff;
      *(undefined *)((int)puVar6 + 7) = 0xff;
      puVar8 = (uint *)0xffffffff;
      in_r7 = 0;
      FUN_8002e088(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar6,5,0xff,
                   0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    }
    dVar12 = (double)FLOAT_803dc074;
    iVar2 = FUN_8002fb40((double)FLOAT_803e64f4,dVar12);
    if ((*(short *)(uVar1 + 0xa0) == 1) && (iVar2 != 0)) {
      FUN_8003042c((double)FLOAT_803e64cc,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                   uVar1,0,0,puVar8,in_r7,in_r8,in_r9,in_r10);
    }
  }
  DAT_803de8c8 = iVar3;
  FUN_80286888();
  return;
}

