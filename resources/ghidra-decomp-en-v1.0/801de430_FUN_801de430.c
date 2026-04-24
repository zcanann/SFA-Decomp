// Function: FUN_801de430
// Entry: 801de430
// Size: 2596 bytes

/* WARNING: Removing unreachable block (ram,0x801dee2c) */
/* WARNING: Removing unreachable block (ram,0x801dee1c) */
/* WARNING: Removing unreachable block (ram,0x801dee0c) */
/* WARNING: Removing unreachable block (ram,0x801dedfc) */
/* WARNING: Removing unreachable block (ram,0x801dedec) */
/* WARNING: Removing unreachable block (ram,0x801deddc) */
/* WARNING: Removing unreachable block (ram,0x801dedd4) */
/* WARNING: Removing unreachable block (ram,0x801dede4) */
/* WARNING: Removing unreachable block (ram,0x801dedf4) */
/* WARNING: Removing unreachable block (ram,0x801dee04) */
/* WARNING: Removing unreachable block (ram,0x801dee14) */
/* WARNING: Removing unreachable block (ram,0x801dee24) */
/* WARNING: Removing unreachable block (ram,0x801dee34) */

void FUN_801de430(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  uint uVar8;
  int *piVar9;
  int *piVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double in_f19;
  undefined8 in_f20;
  undefined8 in_f21;
  undefined8 in_f22;
  double dVar15;
  undefined8 in_f23;
  double dVar16;
  undefined8 in_f24;
  double dVar17;
  undefined8 in_f25;
  double dVar18;
  undefined8 in_f26;
  double dVar19;
  undefined8 in_f27;
  double dVar20;
  undefined8 in_f28;
  double dVar21;
  undefined8 in_f29;
  double dVar22;
  undefined8 in_f30;
  double dVar23;
  undefined8 in_f31;
  double dVar24;
  int local_128;
  int local_124;
  int local_120;
  int local_11c;
  int local_118;
  int local_114;
  int local_110;
  int local_10c;
  int local_108;
  int local_104;
  undefined4 local_100;
  undefined local_fc;
  undefined4 local_f8;
  uint uStack244;
  double local_f0;
  undefined auStack200 [16];
  undefined auStack184 [16];
  undefined auStack168 [16];
  undefined auStack152 [16];
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  __psq_st0(auStack152,(int)((ulonglong)in_f22 >> 0x20),0);
  __psq_st1(auStack152,(int)in_f22,0);
  __psq_st0(auStack168,(int)((ulonglong)in_f21 >> 0x20),0);
  __psq_st1(auStack168,(int)in_f21,0);
  __psq_st0(auStack184,(int)((ulonglong)in_f20 >> 0x20),0);
  __psq_st1(auStack184,(int)in_f20,0);
  __psq_st0(auStack200,(int)((ulonglong)in_f19 >> 0x20),0);
  __psq_st1(auStack200,SUB84(in_f19,0),0);
  iVar3 = FUN_802860dc();
  piVar10 = *(int **)(iVar3 + 0xb8);
  iVar4 = FUN_8002b9ec();
  *(byte *)(piVar10 + 0xc) = *(byte *)(piVar10 + 0xc) | 4;
  FUN_8011f3ec(0xf);
  DAT_803ddc10 = 0;
  *piVar10 = 0;
  iVar5 = FUN_8002e0fc(&local_104,&local_108);
  while (local_104 < local_108) {
    *piVar10 = *(int *)(iVar5 + local_104 * 4);
    local_104 = local_104 + 1;
    if (*(short *)(*piVar10 + 0x46) == 0x3ff) {
      local_104 = local_108;
    }
  }
  for (iVar5 = 0; fVar2 = FLOAT_803e5668, iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b);
      iVar5 = iVar5 + 1) {
    bVar1 = *(byte *)(param_3 + iVar5 + 0x81);
    if (bVar1 == 3) {
      iVar7 = FUN_8002e0fc(&local_110,&local_10c);
      piVar9 = (int *)(iVar7 + local_110 * 4);
      for (; local_110 < local_10c; local_110 = local_110 + 1) {
        if ((*piVar9 != iVar3) && (*(short *)(*piVar9 + 0x46) == 0x282)) {
          iVar7 = *(int *)(iVar7 + local_110 * 4);
          (**(code **)(**(int **)(iVar7 + 0x68) + 0x20))(iVar7,2);
          break;
        }
        piVar9 = piVar9 + 1;
      }
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        *(byte *)(piVar10 + 0xc) = *(byte *)(piVar10 + 0xc) | 1;
      }
      else if (bVar1 != 0) {
        *(byte *)(piVar10 + 0xc) = *(byte *)(piVar10 + 0xc) | 2;
        *(undefined2 *)((int)piVar10 + 0x2e) = 0;
        (**(code **)(*DAT_803dca54 + 0x50))(0x48,3,0,0);
      }
    }
    else if (bVar1 == 5) {
      if (*piVar10 != 0) {
        *(float *)(iVar4 + 0x98) = FLOAT_803e5668;
        *(float *)(*piVar10 + 0x98) = fVar2;
        FUN_80030334((double)*(float *)(iVar4 + 0x98),iVar4,0x401,0);
        FUN_80030334((double)*(float *)(*piVar10 + 0x98),*piVar10,0,0);
        piVar10[10] = piVar10[8];
      }
    }
    else if (bVar1 < 5) {
      iVar7 = FUN_8002e0fc(&local_118,&local_114);
      piVar9 = (int *)(iVar7 + local_118 * 4);
      for (; local_118 < local_114; local_118 = local_118 + 1) {
        if ((*piVar9 != iVar3) && (*(short *)(*piVar9 + 0x46) == 0x282)) {
          iVar7 = *(int *)(iVar7 + local_118 * 4);
          (**(code **)(**(int **)(iVar7 + 0x68) + 0x20))(iVar7,3);
          break;
        }
        piVar9 = piVar9 + 1;
      }
    }
  }
  if ((*(byte *)(piVar10 + 0xc) & 3) == 0) {
    uVar6 = 0;
  }
  else if (piVar10[9] < 0x19) {
    uVar6 = 0;
  }
  else {
    iVar5 = (**(code **)(*DAT_803dca50 + 0x10))();
    if (iVar5 != 0x48) {
      local_100 = 3;
      local_fc = 1;
      (**(code **)(*DAT_803dca50 + 0x1c))(0x48,1,3,8,&local_100,0,0xff);
    }
    if (*(short *)(iVar4 + 0xa0) != 0x401) {
      FUN_80030334((double)*(float *)(iVar4 + 0x98),iVar4,0x401,0);
    }
    iVar5 = *piVar10;
    if (*(short *)(iVar5 + 0xa0) != 0) {
      FUN_80030334((double)*(float *)(iVar5 + 0x98),iVar5,0,0);
    }
    *(undefined2 *)(param_3 + 0x6e) = 0xffff;
    *(undefined *)(param_3 + 0x56) = 0;
    FUN_8000da58(iVar3,0x3af);
    dVar15 = (double)FLOAT_803e566c;
    dVar16 = (double)FLOAT_803e5674;
    dVar17 = (double)FLOAT_803e5670;
    dVar18 = (double)FLOAT_803e5678;
    dVar19 = (double)FLOAT_803e5684;
    dVar20 = (double)FLOAT_803e5680;
    dVar21 = (double)FLOAT_803e567c;
    dVar22 = (double)FLOAT_803e568c;
    dVar23 = (double)FLOAT_803e5690;
    dVar24 = (double)FLOAT_803e569c;
    dVar14 = DOUBLE_803e56a8;
    for (iVar5 = 0; iVar5 < (int)(uint)DAT_803db410; iVar5 = iVar5 + 1) {
      if (*piVar10 == 0) {
        uVar6 = 0;
        goto LAB_801dedd4;
      }
      uStack244 = piVar10[8] + 0xb24U ^ 0x80000000;
      local_f8 = 0x43300000;
      dVar12 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack244) - dVar14) /
                              dVar15);
      dVar13 = (double)(float)(dVar16 * dVar12 + dVar17);
      if (dVar13 < dVar18) {
        dVar13 = -dVar13;
      }
      dVar12 = (double)(float)((double)(float)(dVar19 * dVar12 + dVar20) * dVar13 + dVar21);
      uVar8 = FUN_80014e14(0);
      if (((uVar8 & 0x100) != 0) && (iVar7 = FUN_80014670(), iVar7 == 0)) {
        piVar10[2] = (int)((float)piVar10[2] - FLOAT_803e5688);
      }
      if ((double)(float)piVar10[2] < dVar22) {
        piVar10[2] = (int)(float)dVar22;
      }
      uVar8 = piVar10[8];
      if ((-0x46dd < (int)uVar8) && ((int)uVar8 < -0xb23)) {
        piVar10[8] = (int)((float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803e56a8
                                  ) + (float)piVar10[2]);
      }
      local_f0 = (double)CONCAT44(0x43300000,piVar10[10] ^ 0x80000000);
      uVar8 = piVar10[8];
      uStack244 = uVar8 ^ 0x80000000;
      local_f8 = 0x43300000;
      in_f19 = (double)(float)((double)((float)(local_f0 - dVar14) -
                                       (float)((double)CONCAT44(0x43300000,uStack244) - dVar14)) /
                              dVar23);
      if ((int)uVar8 < -0x46dc) {
        *(undefined2 *)((int)piVar10 + 0x2e) = 0;
        *(byte *)(piVar10 + 0xc) = *(byte *)(piVar10 + 0xc) & 0xfc;
        *(byte *)(piVar10 + 0xc) = *(byte *)(piVar10 + 0xc) | 8;
        iVar4 = FUN_8002e0fc(&local_120,&local_11c);
        piVar9 = (int *)(iVar4 + local_120 * 4);
        goto LAB_801de9dc;
      }
      if (-0xb24 < (int)uVar8) {
        *(undefined2 *)((int)piVar10 + 0x2e) = 3;
        *(byte *)(piVar10 + 0xc) = *(byte *)(piVar10 + 0xc) & 0xfc;
        *(byte *)(piVar10 + 0xc) = *(byte *)(piVar10 + 0xc) | 0x10;
        iVar4 = FUN_8002e0fc(&local_128,&local_124);
        piVar9 = (int *)(iVar4 + local_128 * 4);
        goto LAB_801deae8;
      }
      if (0 < piVar10[9]) {
        (**(code **)(*DAT_803dca54 + 0x74))();
      }
      if ((double)(float)piVar10[2] < dVar23) {
        piVar10[2] = (int)(float)((double)FLOAT_803e5698 * dVar12 + (double)(float)piVar10[2]);
      }
      local_f0 = (double)CONCAT44(0x43300000,piVar10[10] ^ 0x80000000);
      uStack244 = piVar10[8] ^ 0x80000000;
      local_f8 = 0x43300000;
      iVar7 = FUN_8002fa48((double)(float)((double)((float)(local_f0 - dVar14) -
                                                   (float)((double)CONCAT44(0x43300000,uStack244) -
                                                          dVar14)) / dVar24),(double)FLOAT_803db414,
                           iVar4,0);
      if ((iVar7 != 0) && (*(float *)(iVar4 + 0x98) < FLOAT_803e5678)) {
        *(float *)(iVar4 + 0x98) = FLOAT_803e567c + *(float *)(iVar4 + 0x98);
      }
      local_f0 = (double)CONCAT44(0x43300000,piVar10[8] ^ 0x80000000);
      uStack244 = piVar10[10] ^ 0x80000000;
      local_f8 = 0x43300000;
      iVar7 = FUN_8002fa48((double)(float)((double)((float)(local_f0 - dVar14) -
                                                   (float)((double)CONCAT44(0x43300000,uStack244) -
                                                          dVar14)) / dVar24),(double)FLOAT_803db414,
                           *piVar10,0);
      if (iVar7 != 0) {
        fVar2 = *(float *)(*piVar10 + 0x98);
        if (fVar2 < FLOAT_803e5678) {
          *(float *)(*piVar10 + 0x98) = FLOAT_803e567c + fVar2;
        }
      }
      piVar10[10] = piVar10[8];
    }
    piVar10[6] = (int)((float)piVar10[6] - FLOAT_803db414);
    if ((double)(float)piVar10[6] < (double)FLOAT_803e5678) {
      if ((double)FLOAT_803e5678 <= in_f19) {
        uVar8 = FUN_800221a0(0x78,0xf0);
        local_f0 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
        piVar10[6] = (int)(float)(local_f0 - DOUBLE_803e56a8);
      }
      else {
        uVar8 = FUN_800221a0(0x28,100);
        local_f0 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
        piVar10[6] = (int)(float)(local_f0 - DOUBLE_803e56a8);
      }
      FUN_8000bb18(iVar4,0x13a);
    }
    piVar10[7] = (int)((float)piVar10[7] - FLOAT_803db414);
    if ((double)(float)piVar10[7] < (double)FLOAT_803e5678) {
      if (in_f19 <= (double)FLOAT_803e5678) {
        uVar8 = FUN_800221a0(0x78,0xf0);
        local_f0 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
        piVar10[7] = (int)(float)(local_f0 - DOUBLE_803e56a8);
      }
      else {
        uVar8 = FUN_800221a0(0x28,100);
        local_f0 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
        piVar10[7] = (int)(float)(local_f0 - DOUBLE_803e56a8);
      }
      FUN_8000bb18(iVar3,0x4a3);
    }
    if (in_f19 < (double)FLOAT_803e5678) {
      in_f19 = -in_f19;
    }
    uVar8 = (uint)((double)FLOAT_803e56a0 * in_f19);
    local_f0 = (double)(longlong)(int)uVar8;
    if (100 < (int)uVar8) {
      uVar8 = 100;
    }
    FUN_8000b99c((double)FLOAT_803e56a4,iVar3,0x3af,uVar8 & 0xff);
    uVar6 = 0;
  }
LAB_801dedd4:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  __psq_l0(auStack56,uVar11);
  __psq_l1(auStack56,uVar11);
  __psq_l0(auStack72,uVar11);
  __psq_l1(auStack72,uVar11);
  __psq_l0(auStack88,uVar11);
  __psq_l1(auStack88,uVar11);
  __psq_l0(auStack104,uVar11);
  __psq_l1(auStack104,uVar11);
  __psq_l0(auStack120,uVar11);
  __psq_l1(auStack120,uVar11);
  __psq_l0(auStack136,uVar11);
  __psq_l1(auStack136,uVar11);
  __psq_l0(auStack152,uVar11);
  __psq_l1(auStack152,uVar11);
  __psq_l0(auStack168,uVar11);
  __psq_l1(auStack168,uVar11);
  __psq_l0(auStack184,uVar11);
  __psq_l1(auStack184,uVar11);
  __psq_l0(auStack200,uVar11);
  __psq_l1(auStack200,uVar11);
  FUN_80286128(uVar6);
  return;
LAB_801de9dc:
  if (local_11c <= local_120) goto LAB_801de9e8;
  if ((*piVar9 != iVar3) && (*(short *)(*piVar9 + 0x46) == 0x282)) {
    iVar3 = *(int *)(iVar4 + local_120 * 4);
    (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,4);
    goto LAB_801de9e8;
  }
  piVar9 = piVar9 + 1;
  local_120 = local_120 + 1;
  goto LAB_801de9dc;
LAB_801de9e8:
  dVar14 = (double)FUN_8001461c();
  local_f0 = (double)(longlong)(int)(dVar14 / (double)FLOAT_803e5694);
  FUN_801de320(&DAT_803dc070,(int)(dVar14 / (double)FLOAT_803e5694));
  FUN_8011f38c(0);
  if (0 < piVar10[9]) {
    FUN_800882c8();
  }
  (**(code **)(*DAT_803dca4c + 0xc))(0x14,1);
  DAT_803ddc10 = 2;
  uVar6 = 4;
  goto LAB_801dedd4;
LAB_801deae8:
  if (local_124 <= local_128) goto LAB_801deaf4;
  if ((*piVar9 != iVar3) && (*(short *)(*piVar9 + 0x46) == 0x282)) {
    iVar3 = *(int *)(iVar4 + local_128 * 4);
    (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,4);
    goto LAB_801deaf4;
  }
  piVar9 = piVar9 + 1;
  local_128 = local_128 + 1;
  goto LAB_801deae8;
LAB_801deaf4:
  FUN_8011f38c(0);
  if (0 < piVar10[9]) {
    FUN_800882c8();
  }
  (**(code **)(*DAT_803dca4c + 0xc))(0x14,1);
  DAT_803ddc10 = 2;
  uVar6 = 4;
  goto LAB_801dedd4;
}

