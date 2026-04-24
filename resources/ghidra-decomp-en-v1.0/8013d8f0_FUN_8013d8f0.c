// Function: FUN_8013d8f0
// Entry: 8013d8f0
// Size: 588 bytes

/* WARNING: Removing unreachable block (ram,0x8013db14) */
/* WARNING: Removing unreachable block (ram,0x8013db1c) */

void FUN_8013d8f0(void)

{
  bool bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  undefined8 uVar12;
  int local_48 [12];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar12 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar6 = (int)uVar12;
  iVar7 = 0;
  dVar10 = (double)FLOAT_803e2418;
  iVar4 = FUN_8013db3c();
  if (iVar4 == 0) {
    *(undefined *)(iVar6 + 8) = 1;
    *(undefined *)(iVar6 + 10) = 0;
    fVar2 = FLOAT_803e23dc;
    *(float *)(iVar6 + 0x71c) = FLOAT_803e23dc;
    *(float *)(iVar6 + 0x720) = fVar2;
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xffffffef;
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffeffff;
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffdffff;
    *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffbffff;
    *(undefined *)(iVar6 + 0xd) = 0xff;
  }
  else {
    piVar5 = (int *)FUN_80036f50(0x4b,local_48);
    dVar11 = (double)FLOAT_803e24c4;
    for (iVar4 = 0; iVar4 < local_48[0]; iVar4 = iVar4 + 1) {
      dVar9 = (double)FUN_8002166c(*(int *)(iVar6 + 4) + 0x18,*piVar5 + 0x18);
      if ((dVar11 < dVar9) &&
         (dVar9 = (double)FUN_8002166c(iVar3 + 0x18,*piVar5 + 0x18), dVar9 < dVar10)) {
        iVar7 = *piVar5;
        dVar10 = dVar9;
      }
      piVar5 = piVar5 + 1;
    }
    if (iVar7 != 0) {
      *(int *)(iVar6 + 0x24) = iVar7;
      if (*(int *)(iVar6 + 0x28) != iVar7 + 0x18) {
        *(int *)(iVar6 + 0x28) = iVar7 + 0x18;
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xfffffbff;
        *(undefined2 *)(iVar6 + 0xd2) = 0;
      }
      iVar4 = FUN_8013b368((double)FLOAT_803e247c,iVar3,iVar6);
      if (iVar4 == 1) goto LAB_8013db14;
    }
    if (FLOAT_803e23dc == *(float *)(iVar6 + 0x2ac)) {
      bVar1 = false;
    }
    else if (FLOAT_803e2410 == *(float *)(iVar6 + 0x2b0)) {
      bVar1 = true;
    }
    else if (*(float *)(iVar6 + 0x2b4) - *(float *)(iVar6 + 0x2b0) <= FLOAT_803e2414) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      FUN_8013a3f0((double)FLOAT_803e243c,iVar3,8,0);
      *(float *)(iVar6 + 0x79c) = FLOAT_803e2440;
      *(float *)(iVar6 + 0x838) = FLOAT_803e23dc;
      FUN_80148bc8(s_in_water_8031d46c);
    }
    else {
      FUN_8013a3f0((double)FLOAT_803e2444,iVar3,0,0);
      FUN_80148bc8(s_out_of_water_8031d478);
    }
  }
LAB_8013db14:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  FUN_80286128();
  return;
}

