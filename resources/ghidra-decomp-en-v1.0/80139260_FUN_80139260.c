// Function: FUN_80139260
// Entry: 80139260
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x80139374) */
/* WARNING: Removing unreachable block (ram,0x8013937c) */

void FUN_80139260(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar9;
  double dVar10;
  undefined8 uVar11;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar11 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar11 >> 0x20);
  dVar9 = (double)FLOAT_803e2418;
  iVar5 = 0;
  iVar4 = 0;
  iVar2 = iVar1;
  dVar10 = dVar9;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(iVar1 + 0x798); iVar6 = iVar6 + 1) {
    if ((int)*(char *)(iVar2 + 0x74d) == (int)uVar11) {
      dVar8 = (double)FUN_8002166c(*(int *)(iVar1 + 4) + 0x18,*(int *)(iVar2 + 0x748) + 0x18);
      if (*(char *)(iVar2 + 0x74c) == '\x01') {
        if (dVar8 < dVar10) {
          iVar5 = *(int *)(iVar2 + 0x748);
          dVar10 = dVar8;
        }
      }
      else if (dVar8 < dVar9) {
        iVar4 = *(int *)(iVar2 + 0x748);
        dVar9 = dVar8;
      }
    }
    iVar2 = iVar2 + 8;
  }
  if (iVar5 == 0) {
    if (iVar4 == 0) {
      uVar3 = 0;
      goto LAB_80139374;
    }
    *(int *)(iVar1 + 0x24) = iVar4;
  }
  else {
    *(int *)(iVar1 + 0x24) = iVar5;
  }
  iVar2 = *(int *)(iVar1 + 0x24) + 0x18;
  if (*(int *)(iVar1 + 0x28) != iVar2) {
    *(int *)(iVar1 + 0x28) = iVar2;
    *(uint *)(iVar1 + 0x54) = *(uint *)(iVar1 + 0x54) & 0xfffffbff;
    *(undefined2 *)(iVar1 + 0xd2) = 0;
  }
  *(undefined *)(iVar1 + 10) = 0;
  uVar3 = 1;
LAB_80139374:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  FUN_80286124(uVar3);
  return;
}

