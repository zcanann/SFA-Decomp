// Function: FUN_8015cbd0
// Entry: 8015cbd0
// Size: 664 bytes

/* WARNING: Removing unreachable block (ram,0x8015ce48) */

void FUN_8015cbd0(void)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined *puVar6;
  int iVar7;
  undefined4 uVar8;
  undefined8 in_f31;
  double dVar9;
  undefined8 uVar10;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar10 = FUN_802860d8();
  fVar1 = FLOAT_803e2d48;
  iVar2 = (int)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  iVar7 = *(int *)(iVar5 + 0x40c);
  if (*(short *)(iVar2 + 0x46) == 99) {
    *(float *)(iVar7 + 0x28) = FLOAT_803e2d84;
    fVar1 = FLOAT_803e2d88;
  }
  else {
    *(float *)(iVar7 + 0x28) = FLOAT_803e2d48;
  }
  dVar9 = (double)fVar1;
  uVar3 = 0;
  if ((*(char *)(iVar5 + 0x25f) != '\0') &&
     (uVar3 = (uint)(byte)(&DAT_8031fe48)[*(char *)(iVar5 + 0xbc)], 0x1e < uVar3)) {
    uVar3 = 0;
  }
  puVar6 = &DAT_8031fe38 + uVar3 * 3;
  if ((*(byte *)(iVar7 + 0x44) & 1) != 0) {
    FUN_8015cb0c(iVar2,iVar7);
    *(byte *)(iVar7 + 0x44) = *(byte *)(iVar7 + 0x44) & 0xfe;
  }
  if (((*(byte *)(iVar7 + 0x44) & 4) != 0) && ((*(byte *)(iVar5 + 0x404) & 0x40) == 0)) {
    iVar4 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(iVar2,0x56,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar4 = iVar4 + 1;
    } while (iVar4 < 4);
  }
  if (((*(byte *)(iVar7 + 0x44) & 8) != 0) && ((*(byte *)(iVar5 + 0x404) & 0x40) == 0)) {
    (**(code **)(*DAT_803dca88 + 8))(iVar2,0x57,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
  }
  if ((*(byte *)(iVar7 + 0x44) & 0x10) != 0) {
    FUN_8000fad8();
    FUN_8000e67c((double)(float)((double)FLOAT_803e2d88 * dVar9));
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(iVar2,0x57,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x28);
  }
  if ((*(byte *)(iVar7 + 0x44) & 0x20) != 0) {
    FUN_8000fad8();
    FUN_8000e67c((double)(float)((double)FLOAT_803e2d8c * dVar9));
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(iVar2,0x57,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x28);
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(iVar2,0x58,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 10);
  }
  *(undefined *)(iVar7 + 0x44) = 0;
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286124();
  return;
}

