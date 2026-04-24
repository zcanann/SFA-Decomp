// Function: FUN_801a9fd0
// Entry: 801a9fd0
// Size: 308 bytes

/* WARNING: Removing unreachable block (ram,0x801aa0e4) */

void FUN_801a9fd0(void)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  byte bVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined8 uVar10;
  undefined auStack56 [48];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar10 = FUN_802860d8();
  uVar2 = (undefined4)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  cVar1 = '\0';
  iVar3 = FUN_8001ffb4(0x1c0);
  if (iVar3 != 0) {
    iVar3 = FUN_80036f50(0x3f,auStack56);
    dVar9 = (double)FLOAT_803e4618;
    for (bVar6 = 0; bVar6 < 4; bVar6 = bVar6 + 1) {
      iVar4 = FUN_80036e58(5,*(undefined4 *)(iVar3 + (uint)bVar6 * 4),0);
      dVar8 = (double)FUN_8002166c(*(int *)(iVar3 + (uint)bVar6 * 4) + 0x18,iVar4 + 0x18);
      if (dVar9 < dVar8) {
        cVar1 = cVar1 + '\x01';
      }
    }
  }
  if (cVar1 == '\0') {
    if (*(char *)(iVar5 + 1) != '\0') {
      FUN_8000db90(uVar2,0x223);
      *(undefined *)(iVar5 + 1) = 0;
    }
  }
  else {
    if (*(char *)(iVar5 + 1) == '\0') {
      FUN_8000dcbc(uVar2,0x223);
      *(undefined *)(iVar5 + 1) = 1;
    }
    FUN_8000b99c((double)FLOAT_803e461c,uVar2,0x223,cVar1 * '\x0f' + '(');
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286124(cVar1);
  return;
}

