// Function: FUN_801d52c0
// Entry: 801d52c0
// Size: 432 bytes

void FUN_801d52c0(void)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  int iVar7;
  char cVar8;
  double dVar9;
  int local_28 [10];
  
  iVar1 = FUN_80286834();
  cVar8 = -1;
  cVar6 = '\0';
  iVar2 = *(int *)(*(int *)(iVar1 + 0x4c) + 0x14);
  if (iVar2 == DAT_80327ad8) {
    cVar8 = '\0';
  }
  else if (iVar2 == DAT_80327ae8) {
    cVar8 = '\x01';
  }
  else if (iVar2 == DAT_80327af8) {
    cVar8 = '\x02';
  }
  else if (iVar2 == DAT_80327b08) {
    cVar8 = '\x03';
  }
  else if (iVar2 == DAT_80327b18) {
    cVar8 = '\x04';
  }
  else if (iVar2 == DAT_80327b28) {
    cVar8 = '\x05';
  }
  piVar3 = FUN_80037048(3,local_28);
  iVar2 = (int)cVar8;
  for (iVar7 = 0; iVar7 < local_28[0]; iVar7 = iVar7 + 1) {
    iVar4 = *piVar3;
    if ((*(short *)(iVar4 + 0x46) == 0x4d7) &&
       (((iVar5 = *(int *)(*(int *)(iVar4 + 0x4c) + 0x14), iVar5 == (&DAT_80327adc)[iVar2 * 4] ||
         (iVar5 == (&DAT_80327ae0)[iVar2 * 4])) || (iVar5 == (&DAT_80327ae4)[iVar2 * 4])))) {
      FUN_8014cae4(iVar4,iVar1);
      dVar9 = FUN_80021794((float *)(*piVar3 + 0x18),(float *)(iVar1 + 0x18));
      if (dVar9 < (double)FLOAT_803e60ac) {
        FUN_80020078((int)*(short *)(*(int *)(*piVar3 + 0x4c) + 0x18));
      }
      cVar6 = cVar6 + '\x01';
      if (cVar6 == '\x03') break;
    }
    piVar3 = piVar3 + 1;
  }
  FUN_80286880();
  return;
}

