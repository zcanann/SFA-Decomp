// Function: FUN_8005649c
// Entry: 8005649c
// Size: 488 bytes

void FUN_8005649c(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  int local_1c [7];
  
  FUN_802860dc();
  piVar2 = (int *)FUN_80036f50(6,local_1c);
  iVar3 = FUN_8000faac();
  FUN_8000dde8();
  DAT_80386664 = 0;
  DAT_80386674 = 0;
  DAT_80386684 = 0;
  DAT_80386694 = 0;
  DAT_803866a4 = 0;
  DAT_803866b4 = 0;
  DAT_803866c4 = 0;
  DAT_803866d4 = 0;
  DAT_803866e4 = 0;
  DAT_803866f4 = 0;
  DAT_80386704 = 0;
  DAT_80386714 = 0;
  DAT_80386724 = 0;
  DAT_80386734 = 0;
  DAT_80386744 = 0;
  DAT_80386754 = 0;
  DAT_80386764 = 0;
  DAT_80386774 = 0;
  DAT_80386784 = 0;
  DAT_80386794 = 0;
  DAT_803867a4 = 0;
  DAT_803867b4 = 0;
  DAT_803867c4 = 0;
  DAT_803867d4 = 0;
  DAT_803867e4 = 0;
  DAT_803867f4 = 0;
  DAT_80386804 = 0;
  DAT_80386814 = 0;
  DAT_80386824 = 0;
  iVar4 = -0x7fc797d8;
  iVar1 = 1;
  do {
    *(undefined4 *)(iVar4 + 0xc) = 0;
    iVar4 = iVar4 + 0x10;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  DAT_80386648 = *(undefined4 *)(iVar3 + 0x44);
  DAT_8038664c = *(undefined4 *)(iVar3 + 0x48);
  DAT_80386650 = *(undefined4 *)(iVar3 + 0x4c);
  DAT_80386654 = 1;
  for (iVar1 = 0; iVar1 < local_1c[0]; iVar1 = iVar1 + 1) {
    iVar4 = *(char *)(*piVar2 + 0x35) + 1;
    if (*(int *)(iVar3 + 0x40) == *piVar2) {
      (&DAT_80386648)[iVar4 * 4] = *(undefined4 *)(iVar3 + 0xc);
      (&DAT_8038664c)[iVar4 * 4] = *(undefined4 *)(iVar3 + 0x10);
      (&DAT_80386650)[iVar4 * 4] = *(undefined4 *)(iVar3 + 0x14);
    }
    else {
      FUN_8000e034((double)*(float *)(iVar3 + 0x44),(double)*(float *)(iVar3 + 0x48),
                   (double)*(float *)(iVar3 + 0x4c),&local_20,&local_24,&local_28);
      (&DAT_80386648)[iVar4 * 4] = local_20;
      (&DAT_8038664c)[iVar4 * 4] = local_24;
      (&DAT_80386650)[iVar4 * 4] = local_28;
    }
    (&DAT_80386654)[iVar4 * 4] = 1;
    piVar2 = piVar2 + 1;
  }
  FUN_80286128();
  return;
}

