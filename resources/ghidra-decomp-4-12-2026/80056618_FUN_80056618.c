// Function: FUN_80056618
// Entry: 80056618
// Size: 488 bytes

void FUN_80056618(void)

{
  int iVar1;
  int *piVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  float local_28;
  float local_24;
  float local_20;
  int local_1c [7];
  
  FUN_80286840();
  piVar2 = FUN_80037048(6,local_1c);
  psVar3 = FUN_8000facc();
  FUN_8000de08(psVar3);
  DAT_803872c4 = 0;
  DAT_803872d4 = 0;
  DAT_803872e4 = 0;
  DAT_803872f4 = 0;
  DAT_80387304 = 0;
  DAT_80387314 = 0;
  DAT_80387324 = 0;
  DAT_80387334 = 0;
  DAT_80387344 = 0;
  DAT_80387354 = 0;
  DAT_80387364 = 0;
  DAT_80387374 = 0;
  DAT_80387384 = 0;
  DAT_80387394 = 0;
  DAT_803873a4 = 0;
  DAT_803873b4 = 0;
  DAT_803873c4 = 0;
  DAT_803873d4 = 0;
  DAT_803873e4 = 0;
  DAT_803873f4 = 0;
  DAT_80387404 = 0;
  DAT_80387414 = 0;
  DAT_80387424 = 0;
  DAT_80387434 = 0;
  DAT_80387444 = 0;
  DAT_80387454 = 0;
  DAT_80387464 = 0;
  DAT_80387474 = 0;
  DAT_80387484 = 0;
  iVar4 = -0x7fc78b78;
  iVar1 = 1;
  do {
    *(undefined4 *)(iVar4 + 0xc) = 0;
    iVar4 = iVar4 + 0x10;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  DAT_803872a8 = *(undefined4 *)(psVar3 + 0x22);
  DAT_803872ac = *(undefined4 *)(psVar3 + 0x24);
  DAT_803872b0 = *(undefined4 *)(psVar3 + 0x26);
  DAT_803872b4 = 1;
  for (iVar1 = 0; iVar1 < local_1c[0]; iVar1 = iVar1 + 1) {
    iVar4 = *piVar2;
    iVar5 = *(char *)(iVar4 + 0x35) + 1;
    if (*(int *)(psVar3 + 0x20) == iVar4) {
      (&DAT_803872a8)[iVar5 * 4] = *(undefined4 *)(psVar3 + 6);
      (&DAT_803872ac)[iVar5 * 4] = *(undefined4 *)(psVar3 + 8);
      (&DAT_803872b0)[iVar5 * 4] = *(undefined4 *)(psVar3 + 10);
    }
    else {
      FUN_8000e054((double)*(float *)(psVar3 + 0x22),(double)*(float *)(psVar3 + 0x24),
                   (double)*(float *)(psVar3 + 0x26),&local_20,&local_24,&local_28,iVar4);
      (&DAT_803872a8)[iVar5 * 4] = local_20;
      (&DAT_803872ac)[iVar5 * 4] = local_24;
      (&DAT_803872b0)[iVar5 * 4] = local_28;
    }
    (&DAT_803872b4)[iVar5 * 4] = 1;
    piVar2 = piVar2 + 1;
  }
  FUN_8028688c();
  return;
}

