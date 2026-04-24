// Function: FUN_802aabe4
// Entry: 802aabe4
// Size: 352 bytes

void FUN_802aabe4(void)

{
  int iVar1;
  short sVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  short *psVar5;
  undefined auStack56 [8];
  undefined auStack48 [4];
  undefined4 local_2c;
  
  iVar1 = FUN_802860dc();
  uVar3 = *(undefined4 *)(*(int *)(iVar1 + 0x7c) + *(char *)(iVar1 + 0xad) * 4);
  FUN_80030334((double)FLOAT_803e7ea4,iVar1,(int)**(short **)(*(int *)(iVar1 + 0xb8) + 0x3f8),0);
  FUN_80027e00((double)FLOAT_803e7ea4,(double)*(float *)(iVar1 + 8),uVar3,0,0,auStack48,auStack56);
  DAT_803daf88 = local_2c;
  FUN_80030334((double)FLOAT_803e7ea4,iVar1,(int)DAT_80332f2c,0);
  FUN_80027e00((double)FLOAT_803e7ea4,(double)*(float *)(iVar1 + 8),uVar3,0,0,auStack48,auStack56);
  DAT_803daf8c = local_2c;
  psVar5 = &DAT_80332f6a;
  puVar4 = &DAT_803dafb8;
  for (sVar2 = 0xc; sVar2 < 0x10; sVar2 = sVar2 + 1) {
    FUN_80030334((double)FLOAT_803e7ea4,iVar1,(int)*psVar5,0);
    FUN_80027e00((double)FLOAT_803e7ea4,(double)*(float *)(iVar1 + 8),uVar3,0,0,auStack48,auStack56)
    ;
    *puVar4 = local_2c;
    psVar5 = psVar5 + 1;
    puVar4 = puVar4 + 1;
  }
  FUN_8002f52c(iVar1,0,0,0);
  FUN_80286128();
  return;
}

