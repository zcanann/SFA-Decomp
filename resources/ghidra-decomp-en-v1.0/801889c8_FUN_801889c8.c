// Function: FUN_801889c8
// Entry: 801889c8
// Size: 604 bytes

void FUN_801889c8(void)

{
  int iVar1;
  int iVar2;
  byte bVar3;
  int iVar4;
  undefined auStack56 [12];
  float local_2c;
  float local_28;
  float local_24 [9];
  
  iVar2 = FUN_802860d0();
  iVar4 = *(int *)(iVar2 + 0xb8);
  if (*(char *)(iVar4 + 0x1a) != '\0') {
    for (bVar3 = 0; bVar3 < 5; bVar3 = bVar3 + 1) {
      iVar1 = (uint)bVar3 * 8;
      FUN_8003842c(iVar2,(&DAT_80321a2c)[iVar1],&local_2c,&local_28,local_24,0);
      local_2c = local_2c - *(float *)(iVar2 + 0xc);
      local_28 = local_28 - *(float *)(iVar2 + 0x10);
      local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
      FUN_800971a0((double)(*(float *)(iVar2 + 8) * (float)(&DAT_80321a28)[(uint)bVar3 * 2]),iVar2,4
                   ,(&DAT_80321a2d)[iVar1],(&DAT_80321a2e)[iVar1],auStack56);
    }
  }
  if (*(float *)(iVar4 + 0xc) != FLOAT_803e3b98) {
    FUN_8003842c(iVar2,6,&local_2c,&local_28,local_24,0);
    local_2c = local_2c - *(float *)(iVar2 + 0xc);
    local_28 = local_28 - *(float *)(iVar2 + 0x10);
    local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
    FUN_8009837c((double)FLOAT_803e3b9c,(double)*(float *)(iVar4 + 0xc),iVar2,4,0,0,auStack56);
  }
  if (*(float *)(iVar4 + 8) != FLOAT_803e3b98) {
    FUN_8003842c(iVar2,8,&local_2c,&local_28,local_24,0);
    local_2c = local_2c - *(float *)(iVar2 + 0xc);
    local_28 = local_28 - *(float *)(iVar2 + 0x10);
    local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
    FUN_8009837c((double)FLOAT_803e3b9c,(double)*(float *)(iVar4 + 8),iVar2,4,0,0,auStack56);
  }
  if (*(float *)(iVar4 + 4) != FLOAT_803e3b98) {
    FUN_8003842c(iVar2,7,&local_2c,&local_28,local_24,0);
    local_2c = local_2c - *(float *)(iVar2 + 0xc);
    local_28 = local_28 - *(float *)(iVar2 + 0x10);
    local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
    FUN_8009837c((double)FLOAT_803e3b9c,(double)*(float *)(iVar4 + 4),iVar2,4,0,0,auStack56);
  }
  FUN_8028611c();
  return;
}

