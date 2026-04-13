// Function: FUN_80188f20
// Entry: 80188f20
// Size: 604 bytes

void FUN_80188f20(void)

{
  int iVar1;
  int iVar2;
  byte bVar3;
  int iVar4;
  undefined auStack_38 [12];
  float local_2c;
  float local_28;
  float local_24 [9];
  
  iVar2 = FUN_80286834();
  iVar4 = *(int *)(iVar2 + 0xb8);
  if (*(char *)(iVar4 + 0x1a) != '\0') {
    for (bVar3 = 0; bVar3 < 5; bVar3 = bVar3 + 1) {
      iVar1 = (uint)bVar3 * 8;
      FUN_80038524(iVar2,(uint)(byte)(&DAT_8032267c)[iVar1],&local_2c,&local_28,local_24,0);
      local_2c = local_2c - *(float *)(iVar2 + 0xc);
      local_28 = local_28 - *(float *)(iVar2 + 0x10);
      local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
      FUN_8009742c((double)(*(float *)(iVar2 + 8) * (float)(&DAT_80322678)[(uint)bVar3 * 2]),iVar2,4
                   ,(uint)(byte)(&DAT_8032267d)[iVar1],(uint)(byte)(&DAT_8032267e)[iVar1],
                   (int)auStack_38);
    }
  }
  if (*(float *)(iVar4 + 0xc) != FLOAT_803e4830) {
    FUN_80038524(iVar2,6,&local_2c,&local_28,local_24,0);
    local_2c = local_2c - *(float *)(iVar2 + 0xc);
    local_28 = local_28 - *(float *)(iVar2 + 0x10);
    local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
    FUN_80098608((double)FLOAT_803e4834,(double)*(float *)(iVar4 + 0xc));
  }
  if (*(float *)(iVar4 + 8) != FLOAT_803e4830) {
    FUN_80038524(iVar2,8,&local_2c,&local_28,local_24,0);
    local_2c = local_2c - *(float *)(iVar2 + 0xc);
    local_28 = local_28 - *(float *)(iVar2 + 0x10);
    local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
    FUN_80098608((double)FLOAT_803e4834,(double)*(float *)(iVar4 + 8));
  }
  if (*(float *)(iVar4 + 4) != FLOAT_803e4830) {
    FUN_80038524(iVar2,7,&local_2c,&local_28,local_24,0);
    local_2c = local_2c - *(float *)(iVar2 + 0xc);
    local_28 = local_28 - *(float *)(iVar2 + 0x10);
    local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
    FUN_80098608((double)FLOAT_803e4834,(double)*(float *)(iVar4 + 4));
  }
  FUN_80286880();
  return;
}

