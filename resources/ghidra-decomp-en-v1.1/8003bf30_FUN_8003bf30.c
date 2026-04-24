// Function: FUN_8003bf30
// Entry: 8003bf30
// Size: 196 bytes

/* WARNING: Removing unreachable block (ram,0x8003bfd4) */
/* WARNING: Removing unreachable block (ram,0x8003bf40) */

void FUN_8003bf30(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  float *pfVar4;
  float *pfVar5;
  float *pfVar6;
  double dVar7;
  
  iVar3 = FUN_80286838();
  pfVar4 = (float *)FUN_80022b0c();
  bVar1 = *(byte *)(iVar3 + 0xf3);
  bVar2 = *(byte *)(iVar3 + 0xf4);
  pfVar5 = pfVar4 + 0x9c0;
  pfVar6 = pfVar4 + 0x4b0;
  FUN_80022a88(0);
  dVar7 = (double)FLOAT_803df684;
  for (iVar3 = 0; iVar3 < (int)((uint)bVar1 + (uint)bVar2); iVar3 = iVar3 + 1) {
    FUN_80247618(param_3,pfVar5,pfVar4);
    FUN_80247618(pfVar4,param_4,pfVar6);
    pfVar6[3] = (float)dVar7;
    pfVar6[7] = (float)dVar7;
    pfVar6[0xb] = (float)dVar7;
    pfVar5 = pfVar5 + 0x10;
    pfVar4 = pfVar4 + 0xc;
    pfVar6 = pfVar6 + 0xc;
  }
  DAT_803dd8c8 = 2;
  FUN_80286884();
  return;
}

