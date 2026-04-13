// Function: FUN_80041110
// Entry: 80041110
// Size: 236 bytes

void FUN_80041110(void)

{
  ushort *puVar1;
  int *piVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  float *pfVar7;
  short *psVar8;
  
  puVar1 = (ushort *)FUN_80286838();
  psVar6 = *(short **)(*(int *)(puVar1 + 0x28) + 0x40);
  pfVar7 = *(float **)(puVar1 + 0x3a);
  if ((*(byte *)((int)puVar1 + 0xaf) & 0x28) == 0) {
    piVar2 = (int *)FUN_8002b660((int)puVar1);
    psVar8 = psVar6;
    for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(*(int *)(puVar1 + 0x28) + 0x72); iVar5 = iVar5 + 1)
    {
      iVar4 = (int)*(char *)((int)psVar8 + *(char *)((int)puVar1 + 0xad) + 0x12);
      if (iVar4 < 0) {
        pfVar3 = (float *)0x0;
      }
      else {
        pfVar3 = (float *)FUN_80028630(piVar2,iVar4);
      }
      FUN_800411fc((float *)0x0,pfVar7 + 3,psVar8 + 3,*(byte *)(psVar6 + 8) & 0x10,puVar1,0);
      FUN_800411fc(pfVar3,pfVar7,psVar8,*(byte *)(psVar6 + 8) & 0x10,puVar1,1);
      psVar8 = psVar8 + 0xc;
      pfVar7 = pfVar7 + 6;
    }
  }
  FUN_80286884();
  return;
}

