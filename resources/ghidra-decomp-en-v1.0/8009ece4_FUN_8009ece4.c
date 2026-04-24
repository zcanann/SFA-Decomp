// Function: FUN_8009ece4
// Entry: 8009ece4
// Size: 468 bytes

void FUN_8009ece4(void)

{
  undefined4 uVar1;
  char cVar3;
  int iVar2;
  int iVar4;
  undefined4 *puVar5;
  short *psVar6;
  int *piVar7;
  float *pfVar8;
  byte *pbVar9;
  char *pcVar10;
  char *pcVar11;
  float local_48;
  float local_44;
  float local_40;
  undefined4 local_38;
  uint uStack52;
  
  FUN_802860cc();
  uVar1 = FUN_8000f54c();
  iVar4 = 0;
  pcVar11 = &DAT_8039bbc8;
  pcVar10 = &DAT_8039b9d8;
  pbVar9 = &DAT_8039bb78;
  pfVar8 = (float *)&DAT_8039ad58;
  piVar7 = &DAT_8039ba28;
  psVar6 = &DAT_8030f8c8;
  puVar5 = &DAT_8039bd58;
  do {
    if (((*pcVar11 != '\0') && (*pcVar10 == '\0')) &&
       (cVar3 = FUN_8005e97c((double)(*pfVar8 - FLOAT_803dcdd8),(double)(pfVar8[1] - FLOAT_803dcdd8)
                             ,(double)pfVar8[2],(double)pfVar8[3],
                             (double)(pfVar8[4] - FLOAT_803dcddc),
                             (double)(pfVar8[5] - FLOAT_803dcddc),
                             &DAT_8030f898 + (uint)*pbVar9 * 0x18), cVar3 != '\0')) {
      iVar2 = *piVar7;
      if (iVar2 == 0) {
        local_48 = FLOAT_803df358 * (*pfVar8 + pfVar8[1]);
        local_44 = FLOAT_803df358 * (pfVar8[2] + pfVar8[3]);
        local_40 = FLOAT_803df358 * (pfVar8[4] + pfVar8[5]);
      }
      else {
        local_48 = *(float *)(iVar2 + 0xc);
        local_44 = *(float *)(iVar2 + 0x10);
        local_40 = *(float *)(iVar2 + 0x14);
      }
      local_40 = local_40 - FLOAT_803dcddc;
      local_48 = local_48 - FLOAT_803dcdd8;
      FUN_80247494(uVar1,&local_48,&local_48);
      if (*piVar7 != 0) {
        uStack52 = (int)*psVar6 & 0x21U ^ 0x80000000;
        local_38 = 0x43300000;
        local_40 = local_40 - (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df360);
      }
      FUN_8005de94(*puVar5,iVar4,&local_48);
    }
    pcVar11 = pcVar11 + 1;
    pcVar10 = pcVar10 + 1;
    pbVar9 = pbVar9 + 1;
    pfVar8 = pfVar8 + 6;
    piVar7 = piVar7 + 1;
    psVar6 = psVar6 + 1;
    puVar5 = puVar5 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 0x50);
  FUN_80286118();
  return;
}

