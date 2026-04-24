// Function: FUN_8009ef70
// Entry: 8009ef70
// Size: 468 bytes

void FUN_8009ef70(void)

{
  float *pfVar1;
  uint uVar2;
  int iVar3;
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
  uint uStack_34;
  
  FUN_80286830();
  pfVar1 = (float *)FUN_8000f56c();
  iVar4 = 0;
  pcVar11 = &DAT_8039c828;
  pcVar10 = &DAT_8039c638;
  pbVar9 = &DAT_8039c7d8;
  pfVar8 = (float *)&DAT_8039b9b8;
  piVar7 = &DAT_8039c688;
  psVar6 = &DAT_80310488;
  puVar5 = &DAT_8039c9b8;
  do {
    if (((*pcVar11 != '\0') && (*pcVar10 == '\0')) &&
       (uVar2 = FUN_8005eaf8((double)(*pfVar8 - FLOAT_803dda58),(double)(pfVar8[1] - FLOAT_803dda58)
                             ,(double)pfVar8[2],(double)pfVar8[3],
                             (double)(pfVar8[4] - FLOAT_803dda5c),
                             (double)(pfVar8[5] - FLOAT_803dda5c),
                             (float *)(&DAT_80310458 + (uint)*pbVar9 * 0x18)), (uVar2 & 0xff) != 0))
    {
      iVar3 = *piVar7;
      if (iVar3 == 0) {
        local_48 = FLOAT_803dffd8 * (*pfVar8 + pfVar8[1]);
        local_44 = FLOAT_803dffd8 * (pfVar8[2] + pfVar8[3]);
        local_40 = FLOAT_803dffd8 * (pfVar8[4] + pfVar8[5]);
      }
      else {
        local_48 = *(float *)(iVar3 + 0xc);
        local_44 = *(float *)(iVar3 + 0x10);
        local_40 = *(float *)(iVar3 + 0x14);
      }
      local_40 = local_40 - FLOAT_803dda5c;
      local_48 = local_48 - FLOAT_803dda58;
      FUN_80247bf8(pfVar1,&local_48,&local_48);
      if (*piVar7 != 0) {
        uStack_34 = (int)*psVar6 & 0x21U ^ 0x80000000;
        local_38 = 0x43300000;
        local_40 = local_40 - (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803dffe0);
      }
      FUN_8005e010(*puVar5,iVar4,(int)&local_48);
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
  FUN_8028687c();
  return;
}

