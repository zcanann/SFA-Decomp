// Function: FUN_8009e034
// Entry: 8009e034
// Size: 264 bytes

void FUN_8009e034(void)

{
  char cVar1;
  int iVar2;
  undefined4 *puVar3;
  float *pfVar4;
  byte *pbVar5;
  byte *pbVar6;
  int *piVar7;
  char *pcVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_802860cc();
  iVar2 = 0;
  pcVar8 = &DAT_8039bbc8;
  piVar7 = &DAT_8039ba28;
  pbVar6 = &DAT_8039b9d8;
  pbVar5 = &DAT_8039bb78;
  pfVar4 = (float *)&DAT_8039ad58;
  puVar3 = &DAT_8039bd58;
  do {
    if ((((*pcVar8 != '\0') && (*piVar7 == (int)((ulonglong)uVar9 >> 0x20))) &&
        ((uint)*pbVar6 == (int)uVar9 + 1U)) &&
       (cVar1 = FUN_8005e97c((double)(*pfVar4 - FLOAT_803dcdd8),(double)(pfVar4[1] - FLOAT_803dcdd8)
                             ,(double)pfVar4[2],(double)pfVar4[3],
                             (double)(pfVar4[4] - FLOAT_803dcddc),
                             (double)(pfVar4[5] - FLOAT_803dcddc),
                             &DAT_8030f898 + (uint)*pbVar5 * 0x18), cVar1 != '\0')) {
      FUN_8009e13c(*puVar3,iVar2);
    }
    pcVar8 = pcVar8 + 1;
    piVar7 = piVar7 + 1;
    pbVar6 = pbVar6 + 1;
    pbVar5 = pbVar5 + 1;
    pfVar4 = pfVar4 + 6;
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x50);
  FUN_80286118();
  return;
}

