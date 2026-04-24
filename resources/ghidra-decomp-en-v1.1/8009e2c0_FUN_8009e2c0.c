// Function: FUN_8009e2c0
// Entry: 8009e2c0
// Size: 264 bytes

void FUN_8009e2c0(void)

{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  byte *pbVar4;
  byte *pbVar5;
  int *piVar6;
  char *pcVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_80286830();
  iVar2 = 0;
  pcVar7 = &DAT_8039c828;
  piVar6 = &DAT_8039c688;
  pbVar5 = &DAT_8039c638;
  pbVar4 = &DAT_8039c7d8;
  pfVar3 = (float *)&DAT_8039b9b8;
  do {
    if ((((*pcVar7 != '\0') && (*piVar6 == (int)((ulonglong)uVar8 >> 0x20))) &&
        ((uint)*pbVar5 == (int)uVar8 + 1U)) &&
       (uVar1 = FUN_8005eaf8((double)(*pfVar3 - FLOAT_803dda58),(double)(pfVar3[1] - FLOAT_803dda58)
                             ,(double)pfVar3[2],(double)pfVar3[3],
                             (double)(pfVar3[4] - FLOAT_803dda5c),
                             (double)(pfVar3[5] - FLOAT_803dda5c),
                             (float *)(&DAT_80310458 + (uint)*pbVar4 * 0x18)), (uVar1 & 0xff) != 0))
    {
      FUN_8009e3c8();
    }
    pcVar7 = pcVar7 + 1;
    piVar6 = piVar6 + 1;
    pbVar5 = pbVar5 + 1;
    pbVar4 = pbVar4 + 1;
    pfVar3 = pfVar3 + 6;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x50);
  FUN_8028687c();
  return;
}

