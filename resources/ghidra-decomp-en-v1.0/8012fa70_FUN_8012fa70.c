// Function: FUN_8012fa70
// Entry: 8012fa70
// Size: 188 bytes

void FUN_8012fa70(int param_1,char param_2)

{
  int iVar1;
  int iVar2;
  short sVar3;
  uint uVar4;
  char cVar5;
  
  iVar2 = FUN_801242dc((&PTR_DAT_8031b5d8)[param_1 * 4],(int)param_2);
  sVar3 = (&DAT_8031b5dc)[param_1 * 8];
  uVar4 = 0;
  cVar5 = '\x01';
  while( true ) {
    if (iVar2 << 1 <= (int)(uVar4 & 0xff)) {
      return;
    }
    iVar1 = (int)sVar3;
    if (((&DAT_803a8c78)[iVar1] != '\0') && ((cVar5 != '\0' || (iVar2 <= (int)(uVar4 & 0xff)))))
    break;
    sVar3 = sVar3 + 1;
    if (iVar2 <= sVar3) {
      sVar3 = 0;
    }
    uVar4 = uVar4 + 1;
    cVar5 = (&DAT_803a8c78)[iVar1];
  }
  (&DAT_8031b5dc)[param_1 * 8] = sVar3;
  return;
}

