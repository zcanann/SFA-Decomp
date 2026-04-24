// Function: FUN_8012f9b4
// Entry: 8012f9b4
// Size: 188 bytes

void FUN_8012f9b4(int param_1,short param_2,char param_3)

{
  int iVar1;
  short sVar2;
  uint uVar3;
  
  iVar1 = FUN_801242dc((&PTR_DAT_8031b5d8)[param_1 * 4],(int)param_3);
  sVar2 = (&DAT_8031b5dc)[param_1 * 8];
  uVar3 = 0;
  while( true ) {
    if (iVar1 <= (int)(uVar3 & 0xff)) {
      return;
    }
    if (((&DAT_803a8c78)[sVar2] != '\0') && ((int)param_2 == (&DAT_803a9038)[sVar2])) break;
    sVar2 = sVar2 + 1;
    if (iVar1 <= sVar2) {
      sVar2 = 0;
    }
    uVar3 = uVar3 + 1;
  }
  (&DAT_8031b5dc)[param_1 * 8] = sVar2;
  return;
}

