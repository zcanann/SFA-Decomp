// Function: FUN_8012fd0c
// Entry: 8012fd0c
// Size: 188 bytes

void FUN_8012fd0c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,short param_10)

{
  int iVar1;
  short sVar2;
  uint uVar3;
  
  iVar1 = FUN_801245c0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  sVar2 = (&DAT_8031c22c)[param_9 * 8];
  uVar3 = 0;
  while( true ) {
    if (iVar1 <= (int)(uVar3 & 0xff)) {
      return;
    }
    if (((&DAT_803a98d8)[sVar2] != '\0') && ((int)param_10 == (&DAT_803a9c98)[sVar2])) break;
    sVar2 = sVar2 + 1;
    if (iVar1 <= sVar2) {
      sVar2 = 0;
    }
    uVar3 = uVar3 + 1;
  }
  (&DAT_8031c22c)[param_9 * 8] = sVar2;
  return;
}

