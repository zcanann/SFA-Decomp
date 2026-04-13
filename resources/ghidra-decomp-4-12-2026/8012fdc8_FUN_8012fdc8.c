// Function: FUN_8012fdc8
// Entry: 8012fdc8
// Size: 188 bytes

void FUN_8012fdc8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  int iVar2;
  short sVar3;
  uint uVar4;
  char cVar5;
  
  iVar2 = FUN_801245c0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  sVar3 = (&DAT_8031c22c)[param_9 * 8];
  uVar4 = 0;
  cVar5 = '\x01';
  while( true ) {
    if (iVar2 << 1 <= (int)(uVar4 & 0xff)) {
      return;
    }
    iVar1 = (int)sVar3;
    if (((&DAT_803a98d8)[iVar1] != '\0') && ((cVar5 != '\0' || (iVar2 <= (int)(uVar4 & 0xff)))))
    break;
    sVar3 = sVar3 + 1;
    if (iVar2 <= sVar3) {
      sVar3 = 0;
    }
    uVar4 = uVar4 + 1;
    cVar5 = (&DAT_803a98d8)[iVar1];
  }
  (&DAT_8031c22c)[param_9 * 8] = sVar3;
  return;
}

