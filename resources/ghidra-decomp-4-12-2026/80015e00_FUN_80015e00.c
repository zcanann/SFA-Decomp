// Function: FUN_80015e00
// Entry: 80015e00
// Size: 188 bytes

void FUN_80015e00(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  byte *pbVar3;
  byte *pbVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_80286840();
  iVar1 = DAT_803dd648;
  if (DAT_803dd5ec == 0) {
    iVar2 = DAT_803dd648 * 5;
    DAT_803dd648 = DAT_803dd648 + 1;
    (&DAT_8033b1a0)[iVar2] = 7;
    pbVar3 = DAT_803dd644;
    pbVar4 = FUN_80015c28(DAT_803dd644,(byte *)((ulonglong)uVar5 >> 0x20));
    DAT_803dd644 = pbVar4 + 1;
    (&DAT_8033b1a4)[iVar1 * 5] = pbVar3;
    (&DAT_8033b1a8)[iVar1 * 5] = (int)uVar5;
    (&DAT_8033b1ac)[iVar1 * 5] = param_3;
    (&DAT_8033b1b0)[iVar1 * 5] = param_4;
  }
  else {
    iVar1 = (int)uVar5 * 0x20;
    *(short *)(&DAT_802c7b98 + iVar1) = (short)param_3;
    *(short *)(&DAT_802c7b9a + iVar1) = (short)param_4;
    FUN_80015ebc();
  }
  FUN_8028688c();
  return;
}

