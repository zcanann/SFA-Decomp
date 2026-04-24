// Function: FUN_800161c4
// Entry: 800161c4
// Size: 148 bytes

void FUN_800161c4(byte *param_1,undefined4 param_2)

{
  int iVar1;
  byte *pbVar2;
  int iVar3;
  byte *pbVar4;
  
  iVar3 = DAT_803dd648;
  if (DAT_803dd5ec == 0) {
    iVar1 = DAT_803dd648 * 5;
    DAT_803dd648 = DAT_803dd648 + 1;
    (&DAT_8033b1a0)[iVar1] = 6;
    pbVar2 = DAT_803dd644;
    pbVar4 = FUN_80015c28(DAT_803dd644,param_1);
    DAT_803dd644 = pbVar4 + 1;
    (&DAT_8033b1a4)[iVar3 * 5] = pbVar2;
    (&DAT_8033b1a8)[iVar3 * 5] = param_2;
  }
  else {
    FUN_80015ebc();
  }
  return;
}

