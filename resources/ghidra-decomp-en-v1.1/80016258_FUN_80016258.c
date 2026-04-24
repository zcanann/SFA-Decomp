// Function: FUN_80016258
// Entry: 80016258
// Size: 108 bytes

void FUN_80016258(byte *param_1)

{
  int iVar1;
  byte *pbVar2;
  int iVar3;
  byte *pbVar4;
  
  iVar3 = DAT_803dd648;
  iVar1 = DAT_803dd648 * 5;
  DAT_803dd648 = DAT_803dd648 + 1;
  (&DAT_8033b1a0)[iVar1] = 5;
  pbVar2 = DAT_803dd644;
  pbVar4 = FUN_80015c28(DAT_803dd644,param_1);
  DAT_803dd644 = pbVar4 + 1;
  (&DAT_8033b1a4)[iVar3 * 5] = pbVar2;
  return;
}

