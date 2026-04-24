// Function: FUN_80243bcc
// Entry: 80243bcc
// Size: 136 bytes

uint FUN_80243bcc(uint param_1)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  
  uVar3 = FUN_8024377c();
  uVar1 = DAT_800000c4;
  uVar2 = DAT_800000c4 | DAT_800000c8;
  DAT_800000c4 = DAT_800000c4 & ~param_1;
  uVar4 = DAT_800000c4 | DAT_800000c8;
  for (param_1 = param_1 & uVar2; param_1 != 0; param_1 = FUN_8024386c(param_1,uVar4)) {
  }
  FUN_802437a4(uVar3);
  return uVar1;
}

