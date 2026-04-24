// Function: FUN_802849cc
// Entry: 802849cc
// Size: 116 bytes

void FUN_802849cc(undefined4 param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_80284a40();
  FUN_8027c48c(param_1,uVar1);
  uVar1 = DAT_803de330;
  DAT_803de3a8 = 0;
  FUN_8024037c();
  FUN_80250ef8(DAT_803de32c | 0xbabe0000);
  do {
    iVar2 = FUN_80250ec0();
  } while (iVar2 != 0);
  FUN_80250ef8(uVar1);
  do {
    iVar2 = FUN_80250ec0();
  } while (iVar2 != 0);
  return;
}

