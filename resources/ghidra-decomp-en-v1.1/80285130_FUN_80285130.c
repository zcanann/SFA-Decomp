// Function: FUN_80285130
// Entry: 80285130
// Size: 116 bytes

void FUN_80285130(undefined4 param_1)

{
  undefined4 uVar1;
  uint uVar2;
  ushort uVar3;
  
  uVar2 = FUN_802851a4();
  FUN_8027cbf0(param_1,uVar2);
  uVar1 = DAT_803defb0;
  DAT_803df028 = 0;
  FUN_80240a74();
  FUN_8025165c(DAT_803defac | 0xbabe0000);
  do {
    uVar3 = FUN_80251624();
  } while (uVar3 != 0);
  FUN_8025165c(uVar1);
  do {
    uVar3 = FUN_80251624();
  } while (uVar3 != 0);
  return;
}

