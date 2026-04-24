// Function: FUN_802538e4
// Entry: 802538e4
// Size: 124 bytes

undefined4 FUN_802538e4(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  
  puVar3 = (undefined4 *)(&DAT_803ae400 + param_1 * 0x40);
  uVar1 = FUN_8024377c();
  uVar2 = *puVar3;
  *puVar3 = param_2;
  if (param_1 == 2) {
    FUN_80253188(0,&DAT_803ae400);
  }
  else {
    FUN_80253188(param_1,puVar3);
  }
  FUN_802437a4(uVar1);
  return uVar2;
}

