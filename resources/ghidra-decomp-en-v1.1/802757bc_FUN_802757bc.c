// Function: FUN_802757bc
// Entry: 802757bc
// Size: 96 bytes

undefined4 FUN_802757bc(undefined2 param_1)

{
  undefined4 uVar1;
  
  uRam803def34 = param_1;
  DAT_803def38 = (undefined4 *)
                 FUN_8028364c(&DAT_803def30,-0x7fc3f128,(uint)DAT_803def0a,8,&LAB_802757ac);
  if (DAT_803def38 == (undefined4 *)0x0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *DAT_803def38;
  }
  return uVar1;
}

