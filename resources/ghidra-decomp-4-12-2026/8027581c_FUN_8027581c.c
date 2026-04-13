// Function: FUN_8027581c
// Entry: 8027581c
// Size: 96 bytes

undefined4 FUN_8027581c(undefined2 param_1)

{
  undefined4 uVar1;
  
  uRam803def40 = param_1;
  DAT_803def44 = (undefined4 *)
                 FUN_8028364c(&DAT_803def3c,-0x7fc3b128,(uint)DAT_803def0c,8,&LAB_802757ac);
  if (DAT_803def44 == (undefined4 *)0x0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *DAT_803def44;
  }
  return uVar1;
}

