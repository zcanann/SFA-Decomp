// Function: FUN_8027588c
// Entry: 8027588c
// Size: 128 bytes

undefined4 FUN_8027588c(undefined2 param_1,undefined2 *param_2)

{
  undefined4 uVar1;
  
  DAT_803caefc = param_1;
  DAT_803def48 = (undefined4 *)
                 FUN_8028364c(&DAT_803caef8,-0x7fc3a928,(uint)DAT_803def0e,0xc,&LAB_8027587c);
  if (DAT_803def48 == (undefined4 *)0x0) {
    uVar1 = 0;
  }
  else {
    *param_2 = *(undefined2 *)((int)DAT_803def48 + 6);
    uVar1 = *DAT_803def48;
  }
  return uVar1;
}

