// Function: FUN_800e7da0
// Entry: 800e7da0
// Size: 160 bytes

undefined4 FUN_800e7da0(char param_1,undefined4 param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  if (param_1 == '\0') {
    uVar1 = FUN_8001ffb4(param_2);
  }
  else {
    iVar2 = FUN_8001ffb4(0xbfd);
    if ((((iVar2 == 0) && (iVar2 = FUN_8001ffb4(0xff), iVar2 == 0)) &&
        (iVar2 = FUN_8001ffb4(0xba8), iVar2 == 0)) &&
       (((iVar2 = FUN_8001ffb4(0xc85), iVar2 == 0 && (iVar2 = FUN_8001ffb4(0xc6e), iVar2 == 0)) &&
        (iVar2 = FUN_8001ffb4(0x174), iVar2 == 0)))) {
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  return uVar1;
}

