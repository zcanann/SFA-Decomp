// Function: FUN_800e8024
// Entry: 800e8024
// Size: 160 bytes

uint FUN_800e8024(char param_1,uint param_2)

{
  uint uVar1;
  
  if (param_1 == '\0') {
    uVar1 = FUN_80020078(param_2);
  }
  else {
    uVar1 = FUN_80020078(0xbfd);
    if ((((uVar1 == 0) && (uVar1 = FUN_80020078(0xff), uVar1 == 0)) &&
        (uVar1 = FUN_80020078(0xba8), uVar1 == 0)) &&
       (((uVar1 = FUN_80020078(0xc85), uVar1 == 0 && (uVar1 = FUN_80020078(0xc6e), uVar1 == 0)) &&
        (uVar1 = FUN_80020078(0x174), uVar1 == 0)))) {
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  return uVar1;
}

