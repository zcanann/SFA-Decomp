// Function: FUN_8007c54c
// Entry: 8007c54c
// Size: 660 bytes

void FUN_8007c54c(char param_1)

{
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  
  FUN_8006c86c(1);
  FUN_80258674(1,0,0,0x24,0,0x7d);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  local_20 = FLOAT_803dfb5c;
  local_1c = FLOAT_803dfb78;
  local_18 = FLOAT_803dfb5c;
  local_14 = FLOAT_803dfb5c;
  local_10 = FLOAT_803dfb5c;
  local_c = FLOAT_803dfb78;
  FUN_8025bd1c(0,0,0);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_20,-2);
  FUN_8025b94c(1,0,0,7,1,0,0,0,0,1);
  FUN_8025be54(1);
  FUN_80258944(2);
  FUN_8025ca04(2);
  FUN_8025a608(0,0,0,1,0,0,2);
  FUN_8025a608(2,0,0,1,0,0,2);
  FUN_8025a5bc(1);
  FUN_8025be80(0);
  FUN_8025c828(0,0xff,0xff,4);
  FUN_8025c1a4(0,0xf,0xf,0xf,10);
  FUN_8025c224(0,7,7,7,5);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  if (param_1 == '\0') {
    FUN_8025c1a4(1,0xf,8,0,0xf);
  }
  else {
    FUN_8025c1a4(1,8,0xf,0xf,0);
  }
  FUN_8025c828(1,1,1,8);
  FUN_8025c224(1,7,5,0,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  return;
}

