// Function: FUN_8007c3d0
// Entry: 8007c3d0
// Size: 660 bytes

void FUN_8007c3d0(char param_1)

{
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  
  FUN_8006c6f0(1);
  FUN_80257f10(1,0,0,0x24,0,0x7d);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  local_20 = FLOAT_803deedc;
  local_1c = FLOAT_803deef8;
  local_18 = FLOAT_803deedc;
  local_14 = FLOAT_803deedc;
  local_10 = FLOAT_803deedc;
  local_c = FLOAT_803deef8;
  FUN_8025b5b8(0,0,0);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&local_20,0xfffffffe);
  FUN_8025b1e8(1,0,0,7,1,0,0,0,0,1);
  FUN_8025b6f0(1);
  FUN_802581e0(2);
  FUN_8025c2a0(2);
  FUN_80259ea4(0,0,0,1,0,0,2);
  FUN_80259ea4(2,0,0,1,0,0,2);
  FUN_80259e58(1);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,0xff,0xff,4);
  FUN_8025ba40(0,0xf,0xf,0xf,10);
  FUN_8025bac0(0,7,7,7,5);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  if (param_1 == '\0') {
    FUN_8025ba40(1,0xf,8,0,0xf);
  }
  else {
    FUN_8025ba40(1,8,0xf,0xf,0);
  }
  FUN_8025c0c4(1,1,1,8);
  FUN_8025bac0(1,7,5,0,7);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  return;
}

