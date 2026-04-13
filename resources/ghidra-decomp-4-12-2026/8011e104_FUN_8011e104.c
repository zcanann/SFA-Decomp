// Function: FUN_8011e104
// Entry: 8011e104
// Size: 696 bytes

void FUN_8011e104(int param_1,undefined param_2,undefined4 param_3,char param_4)

{
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_10 = DAT_803e2ab8;
  local_c = CONCAT31((int3)((uint)DAT_803e2ab4 >> 8),param_2);
  local_14 = local_c;
  FUN_8025c428(1,(byte *)&local_14);
  FUN_8025d80c((float *)&DAT_803a9490,0);
  FUN_8025d848((float *)&DAT_803a9490,0);
  FUN_8025d888(0);
  FUN_80258944(1);
  FUN_8025be54(0);
  FUN_8025a5bc(0);
  FUN_8004c3e0(param_1,0);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_8025c584(0,0xc);
  local_18 = local_10;
  FUN_8025c510(0,(byte *)&local_18);
  FUN_8025be80(0);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,2,8,0xe,0xf);
  FUN_8025c224(0,7,1,4,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  if (*(int *)(param_1 + 0x50) == 0) {
    FUN_8025ca04(1);
  }
  else {
    FUN_8025be80(1);
    FUN_8025c828(1,0,1,0xff);
    FUN_8025c1a4(1,0xf,0xf,0xf,0);
    FUN_8025c224(1,7,1,4,7);
    FUN_8025c65c(1,0,0);
    FUN_8025c2a8(1,0,0,0,1,0);
    FUN_8025c368(1,0,0,0,1,0);
    FUN_8025ca04(2);
  }
  FUN_80259288(0);
  if (param_4 == '\0') {
    FUN_8025cce8(1,4,5,5);
  }
  else {
    FUN_8025cce8(1,4,1,5);
  }
  FUN_8007048c(0,7,0);
  FUN_80070434(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  return;
}

