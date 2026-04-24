// Function: FUN_80095208
// Entry: 80095208
// Size: 488 bytes

void FUN_80095208(void)

{
  float *pfVar1;
  undefined auStack_18 [4];
  undefined4 local_14;
  undefined4 local_10;
  
  FUN_802591d0(0x12,5);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  pfVar1 = (float *)FUN_8000f56c();
  FUN_8025d80c(pfVar1,0);
  FUN_8025d888(0);
  FUN_8025c584(0,0xc);
  FUN_8025c5f0(0,0x1c);
  FUN_8025be54(0);
  FUN_80258944(0);
  FUN_8025ca04(1);
  FUN_8025a5bc(1);
  FUN_8025be80(0);
  FUN_8025c828(0,0xff,0xff,4);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xe);
  FUN_8025c224(0,7,7,7,6);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025cce8(1,4,5,5);
  FUN_8007048c(1,3,0);
  FUN_80070434(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80259288(0);
  (**(code **)(*DAT_803dd6d8 + 0x40))
            (&local_10,(int)&local_10 + 1,(int)&local_10 + 2,auStack_18,auStack_18,auStack_18);
  local_10 = CONCAT31(CONCAT21(CONCAT11((char)((int)(local_10 >> 0x18) >> 2) + -0x80,
                                        (char)((int)(local_10 >> 0x10 & 0xff) >> 2) + -0x80),
                               (char)((int)(local_10 >> 8 & 0xff) >> 2) + -0x80),0x80);
  local_14 = local_10;
  FUN_8025c510(0,(byte *)&local_14);
  return;
}

