// Function: FUN_80077a08
// Entry: 80077a08
// Size: 588 bytes

void FUN_80077a08(float *param_1,undefined4 *param_2,float *param_3)

{
  undefined4 local_48;
  float afStack_44 [15];
  
  FUN_80247618(param_1,param_3,afStack_44);
  FUN_8025d8c4(afStack_44,0x1e,1);
  FUN_80258674(0,1,0,0x1e,0,0x7d);
  FUN_8004c460((int)param_1[0x18],0);
  local_48 = *param_2;
  FUN_8025c510(0,(byte *)&local_48);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c584(0,0xc);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xe);
  FUN_8025c224(0,7,4,6,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025cce8(1,4,5,5);
  FUN_8025be54(0);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_80258944(1);
  FUN_8025ca04(1);
  if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(1,3,0);
    DAT_803ddc98 = '\x01';
    DAT_803ddc94 = 3;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  if ((DAT_803ddc91 != '\x01') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(1);
    DAT_803ddc91 = '\x01';
    DAT_803ddc99 = '\x01';
  }
  FUN_8025c754(7,0,0,7,0);
  return;
}

