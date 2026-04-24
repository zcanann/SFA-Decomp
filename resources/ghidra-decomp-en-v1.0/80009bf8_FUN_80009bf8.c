// Function: FUN_80009bf8
// Entry: 80009bf8
// Size: 1424 bytes

undefined4 FUN_80009bf8(void)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 local_10;
  undefined4 local_c;
  
  local_10 = DAT_803de548;
  local_c = DAT_803de54c;
  if (DAT_803dc7cc == '\0') {
    DAT_803dc7cc = '\x01';
    DAT_803dc7f8 = 0;
    DAT_803dc7f4 = 0;
    FUN_80022d3c(1);
    if (DAT_803dc7d0 != '\0') {
      return 1;
    }
    DAT_803dc7d0 = '\x01';
    FUN_802500d4(&DAT_80335d94,10);
    FUN_80250cfc();
    FUN_8024fae8(0);
    FUN_8024f8b8(0);
    FUN_80283f38(&local_10);
    FUN_80281044(0x30,0x30,0x18,1,1,0x1000000);
    FUN_80281194(0x30,0x18);
    iVar1 = FUN_802456c4();
    if (iVar1 == 0) {
      DAT_803db1e8 = 2;
      FUN_80272a64(0);
    }
    else {
      DAT_803db1e8 = 0;
      FUN_80272a64(1);
    }
    DAT_80335d7c = 0;
    DAT_80335d88 = FLOAT_803de550;
    DAT_80335d90 = FLOAT_803de554;
    DAT_80335d8c = FLOAT_803de558;
    DAT_80335d80 = FLOAT_803de558;
    DAT_80335d84 = FLOAT_803de55c;
    FUN_80284c1c();
    FUN_80272b5c(0,&LAB_80284bc0,&DAT_80335c40,0xff,0,0,0,0xff,0);
    iVar1 = FUN_802811a8();
    if (iVar1 == 0) {
      FUN_8007d6dc(s_audioInit__sndIsInstalled___retu_802c5100);
      return 0xff;
    }
    FUN_80272970(0x7f,0,0xff);
    FUN_802729d0(0x7f,100,1,1);
    FUN_8000bdb4();
    FUN_8000d594();
    FUN_8000980c();
    FUN_80022d3c(1);
    DAT_803dc7f8 = DAT_803dc7f8 | 8;
    DAT_803dc7f0 = FUN_80015964(s__audio_starfoxm_poo_802c5130,0,0,FUN_800094e4);
    DAT_803dc7f8 = DAT_803dc7f8 | 0x10;
    DAT_803dc7ec = FUN_80015964(s__audio_starfoxm_pro_802c5144,0,0,FUN_80009434);
    DAT_803dc7f8 = DAT_803dc7f8 | 0x20;
    DAT_803dc7e8 = FUN_80015964(s__audio_starfoxm_sdi_802c5158,0,0,FUN_80009384);
    FUN_80022d3c(0);
    DAT_803dc7f8 = DAT_803dc7f8 | 0x40;
    DAT_803dc7e4 = FUN_80015964(s__audio_starfoxm_sam_802c516c,0,0,FUN_800092d4);
    if ((((DAT_803dc7f0 == 0) || (DAT_803dc7ec == 0)) || (DAT_803dc7e8 == 0)) || (DAT_803dc7e4 == 0)
       ) {
      return 0xff;
    }
    FUN_80022d3c(0);
  }
  if ((((DAT_803dc7cd == '\0') && ((DAT_803dc7f4 & 8) != 0)) &&
      (((DAT_803dc7f4 & 0x10) != 0 && (((DAT_803dc7f4 & 8) != 0 && ((DAT_803dc7f4 & 0x20) != 0))))))
     && ((DAT_803dc7f4 & 0x40) != 0)) {
    FUN_8027b72c(DAT_803dc7ec,0,DAT_803dc7e4,DAT_803dc7e8,DAT_803dc7f0);
    uVar2 = FUN_80023834(0);
    FUN_80023800(DAT_803dc7e4);
    FUN_80023834(uVar2);
    DAT_803dc7cd = '\x01';
    FUN_80022d3c(1);
    DAT_803dc7f8 = DAT_803dc7f8 | 0x80;
    DAT_803dc7e0 = FUN_80015964(s__audio_starfoxs_poo_802c5180,0,0,FUN_80009224);
    DAT_803dc7f8 = DAT_803dc7f8 | 0x100;
    DAT_803dc7dc = FUN_80015964(s__audio_starfoxs_pro_802c5194,0,0,FUN_80009174);
    DAT_803dc7f8 = DAT_803dc7f8 | 0x200;
    DAT_803dc7d4 = FUN_80015964(s__audio_starfoxs_sdi_802c51a8,0,0,FUN_800090c4);
    FUN_80022d3c(0);
    DAT_803dc7f8 = DAT_803dc7f8 | 0x400;
    DAT_803dc7d8 = FUN_80015964(s__audio_starfoxs_sam_802c51bc,0,0,FUN_80009014);
    if ((((DAT_803dc7e0 == 0) || (DAT_803dc7dc == 0)) || (DAT_803dc7d4 == 0)) || (DAT_803dc7d8 == 0)
       ) {
      return 0xff;
    }
  }
  if (((DAT_803dc7ce == '\0') && ((DAT_803dc7f4 & 0x80) != 0)) &&
     ((((DAT_803dc7f4 & 0x100) != 0 &&
       (((DAT_803dc7f4 & 0x80) != 0 && ((DAT_803dc7f4 & 0x200) != 0)))) &&
      ((DAT_803dc7f4 & 0x400) != 0)))) {
    uVar3 = 1;
    do {
      iVar1 = FUN_8027b72c(DAT_803dc7dc,uVar3 & 0xffff,DAT_803dc7d8,DAT_803dc7d4,DAT_803dc7e0);
      if (iVar1 == 0) {
        FUN_8007d6dc(s_sndPushGroup_failed_on_group__d_802c51d0,uVar3);
      }
      uVar3 = uVar3 + 1;
    } while ((int)uVar3 < 0x38);
    uVar2 = FUN_80023834(0);
    FUN_80023800(DAT_803dc7d8);
    FUN_80023834(uVar2);
    DAT_803dc7ce = '\x01';
  }
  if (((DAT_803dc7cf == '\0') && (DAT_803dc7cd != '\0')) && (DAT_803dc7ce != '\0')) {
    DAT_803dc7cf = FUN_8000ae90();
  }
  if ((((DAT_803dc7cf == '\0') || (DAT_803dc7cd == '\0')) ||
      ((DAT_803dc7ce == '\0' || (((DAT_803dc7f4 & 1) == 0 || ((DAT_803dc7f4 & 2) == 0)))))) ||
     ((DAT_803dc7f4 & 4) == 0)) {
    uVar2 = 0;
  }
  else {
    DAT_803dc7c0 = 0;
    DAT_803dc7c4 = 0x1f;
    DAT_803dc7c8 = 0;
    uVar2 = 1;
  }
  return uVar2;
}

