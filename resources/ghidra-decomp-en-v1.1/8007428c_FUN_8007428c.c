// Function: FUN_8007428c
// Entry: 8007428c
// Size: 1032 bytes

undefined4 FUN_8007428c(int param_1,int *param_2,int param_3)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  double dVar5;
  uint3 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  float afStack_54 [13];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar1 = FUN_800284e8(*param_2,param_3);
  puVar2 = (uint *)FUN_8004c3cc(iVar1,0);
  uVar3 = FUN_8005383c(*puVar2);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  uVar4 = FUN_80020078(0x2ba);
  uStack_1c = uVar4 & 0xff;
  DAT_803ddc90 = (undefined)uVar4;
  local_20 = 0x43300000;
  FUN_80247a48((double)((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803dfb80) /
                       FLOAT_803dfbb8),(double)FLOAT_803dfb5c,(double)FLOAT_803dfb5c,afStack_54);
  FUN_8025d8c4(afStack_54,0x1e,1);
  FUN_80258674(1,1,4,0x1e,0,0x7d);
  FUN_80258944(2);
  FUN_8025ca04(3);
  FUN_8025be54(0);
  FUN_8004c460(uVar3,0);
  local_58 = CONCAT31(local_58._0_3_,
                      (char)((uint)*(byte *)(iVar1 + 0xc) * (uint)*(byte *)(param_1 + 0x37) >> 8));
  local_60 = local_58;
  FUN_8025c510(0,(byte *)&local_60);
  FUN_8025c5f0(0,0x1c);
  FUN_8025be80(0);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,0xf,0xf,0xf,8);
  FUN_8025c224(0,7,4,6,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  local_5c = CONCAT31(local_5c._0_3_,0x3e);
  local_64 = local_5c;
  FUN_8025c510(1,(byte *)&local_64);
  FUN_8025c5f0(1,0x1d);
  FUN_8025be80(1);
  FUN_8025c828(1,1,0,0xff);
  FUN_8025c1a4(1,0xf,0xf,0xf,0);
  FUN_8025c224(1,7,6,4,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,2,1,1);
  FUN_8025be80(2);
  FUN_8025c828(2,0xff,0xff,0xff);
  FUN_8025c1a4(2,0xf,0xf,0xf,0);
  FUN_8025c224(2,0,7,1,7);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,0,1,0);
  FUN_8025cce8(1,4,5,5);
  if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(1,3,0);
    DAT_803ddc98 = '\x01';
    DAT_803ddc94 = 3;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  FUN_8025c754(7,0,0,7,0);
  if ((DAT_803ddc91 != '\x01') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(1);
    DAT_803ddc91 = '\x01';
    DAT_803ddc99 = '\x01';
  }
  FUN_80259288(0);
  _local_68 = local_5c;
  dVar5 = (double)FLOAT_803dfb5c;
  FUN_8025ca38(dVar5,dVar5,dVar5,dVar5,0,&local_68);
  return 1;
}

