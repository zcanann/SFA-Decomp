// Function: FUN_80073e80
// Entry: 80073e80
// Size: 1036 bytes

undefined4 FUN_80073e80(int param_1,int *param_2)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  int iVar4;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  int local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_50 = DAT_803dfb34;
  iVar4 = *param_2;
  iVar1 = FUN_800284e8(iVar4,0);
  puVar2 = (uint *)FUN_8004c3cc(iVar1,0);
  uVar3 = FUN_8005383c(*puVar2);
  local_44 = FLOAT_803dfbb4;
  local_40 = FLOAT_803dfb5c;
  local_3c = FLOAT_803dfb5c;
  local_38 = FLOAT_803dfb78;
  local_34 = FLOAT_803dfb5c;
  local_30 = FLOAT_803dfbb4;
  local_2c = FLOAT_803dfb5c;
  local_28 = FLOAT_803dfb78;
  local_24 = FLOAT_803dfb5c;
  local_20 = FLOAT_803dfb5c;
  local_1c = FLOAT_803dfb5c;
  local_18 = FLOAT_803dfb64;
  FUN_8025d8c4(&local_44,0x55,0);
  FUN_80258674(0,1,1,0x1e,1,0x55);
  FUN_8006c748(&local_48);
  FUN_8004c460(local_48,0);
  local_4c = CONCAT31(local_4c._0_3_,*(undefined *)(param_1 + 0x37));
  local_54 = local_4c;
  FUN_8025c510(0,(byte *)&local_54);
  FUN_8025c5f0(1,0x1c);
  local_58 = local_50;
  FUN_8025c428(1,(byte *)&local_58);
  FUN_8025be54(0);
  FUN_80258944(2);
  FUN_8025ca04(2);
  FUN_8025be80(0);
  if ((*(byte *)(iVar4 + 0x24) & 2) == 0) {
    FUN_8025a608(4,0,0,0,0,0,2);
    FUN_8025a608(5,0,0,0,0,0,2);
    FUN_8025a5bc(0);
    FUN_8025c828(0,0,0,0xff);
    FUN_8025c224(0,4,7,7,1);
    FUN_8025cce8(1,4,5,5);
  }
  else {
    FUN_8025a5bc(1);
    FUN_8025a608(4,0,0,1,0,0,2);
    FUN_8025c828(0,0,0,4);
    FUN_8025c224(0,7,4,5,5);
    FUN_8025cce8(1,4,1,5);
  }
  FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,1,0,0,1,0);
  FUN_80258674(1,1,4,0x3c,0,0x7d);
  FUN_8004c460(uVar3,1);
  FUN_8025be80(1);
  FUN_8025c828(1,1,1,0xff);
  FUN_8025c1a4(1,2,0xf,0xf,8);
  FUN_8025c224(1,7,0,6,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
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
  FUN_80259288(2);
  return 1;
}

