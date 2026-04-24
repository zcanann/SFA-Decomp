// Function: FUN_80073d04
// Entry: 80073d04
// Size: 1036 bytes

undefined4 FUN_80073d04(int param_1,int *param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 local_58;
  uint local_54;
  undefined4 local_50;
  uint local_4c;
  undefined4 local_48;
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
  
  local_50 = DAT_803deeb4;
  iVar3 = *param_2;
  uVar1 = FUN_80028424(iVar3,0);
  puVar2 = (undefined4 *)FUN_8004c250(uVar1,0);
  uVar1 = FUN_800536c0(*puVar2);
  local_44 = FLOAT_803def34;
  local_40 = FLOAT_803deedc;
  local_3c = FLOAT_803deedc;
  local_38 = FLOAT_803deef8;
  local_34 = FLOAT_803deedc;
  local_30 = FLOAT_803def34;
  local_2c = FLOAT_803deedc;
  local_28 = FLOAT_803deef8;
  local_24 = FLOAT_803deedc;
  local_20 = FLOAT_803deedc;
  local_1c = FLOAT_803deedc;
  local_18 = FLOAT_803deee4;
  FUN_8025d160(&local_44,0x55,0);
  FUN_80257f10(0,1,1,0x1e,1,0x55);
  FUN_8006c5cc(&local_48);
  FUN_8004c2e4(local_48,0);
  local_4c = local_4c & 0xffffff00 | (uint)*(byte *)(param_1 + 0x37);
  local_54 = local_4c;
  FUN_8025bdac(0,&local_54);
  FUN_8025be8c(1,0x1c);
  local_58 = local_50;
  FUN_8025bcc4(1,&local_58);
  FUN_8025b6f0(0);
  FUN_802581e0(2);
  FUN_8025c2a0(2);
  FUN_8025b71c(0);
  if ((*(byte *)(iVar3 + 0x24) & 2) == 0) {
    FUN_80259ea4(4,0,0,0,0,0,2);
    FUN_80259ea4(5,0,0,0,0,0,2);
    FUN_80259e58(0);
    FUN_8025c0c4(0,0,0,0xff);
    FUN_8025bac0(0,4,7,7,1);
    FUN_8025c584(1,4,5,5);
  }
  else {
    FUN_80259e58(1);
    FUN_80259ea4(4,0,0,1,0,0,2);
    FUN_8025c0c4(0,0,0,4);
    FUN_8025bac0(0,7,4,5,5);
    FUN_8025c584(1,4,1,5);
  }
  FUN_8025ba40(0,0xf,0xf,0xf,0xf);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,1,0,0,1,0);
  FUN_80257f10(1,1,4,0x3c,0,0x7d);
  FUN_8004c2e4(uVar1,1);
  FUN_8025b71c(1);
  FUN_8025c0c4(1,1,1,0xff);
  FUN_8025ba40(1,2,0xf,0xf,8);
  FUN_8025bac0(1,7,0,6,7);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) || (DAT_803dd012 != '\0')) ||
     (DAT_803dd01a == '\0')) {
    FUN_8025c708(1,3,0);
    DAT_803dd018 = '\x01';
    DAT_803dd014 = 3;
    DAT_803dd012 = '\0';
    DAT_803dd01a = '\x01';
  }
  if ((DAT_803dd011 != '\x01') || (DAT_803dd019 == '\0')) {
    FUN_8025c780(1);
    DAT_803dd011 = '\x01';
    DAT_803dd019 = '\x01';
  }
  FUN_8025bff0(7,0,0,7,0);
  FUN_80258b24(2);
  return 1;
}

