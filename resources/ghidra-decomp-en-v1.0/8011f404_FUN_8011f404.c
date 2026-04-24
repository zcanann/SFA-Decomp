// Function: FUN_8011f404
// Entry: 8011f404
// Size: 720 bytes

void FUN_8011f404(void)

{
  short sVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  
  uVar5 = (uint)*(ushort *)(DAT_803a8b30 + 0xc);
  uVar3 = (uint)DAT_803dba59;
  uVar2 = (uint)DAT_803dba58;
  uVar4 = *(ushort *)(DAT_803a8b2c + 10) & 0xff;
  if (DAT_803dd76e == 0) {
    sVar1 = -((ushort)DAT_803dbaf0 * (ushort)DAT_803db410);
  }
  else {
    sVar1 = (ushort)DAT_803dbaf0 * (ushort)DAT_803db410;
  }
  DAT_803dd76c = DAT_803dd76c + sVar1;
  if ((short)DAT_803dd76c < 0) {
    DAT_803dd76c = 0;
  }
  else if (0xff < (short)DAT_803dd76c) {
    DAT_803dd76c = 0xff;
  }
  if (DAT_803dd76c != 0) {
    FUN_8025d3d4(&local_48,&local_4c,&local_50,&local_54);
    FUN_8025d324(0,0,0x280,0x1e0);
    uStack60 = (0x140 - (uint)DAT_803dba58) - uVar4 ^ 0x80000000;
    local_40 = 0x43300000;
    FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1e78),
                 (double)FLOAT_803e1e9c,DAT_803a8b2c,DAT_803dd76c & 0xff,0x100,uVar4,uVar5,1);
    uStack52 = 0x140 - DAT_803dba59 ^ 0x80000000;
    local_38 = 0x43300000;
    FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1e78),
                 (double)FLOAT_803e1e9c,DAT_803a8b30,DAT_803dd76c & 0xff,0x100,
                 (uint)DAT_803dba59 << 1,uVar5,0);
    uStack44 = 0x140 - DAT_803dba58 ^ 0x80000000;
    local_30 = 0x43300000;
    FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1e78),
                 (double)FLOAT_803e1e9c,DAT_803a8b34,DAT_803dd76c & 0xff,0x100,uVar2 - uVar3,uVar5,0
                );
    uStack36 = DAT_803dba59 + 0x140 ^ 0x80000000;
    local_28 = 0x43300000;
    FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e1e78),
                 (double)FLOAT_803e1e9c,DAT_803a8b34,DAT_803dd76c & 0xff,0x100,uVar2 - uVar3,uVar5,0
                );
    uStack28 = DAT_803dba58 + 0x140 ^ 0x80000000;
    local_20 = 0x43300000;
    FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e1e78),
                 (double)FLOAT_803e1e9c,DAT_803a8b2c,DAT_803dd76c & 0xff,0x100);
    local_58 = CONCAT31(0xff0000,(char)DAT_803dd76c);
    local_44 = local_58;
    FUN_800753b8((DAT_803dba5a + 0x140) - (uint)DAT_803dbaef,DAT_803dbaee + 0x32,
                 (uint)DAT_803dbaef + DAT_803dba5a + 0x140,(uVar5 + 0x32) - (uint)DAT_803dbaee,
                 &local_58);
    FUN_8025d324(local_48,local_4c,local_50,local_54);
  }
  return;
}

