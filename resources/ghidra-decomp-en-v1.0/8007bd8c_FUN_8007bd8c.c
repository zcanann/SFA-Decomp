// Function: FUN_8007bd8c
// Entry: 8007bd8c
// Size: 1604 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_8007bd8c(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  uint3 uVar2;
  char cVar3;
  undefined auStack96 [4];
  uint local_5c;
  uint local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined auStack64 [52];
  
  FUN_8006c6f0(0);
  FUN_8004c2e4(param_1,1);
  FUN_8004c2e4(param_2,2);
  FUN_80257f10(1,1,4,0x3c,0,0x7d);
  FUN_8025d160(&DAT_80396820,0x55,0);
  FUN_80257f10(0,0,0,0,0,0x55);
  FUN_80247318((double)FLOAT_803def64,(double)FLOAT_803deee4,(double)FLOAT_803deedc,auStack64);
  FUN_8025d160(auStack64,0x1e,1);
  FUN_80257f10(2,1,4,0x1e,0,0x7d);
  FUN_80259ea4(4,0,0,1,0,0,2);
  cVar3 = FUN_8004c248();
  if (cVar3 == '\0') {
    (**(code **)(*DAT_803dca58 + 0x40))
              (&local_44,(int)&local_44 + 1,(int)&local_44 + 2,auStack96,auStack96,auStack96);
  }
  else {
    local_44._2_2_ = (ushort)local_44 & 0xff | (ushort)DAT_803dd01c._2_1_ << 8;
    local_44 = (uint)DAT_803dd01c._0_1_ << 0x18 |
               CONCAT12(DAT_803dd01c._1_1_,(ushort)local_44) & 0xffff0000 | (uint)local_44._2_2_;
  }
  local_4c = DAT_803db690;
  FUN_8025bdac(0,&local_4c);
  FUN_8025be20(0,0xc);
  local_50 = DAT_803db694;
  FUN_8025bdac(1,&local_50);
  FUN_8025be20(1,0xd);
  local_54 = DAT_803db698;
  FUN_8025bdac(2,&local_54);
  FUN_8025be20(2,0xe);
  uVar1 = (uint)CONCAT12((char)((int)((local_44 & 0xff0000) >> 0x10) >> 2),(ushort)local_44);
  local_44._2_2_ = (ushort)local_44 & 0xff | (ushort)(byte)((int)((uVar1 & 0xff00) >> 8) >> 2) << 8;
  local_44 = ((int)(local_44 >> 0x18) >> 2) << 0x18 | uVar1 & 0xffff0000 | (uint)local_44._2_2_;
  local_58 = local_44;
  FUN_8025bcc4(1,&local_58);
  uVar2 = CONCAT12(local_44._1_1_ + -0x40,local_48._2_2_);
  local_48._2_2_ = local_48._2_2_ & 0xff | (ushort)(byte)(local_44._2_1_ - 0x40) << 8;
  local_48 = (uint)(byte)(local_44._0_1_ - 0x40) << 0x18 | uVar2 & 0xffff0000 | (uint)local_48._2_2_
  ;
  local_5c = local_48;
  FUN_8025bcc4(2,&local_5c);
  FUN_8025b5b8(0,1,1);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&DAT_8030ea10,0xffffffff);
  FUN_8025b284(2,&DAT_8030ea28,0xffffffff);
  FUN_8025b284(3,&DAT_8030ea40,0xffffffff);
  FUN_8025b1e8(0,0,0,7,1,0,0,0,0,0);
  FUN_8025b1e8(1,0,0,7,2,0,0,0,0,1);
  FUN_8025b1e8(2,0,0,7,3,0,0,0,0,0);
  FUN_8025b6f0(1);
  FUN_802581e0(3);
  FUN_8025c2a0(4);
  FUN_80259e58(1);
  FUN_8025c0c4(0,0,0,4);
  FUN_8025ba40(0,0xf,8,0xe,2);
  FUN_8025bac0(0,7,7,7,5);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_8025c0c4(1,0,0,8);
  FUN_8025ba40(1,0xf,8,0xe,0);
  FUN_8025bac0(1,7,5,0,7);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  FUN_8025c0c4(2,0,0,0xff);
  FUN_8025ba40(2,0xf,8,0xe,0);
  FUN_8025bac0(2,7,7,7,0);
  FUN_8025bef8(2,0,0);
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bc04(2,0,0,0,1,0);
  FUN_8025b71c(3);
  FUN_8025c0c4(3,2,2,0xff);
  FUN_8025ba40(3,0,4,9,0xf);
  FUN_8025bac0(3,7,7,7,0);
  FUN_8025bef8(3,0,0);
  FUN_8025bb44(3,0,0,0,1,0);
  FUN_8025bc04(3,0,0,0,1,0);
  FUN_8025c584(1,4,5,5);
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
  return;
}

