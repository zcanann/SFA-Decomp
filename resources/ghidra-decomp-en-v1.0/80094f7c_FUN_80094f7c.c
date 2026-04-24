// Function: FUN_80094f7c
// Entry: 80094f7c
// Size: 488 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_80094f7c(void)

{
  byte bVar1;
  undefined4 uVar2;
  undefined auStack24 [4];
  undefined4 local_14;
  undefined4 local_10;
  
  FUN_80258a6c(0x12,5);
  FUN_802573f8();
  FUN_80256978(9,1);
  uVar2 = FUN_8000f54c();
  FUN_8025d0a8(uVar2,0);
  FUN_8025d124(0);
  FUN_8025be20(0,0xc);
  FUN_8025be8c(0,0x1c);
  FUN_8025b6f0(0);
  FUN_802581e0(0);
  FUN_8025c2a0(1);
  FUN_80259e58(1);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,0xff,0xff,4);
  FUN_8025ba40(0,0xf,0xf,0xf,0xe);
  FUN_8025bac0(0,7,7,7,6);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_8025c584(1,4,5,5);
  FUN_80070310(1,3,0);
  FUN_800702b8(1);
  FUN_8025bff0(7,0,0,7,0);
  FUN_80258b24(0);
  (**(code **)(*DAT_803dca58 + 0x40))
            (&local_10,(int)&local_10 + 1,(int)&local_10 + 2,auStack24,auStack24,auStack24);
  bVar1 = (char)((int)((local_10 & 0xff0000) >> 0x10) >> 2) + 0x80;
  local_10._0_2_ =
       (ushort)(((uint)(byte)((char)((int)(local_10 >> 0x18) >> 2) + 0x80) << 0x18) >> 0x10) |
       (ushort)bVar1;
  local_10 = CONCAT31(CONCAT21(local_10._0_2_,
                               (char)((int)((CONCAT12(bVar1,(short)local_10) & 0xff00) >> 8) >> 2) +
                               -0x80),0x80);
  local_14 = local_10;
  FUN_8025bdac(0,&local_14);
  return;
}

