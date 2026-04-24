// Function: FUN_80116224
// Entry: 80116224
// Size: 920 bytes

void FUN_80116224(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_28;
  int local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14 [3];
  
  DAT_803dd619 = 1;
  iVar1 = FUN_80119338(2);
  if (iVar1 != 0) {
    iVar1 = FUN_80119000(s_starfox_thp_8031a32c,0);
    if (iVar1 == 0) {
      FUN_801192ec();
    }
    else {
      FUN_801181f8(&DAT_803dd638);
      DAT_803dd644 = (uint)*(ushort *)(DAT_803dccf0 + 4) - DAT_803dd638 >> 1;
      DAT_803dd640 = (uint)*(ushort *)(DAT_803dccf0 + 6) - iRam803dd63c >> 1;
      FUN_80118eac(local_14,&local_18,&local_1c,&local_20,&local_24,&local_28);
      DAT_803dd634 = FUN_80023cc8(local_14[0],0x18,0);
      DAT_803dd630 = FUN_80023cc8(local_18,0x18,0);
      DAT_803dd62c = FUN_80023cc8(local_1c,0x18,0);
      DAT_803dd628 = FUN_80023cc8(local_20,0x18,0);
      if (local_24 == 0) {
        DAT_803dd624 = 0;
      }
      else {
        DAT_803dd624 = FUN_80023cc8(local_24,0x18,0);
      }
      DAT_803dd620 = FUN_80023cc8(local_28,0x18,0);
      DAT_803dd61c = FUN_80023cc8(0x4000,0x18,0);
      if (((((DAT_803dd634 == 0) || (DAT_803dd630 == 0)) || (DAT_803dd62c == 0)) ||
          ((DAT_803dd628 == 0 || ((DAT_803dd624 == 0 && (local_24 != 0)))))) ||
         ((DAT_803dd620 == 0 || (DAT_803dd61c == 0)))) {
        FUN_801192ec();
        uVar2 = FUN_80023834(0);
        if (DAT_803dd634 != 0) {
          FUN_80023800();
          DAT_803dd634 = 0;
        }
        if (DAT_803dd630 != 0) {
          FUN_80023800();
          DAT_803dd630 = 0;
        }
        if (DAT_803dd62c != 0) {
          FUN_80023800();
          DAT_803dd62c = 0;
        }
        if (DAT_803dd628 != 0) {
          FUN_80023800();
          DAT_803dd628 = 0;
        }
        if (DAT_803dd624 != 0) {
          FUN_80023800();
          DAT_803dd624 = 0;
        }
        if (DAT_803dd620 != 0) {
          FUN_80023800();
          DAT_803dd620 = 0;
        }
        if (DAT_803dd61c != 0) {
          FUN_80023800();
          DAT_803dd61c = 0;
        }
        FUN_80023834(uVar2);
        FUN_8007d6dc(s__________________malloc_for_movi_8031a338);
        FUN_80022d58(1);
        FUN_80041e3c(0);
        FUN_8007d6dc(s__________________RESTRUCT_for_mo_8031a364);
        FUN_80022d58(1);
      }
      else {
        DAT_803dd619 = 0;
        FUN_802419b8(DAT_803dd634,local_14[0]);
        FUN_802419b8(DAT_803dd630,local_18);
        FUN_802419b8(DAT_803dd62c,local_1c);
        FUN_802419b8(DAT_803dd628,local_20);
        if (DAT_803dd624 != 0) {
          FUN_802419b8(DAT_803dd624,local_24);
        }
        FUN_802419b8(DAT_803dd620,local_28);
        FUN_802419b8(DAT_803dd61c,0x4000);
        FUN_80118c88(DAT_803dd634,DAT_803dd630,DAT_803dd62c,DAT_803dd628,DAT_803dd624,DAT_803dd620);
        iVar1 = FUN_80118960(0,1);
        if (iVar1 == 0) {
          FUN_802428c8(s_n_attractmode_c_8031a38c,0x2fb,s_Fail_to_prepare_8031a39c);
        }
        FUN_80118900();
        DAT_803dd610 = 2;
        FUN_8024c8f0();
        DAT_803dd64d = 10;
        DAT_803dd698 = 0;
        if (DAT_803dd614 == '\x04') {
          FUN_80117b68(100,1);
        }
        else {
          FUN_80117b68(0,1);
        }
      }
    }
  }
  return;
}

