// Function: FUN_80250218
// Entry: 80250218
// Size: 2324 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80250218(void)

{
  ushort uVar1;
  ushort uVar2;
  ushort uVar3;
  ushort uVar4;
  undefined4 uVar5;
  int aiStack288 [16];
  undefined4 uStack224;
  undefined4 uStack220;
  undefined4 uStack216;
  undefined4 uStack212;
  undefined4 uStack208;
  undefined4 uStack204;
  undefined4 uStack200;
  undefined4 uStack196;
  int iStack160;
  undefined4 uStack156;
  undefined4 uStack152;
  undefined4 uStack148;
  undefined4 uStack144;
  undefined4 uStack140;
  undefined4 uStack136;
  undefined4 uStack132;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  
  do {
    uVar1 = read_volatile_2(DAT_cc005016);
  } while ((uVar1 & 1) == 0);
  DAT_803de020 = 0x1000000;
  uVar1 = read_volatile_2(DAT_cc005012);
  write_volatile_2(DAT_cc005012,uVar1 & 0xffc0 | 0x23);
  iStack160 = -0x21524111;
  uStack224 = 0xbad0bad0;
  uVar5 = 0x1000000;
  uStack156 = 0xdeadbeef;
  uStack220 = 0xbad0bad0;
  uVar4 = 3;
  uStack152 = 0xdeadbeef;
  uStack216 = 0xbad0bad0;
  uStack148 = 0xdeadbeef;
  uStack212 = 0xbad0bad0;
  uStack144 = 0xdeadbeef;
  uStack208 = 0xbad0bad0;
  uStack140 = 0xdeadbeef;
  uStack204 = 0xbad0bad0;
  uStack136 = 0xdeadbeef;
  uStack200 = 0xbad0bad0;
  uStack132 = 0xdeadbeef;
  uStack196 = 0xbad0bad0;
  FUN_802419e8(&iStack160,0x20);
  FUN_802419e8(&uStack224,0x20);
  DAT_803de024 = 0;
  uVar3 = (ushort)&uStack224;
  uVar2 = read_volatile_2(DAT_cc005020);
  uVar1 = (ushort)((uint)&uStack224 >> 0x10);
  write_volatile_2(DAT_cc005020,uVar2 & 0xfc00 | uVar1);
  uVar2 = read_volatile_2(DAT_cc005022);
  write_volatile_2(DAT_cc005022,uVar2 & 0x1f | uVar3);
  uVar2 = read_volatile_2(DAT_cc005024);
  write_volatile_2(DAT_cc005024,uVar2 & 0xfc00 | 0x100);
  uVar2 = read_volatile_2(DAT_cc005026);
  write_volatile_2(DAT_cc005026,uVar2 & 0x1f);
  uVar2 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar2 & 0x7fff);
  uVar2 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar2 & 0xfc00);
  uVar2 = read_volatile_2(DAT_cc00502a);
  write_volatile_2(DAT_cc00502a,uVar2 & 0x1f | 0x20);
  do {
    uVar2 = read_volatile_2(DAT_cc00500a);
  } while ((uVar2 & 0x200) != 0);
  uVar2 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar2 & 0xff77 | 0x20);
  uVar2 = read_volatile_2(DAT_cc005020);
  local_5c = 0x120;
  local_58 = 0;
  write_volatile_2(DAT_cc005020,uVar2 & 0xfc00 | uVar1);
  uVar2 = read_volatile_2(DAT_cc005022);
  write_volatile_2(DAT_cc005022,uVar2 & 0x1f | uVar3);
  uVar2 = read_volatile_2(DAT_cc005024);
  write_volatile_2(DAT_cc005024,uVar2 & 0xfc00 | 0x120);
  uVar2 = read_volatile_2(DAT_cc005026);
  write_volatile_2(DAT_cc005026,uVar2 & 0x1f);
  uVar2 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar2 & 0x7fff);
  uVar2 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar2 & 0xfc00);
  uVar2 = read_volatile_2(DAT_cc00502a);
  write_volatile_2(DAT_cc00502a,uVar2 & 0x1f | 0x20);
  do {
    uVar2 = read_volatile_2(DAT_cc00500a);
  } while ((uVar2 & 0x200) != 0);
  uVar2 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar2 & 0xff77 | 0x20);
  uVar2 = read_volatile_2(DAT_cc005020);
  local_60 = 0x200;
  local_54 = 0;
  write_volatile_2(DAT_cc005020,uVar2 & 0xfc00 | uVar1);
  uVar2 = read_volatile_2(DAT_cc005022);
  write_volatile_2(DAT_cc005022,uVar2 & 0x1f | uVar3);
  uVar2 = read_volatile_2(DAT_cc005024);
  write_volatile_2(DAT_cc005024,uVar2 & 0xfc00 | 0x200);
  uVar2 = read_volatile_2(DAT_cc005026);
  write_volatile_2(DAT_cc005026,uVar2 & 0x1f);
  uVar2 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar2 & 0x7fff);
  uVar2 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar2 & 0xfc00);
  uVar2 = read_volatile_2(DAT_cc00502a);
  write_volatile_2(DAT_cc00502a,uVar2 & 0x1f | 0x20);
  do {
    uVar2 = read_volatile_2(DAT_cc00500a);
  } while ((uVar2 & 0x200) != 0);
  uVar2 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar2 & 0xff77 | 0x20);
  uVar2 = read_volatile_2(DAT_cc005020);
  local_64 = 0x100;
  local_50 = 0x200;
  write_volatile_2(DAT_cc005020,uVar2 & 0xfc00 | uVar1);
  uVar2 = read_volatile_2(DAT_cc005022);
  write_volatile_2(DAT_cc005022,uVar2 & 0x1f | uVar3);
  uVar2 = read_volatile_2(DAT_cc005024);
  write_volatile_2(DAT_cc005024,uVar2 & 0xfc00 | 0x100);
  uVar2 = read_volatile_2(DAT_cc005026);
  write_volatile_2(DAT_cc005026,uVar2 & 0x1f | 0x200);
  uVar2 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar2 & 0x7fff);
  uVar2 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar2 & 0xfc00);
  uVar2 = read_volatile_2(DAT_cc00502a);
  write_volatile_2(DAT_cc00502a,uVar2 & 0x1f | 0x20);
  do {
    uVar2 = read_volatile_2(DAT_cc00500a);
  } while ((uVar2 & 0x200) != 0);
  uVar2 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar2 & 0xff77 | 0x20);
  uVar2 = read_volatile_2(DAT_cc005020);
  write_volatile_2(DAT_cc005020,uVar2 & 0xfc00 | uVar1);
  uVar1 = read_volatile_2(DAT_cc005022);
  write_volatile_2(DAT_cc005022,uVar1 & 0x1f | uVar3);
  uVar1 = read_volatile_2(DAT_cc005024);
  write_volatile_2(DAT_cc005024,uVar1 & 0xfc00 | 0x140);
  uVar1 = read_volatile_2(DAT_cc005026);
  write_volatile_2(DAT_cc005026,uVar1 & 0x1f);
  uVar1 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar1 & 0x7fff);
  uVar1 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar1 & 0xfc00);
  uVar1 = read_volatile_2(DAT_cc00502a);
  write_volatile_2(DAT_cc00502a,uVar1 & 0x1f | 0x20);
  do {
    uVar1 = read_volatile_2(DAT_cc00500a);
  } while ((uVar1 & 0x200) != 0);
  uVar1 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar1 & 0xff77 | 0x20);
  FUN_800033a8(aiStack288,0,0x20);
  FUN_802419e8(aiStack288,0x20);
  uVar1 = read_volatile_2(DAT_cc005020);
  write_volatile_2(DAT_cc005020,uVar1 & 0xfc00 | (ushort)((uint)&iStack160 >> 0x10));
  uVar1 = read_volatile_2(DAT_cc005022);
  write_volatile_2(DAT_cc005022,uVar1 & 0x1f | (ushort)&iStack160);
  uVar1 = read_volatile_2(DAT_cc005024);
  write_volatile_2(DAT_cc005024,uVar1 & 0xfc00 | 0x100);
  uVar1 = read_volatile_2(DAT_cc005026);
  write_volatile_2(DAT_cc005026,uVar1 & 0x1f);
  uVar1 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar1 & 0x7fff);
  uVar1 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar1 & 0xfc00);
  uVar1 = read_volatile_2(DAT_cc00502a);
  write_volatile_2(DAT_cc00502a,uVar1 & 0x1f | 0x20);
  do {
    uVar1 = read_volatile_2(DAT_cc00500a);
  } while ((uVar1 & 0x200) != 0);
  uVar1 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar1 & 0xff77 | 0x20);
  FUN_802419b8(aiStack288,0x20);
  uVar2 = read_volatile_2(DAT_cc005020);
  uVar3 = (ushort)aiStack288;
  uVar1 = (ushort)((uint)aiStack288 >> 0x10);
  write_volatile_2(DAT_cc005020,uVar2 & 0xfc00 | uVar1);
  uVar2 = read_volatile_2(DAT_cc005022);
  write_volatile_2(DAT_cc005022,uVar2 & 0x1f | uVar3);
  uVar2 = read_volatile_2(DAT_cc005024);
  write_volatile_2(DAT_cc005024,uVar2 & 0xfc00 | 0x100);
  uVar2 = read_volatile_2(DAT_cc005026);
  write_volatile_2(DAT_cc005026,uVar2 & 0x1f);
  uVar2 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar2 | 0x8000);
  uVar2 = read_volatile_2(DAT_cc005028);
  write_volatile_2(DAT_cc005028,uVar2 & 0xfc00);
  uVar2 = read_volatile_2(DAT_cc00502a);
  write_volatile_2(DAT_cc00502a,uVar2 & 0x1f | 0x20);
  do {
    uVar2 = read_volatile_2(DAT_cc00500a);
  } while ((uVar2 & 0x200) != 0);
  uVar2 = read_volatile_2(DAT_cc00500a);
  write_volatile_2(DAT_cc00500a,uVar2 & 0xff77 | 0x20);
  FUN_8024037c();
  if (aiStack288[0] == iStack160) {
    FUN_800033a8(aiStack288,0,0x20);
    FUN_802419e8(aiStack288,0x20);
    uVar2 = read_volatile_2(DAT_cc005020);
    write_volatile_2(DAT_cc005020,uVar2 & 0xfc00 | uVar1);
    uVar2 = read_volatile_2(DAT_cc005022);
    write_volatile_2(DAT_cc005022,uVar2 & 0x1f | uVar3);
    uVar2 = read_volatile_2(DAT_cc005024);
    write_volatile_2(DAT_cc005024,uVar2 & 0xfc00 | (ushort)local_5c);
    uVar2 = read_volatile_2(DAT_cc005026);
    write_volatile_2(DAT_cc005026,uVar2 & 0x1f | (ushort)local_58);
    uVar2 = read_volatile_2(DAT_cc005028);
    write_volatile_2(DAT_cc005028,uVar2 | 0x8000);
    uVar2 = read_volatile_2(DAT_cc005028);
    write_volatile_2(DAT_cc005028,uVar2 & 0xfc00);
    uVar2 = read_volatile_2(DAT_cc00502a);
    write_volatile_2(DAT_cc00502a,uVar2 & 0x1f | 0x20);
    do {
      uVar2 = read_volatile_2(DAT_cc00500a);
    } while ((uVar2 & 0x200) != 0);
    uVar2 = read_volatile_2(DAT_cc00500a);
    write_volatile_2(DAT_cc00500a,uVar2 & 0xff77 | 0x20);
    FUN_8024037c();
    if (aiStack288[0] == iStack160) {
      DAT_803de024 = 0x200000;
      uVar5 = 0x1200000;
    }
    else {
      FUN_800033a8(aiStack288,0,0x20);
      FUN_802419e8(aiStack288,0x20);
      uVar2 = read_volatile_2(DAT_cc005020);
      write_volatile_2(DAT_cc005020,uVar2 & 0xfc00 | uVar1);
      uVar2 = read_volatile_2(DAT_cc005022);
      write_volatile_2(DAT_cc005022,uVar2 & 0x1f | uVar3);
      uVar2 = read_volatile_2(DAT_cc005024);
      write_volatile_2(DAT_cc005024,uVar2 & 0xfc00 | (ushort)local_60);
      uVar2 = read_volatile_2(DAT_cc005026);
      write_volatile_2(DAT_cc005026,uVar2 & 0x1f | (ushort)local_54);
      uVar2 = read_volatile_2(DAT_cc005028);
      write_volatile_2(DAT_cc005028,uVar2 | 0x8000);
      uVar2 = read_volatile_2(DAT_cc005028);
      write_volatile_2(DAT_cc005028,uVar2 & 0xfc00);
      uVar2 = read_volatile_2(DAT_cc00502a);
      write_volatile_2(DAT_cc00502a,uVar2 & 0x1f | 0x20);
      do {
        uVar2 = read_volatile_2(DAT_cc00500a);
      } while ((uVar2 & 0x200) != 0);
      uVar2 = read_volatile_2(DAT_cc00500a);
      write_volatile_2(DAT_cc00500a,uVar2 & 0xff77 | 0x20);
      FUN_8024037c();
      if (aiStack288[0] == iStack160) {
        DAT_803de024 = 0x400000;
        uVar4 = 0xb;
        uVar5 = 0x1400000;
      }
      else {
        FUN_800033a8(aiStack288,0,0x20);
        FUN_802419e8(aiStack288,0x20);
        uVar2 = read_volatile_2(DAT_cc005020);
        write_volatile_2(DAT_cc005020,uVar2 & 0xfc00 | uVar1);
        uVar2 = read_volatile_2(DAT_cc005022);
        write_volatile_2(DAT_cc005022,uVar2 & 0x1f | uVar3);
        uVar2 = read_volatile_2(DAT_cc005024);
        write_volatile_2(DAT_cc005024,uVar2 & 0xfc00 | (ushort)local_64);
        uVar2 = read_volatile_2(DAT_cc005026);
        write_volatile_2(DAT_cc005026,uVar2 & 0x1f | (ushort)local_50);
        uVar2 = read_volatile_2(DAT_cc005028);
        write_volatile_2(DAT_cc005028,uVar2 | 0x8000);
        uVar2 = read_volatile_2(DAT_cc005028);
        write_volatile_2(DAT_cc005028,uVar2 & 0xfc00);
        uVar2 = read_volatile_2(DAT_cc00502a);
        write_volatile_2(DAT_cc00502a,uVar2 & 0x1f | 0x20);
        do {
          uVar2 = read_volatile_2(DAT_cc00500a);
        } while ((uVar2 & 0x200) != 0);
        uVar2 = read_volatile_2(DAT_cc00500a);
        write_volatile_2(DAT_cc00500a,uVar2 & 0xff77 | 0x20);
        FUN_8024037c();
        if (aiStack288[0] == iStack160) {
          DAT_803de024 = 0x800000;
          uVar4 = 0x13;
          uVar5 = 0x1800000;
        }
        else {
          FUN_800033a8(aiStack288,0,0x20);
          FUN_802419e8(aiStack288,0x20);
          uVar2 = read_volatile_2(DAT_cc005020);
          write_volatile_2(DAT_cc005020,uVar2 & 0xfc00 | uVar1);
          uVar1 = read_volatile_2(DAT_cc005022);
          write_volatile_2(DAT_cc005022,uVar1 & 0x1f | uVar3);
          uVar1 = read_volatile_2(DAT_cc005024);
          write_volatile_2(DAT_cc005024,uVar1 & 0xfc00 | 0x140);
          uVar1 = read_volatile_2(DAT_cc005026);
          write_volatile_2(DAT_cc005026,uVar1 & 0x1f);
          uVar1 = read_volatile_2(DAT_cc005028);
          write_volatile_2(DAT_cc005028,uVar1 | 0x8000);
          uVar1 = read_volatile_2(DAT_cc005028);
          write_volatile_2(DAT_cc005028,uVar1 & 0xfc00);
          uVar1 = read_volatile_2(DAT_cc00502a);
          write_volatile_2(DAT_cc00502a,uVar1 & 0x1f | 0x20);
          do {
            uVar1 = read_volatile_2(DAT_cc00500a);
          } while ((uVar1 & 0x200) != 0);
          uVar1 = read_volatile_2(DAT_cc00500a);
          write_volatile_2(DAT_cc00500a,uVar1 & 0xff77 | 0x20);
          FUN_8024037c();
          if (aiStack288[0] == iStack160) {
            DAT_803de024 = 0x1000000;
            uVar4 = 0x1b;
            uVar5 = 0x2000000;
          }
          else {
            DAT_803de024 = 0x2000000;
            uVar4 = 0x23;
            uVar5 = 0x3000000;
          }
        }
      }
    }
    uVar1 = read_volatile_2(DAT_cc005012);
    write_volatile_2(DAT_cc005012,uVar1 & 0xffc0 | uVar4);
  }
  DAT_803de01c = uVar5;
  _DAT_c00000d0 = uVar5;
  return;
}

