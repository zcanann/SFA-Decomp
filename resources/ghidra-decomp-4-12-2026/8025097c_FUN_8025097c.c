// Function: FUN_8025097c
// Entry: 8025097c
// Size: 2324 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_8025097c(void)

{
  ushort uVar1;
  ushort uVar2;
  ushort uVar3;
  ushort uVar4;
  undefined4 uVar5;
  int aiStack_120 [16];
  undefined4 uStack_e0;
  undefined4 uStack_dc;
  undefined4 uStack_d8;
  undefined4 uStack_d4;
  undefined4 uStack_d0;
  undefined4 uStack_cc;
  undefined4 uStack_c8;
  undefined4 uStack_c4;
  int aiStack_a0 [15];
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  
  do {
    uVar1 = DAT_cc005016;
  } while ((uVar1 & 1) == 0);
  DAT_803deca0 = 0x1000000;
  uVar1 = DAT_cc005012;
  DAT_cc005012 = uVar1 & 0xffc0 | 0x23;
  aiStack_a0[0] = -0x21524111;
  uStack_e0 = 0xbad0bad0;
  uVar5 = 0x1000000;
  aiStack_a0[1] = 0xdeadbeef;
  uStack_dc = 0xbad0bad0;
  uVar4 = 3;
  aiStack_a0[2] = 0xdeadbeef;
  uStack_d8 = 0xbad0bad0;
  aiStack_a0[3] = 0xdeadbeef;
  uStack_d4 = 0xbad0bad0;
  aiStack_a0[4] = 0xdeadbeef;
  uStack_d0 = 0xbad0bad0;
  aiStack_a0[5] = 0xdeadbeef;
  uStack_cc = 0xbad0bad0;
  aiStack_a0[6] = 0xdeadbeef;
  uStack_c8 = 0xbad0bad0;
  aiStack_a0[7] = 0xdeadbeef;
  uStack_c4 = 0xbad0bad0;
  FUN_802420e0((uint)aiStack_a0,0x20);
  FUN_802420e0((uint)&uStack_e0,0x20);
  DAT_803deca4 = 0;
  uVar1 = (ushort)((uint)&uStack_e0 >> 0x10);
  uVar2 = (ushort)&uStack_e0;
  uVar3 = DAT_cc005020;
  DAT_cc005020 = uVar3 & 0xfc00 | uVar1;
  uVar3 = DAT_cc005022;
  DAT_cc005022 = uVar3 & 0x1f | uVar2;
  uVar3 = DAT_cc005024;
  DAT_cc005024 = uVar3 & 0xfc00 | 0x100;
  uVar3 = DAT_cc005026;
  DAT_cc005026 = uVar3 & 0x1f;
  uVar3 = DAT_cc005028;
  DAT_cc005028 = uVar3 & 0x7fff;
  uVar3 = DAT_cc005028;
  DAT_cc005028 = uVar3 & 0xfc00;
  uVar3 = DAT_cc00502a;
  DAT_cc00502a = uVar3 & 0x1f | 0x20;
  do {
    uVar3 = DAT_cc00500a;
  } while ((uVar3 & 0x200) != 0);
  uVar3 = DAT_cc00500a;
  DAT_cc00500a = uVar3 & 0xff77 | 0x20;
  uVar3 = DAT_cc005020;
  local_5c = 0x120;
  local_58 = 0;
  DAT_cc005020 = uVar3 & 0xfc00 | uVar1;
  uVar3 = DAT_cc005022;
  DAT_cc005022 = uVar3 & 0x1f | uVar2;
  uVar3 = DAT_cc005024;
  DAT_cc005024 = uVar3 & 0xfc00 | 0x120;
  uVar3 = DAT_cc005026;
  DAT_cc005026 = uVar3 & 0x1f;
  uVar3 = DAT_cc005028;
  DAT_cc005028 = uVar3 & 0x7fff;
  uVar3 = DAT_cc005028;
  DAT_cc005028 = uVar3 & 0xfc00;
  uVar3 = DAT_cc00502a;
  DAT_cc00502a = uVar3 & 0x1f | 0x20;
  do {
    uVar3 = DAT_cc00500a;
  } while ((uVar3 & 0x200) != 0);
  uVar3 = DAT_cc00500a;
  DAT_cc00500a = uVar3 & 0xff77 | 0x20;
  uVar3 = DAT_cc005020;
  local_60 = 0x200;
  local_54 = 0;
  DAT_cc005020 = uVar3 & 0xfc00 | uVar1;
  uVar3 = DAT_cc005022;
  DAT_cc005022 = uVar3 & 0x1f | uVar2;
  uVar3 = DAT_cc005024;
  DAT_cc005024 = uVar3 & 0xfc00 | 0x200;
  uVar3 = DAT_cc005026;
  DAT_cc005026 = uVar3 & 0x1f;
  uVar3 = DAT_cc005028;
  DAT_cc005028 = uVar3 & 0x7fff;
  uVar3 = DAT_cc005028;
  DAT_cc005028 = uVar3 & 0xfc00;
  uVar3 = DAT_cc00502a;
  DAT_cc00502a = uVar3 & 0x1f | 0x20;
  do {
    uVar3 = DAT_cc00500a;
  } while ((uVar3 & 0x200) != 0);
  uVar3 = DAT_cc00500a;
  DAT_cc00500a = uVar3 & 0xff77 | 0x20;
  uVar3 = DAT_cc005020;
  local_64 = 0x100;
  local_50 = 0x200;
  DAT_cc005020 = uVar3 & 0xfc00 | uVar1;
  uVar3 = DAT_cc005022;
  DAT_cc005022 = uVar3 & 0x1f | uVar2;
  uVar3 = DAT_cc005024;
  DAT_cc005024 = uVar3 & 0xfc00 | 0x100;
  uVar3 = DAT_cc005026;
  DAT_cc005026 = uVar3 & 0x1f | 0x200;
  uVar3 = DAT_cc005028;
  DAT_cc005028 = uVar3 & 0x7fff;
  uVar3 = DAT_cc005028;
  DAT_cc005028 = uVar3 & 0xfc00;
  uVar3 = DAT_cc00502a;
  DAT_cc00502a = uVar3 & 0x1f | 0x20;
  do {
    uVar3 = DAT_cc00500a;
  } while ((uVar3 & 0x200) != 0);
  uVar3 = DAT_cc00500a;
  DAT_cc00500a = uVar3 & 0xff77 | 0x20;
  uVar3 = DAT_cc005020;
  DAT_cc005020 = uVar3 & 0xfc00 | uVar1;
  uVar1 = DAT_cc005022;
  DAT_cc005022 = uVar1 & 0x1f | uVar2;
  uVar1 = DAT_cc005024;
  DAT_cc005024 = uVar1 & 0xfc00 | 0x140;
  uVar1 = DAT_cc005026;
  DAT_cc005026 = uVar1 & 0x1f;
  uVar1 = DAT_cc005028;
  DAT_cc005028 = uVar1 & 0x7fff;
  uVar1 = DAT_cc005028;
  DAT_cc005028 = uVar1 & 0xfc00;
  uVar1 = DAT_cc00502a;
  DAT_cc00502a = uVar1 & 0x1f | 0x20;
  do {
    uVar1 = DAT_cc00500a;
  } while ((uVar1 & 0x200) != 0);
  uVar1 = DAT_cc00500a;
  DAT_cc00500a = uVar1 & 0xff77 | 0x20;
  FUN_800033a8((int)aiStack_120,0,0x20);
  FUN_802420e0((uint)aiStack_120,0x20);
  uVar1 = DAT_cc005020;
  DAT_cc005020 = uVar1 & 0xfc00 | (ushort)((uint)aiStack_a0 >> 0x10);
  uVar1 = DAT_cc005022;
  DAT_cc005022 = uVar1 & 0x1f | (ushort)aiStack_a0;
  uVar1 = DAT_cc005024;
  DAT_cc005024 = uVar1 & 0xfc00 | 0x100;
  uVar1 = DAT_cc005026;
  DAT_cc005026 = uVar1 & 0x1f;
  uVar1 = DAT_cc005028;
  DAT_cc005028 = uVar1 & 0x7fff;
  uVar1 = DAT_cc005028;
  DAT_cc005028 = uVar1 & 0xfc00;
  uVar1 = DAT_cc00502a;
  DAT_cc00502a = uVar1 & 0x1f | 0x20;
  do {
    uVar1 = DAT_cc00500a;
  } while ((uVar1 & 0x200) != 0);
  uVar1 = DAT_cc00500a;
  DAT_cc00500a = uVar1 & 0xff77 | 0x20;
  FUN_802420b0((uint)aiStack_120,0x20);
  uVar3 = DAT_cc005020;
  uVar1 = (ushort)((uint)aiStack_120 >> 0x10);
  uVar2 = (ushort)aiStack_120;
  DAT_cc005020 = uVar3 & 0xfc00 | uVar1;
  uVar3 = DAT_cc005022;
  DAT_cc005022 = uVar3 & 0x1f | uVar2;
  uVar3 = DAT_cc005024;
  DAT_cc005024 = uVar3 & 0xfc00 | 0x100;
  uVar3 = DAT_cc005026;
  DAT_cc005026 = uVar3 & 0x1f;
  uVar3 = DAT_cc005028;
  DAT_cc005028 = uVar3 | 0x8000;
  uVar3 = DAT_cc005028;
  DAT_cc005028 = uVar3 & 0xfc00;
  uVar3 = DAT_cc00502a;
  DAT_cc00502a = uVar3 & 0x1f | 0x20;
  do {
    uVar3 = DAT_cc00500a;
  } while ((uVar3 & 0x200) != 0);
  uVar3 = DAT_cc00500a;
  DAT_cc00500a = uVar3 & 0xff77 | 0x20;
  FUN_80240a74();
  if (aiStack_120[0] == aiStack_a0[0]) {
    FUN_800033a8((int)aiStack_120,0,0x20);
    FUN_802420e0((uint)aiStack_120,0x20);
    uVar3 = DAT_cc005020;
    DAT_cc005020 = uVar3 & 0xfc00 | uVar1;
    uVar3 = DAT_cc005022;
    DAT_cc005022 = uVar3 & 0x1f | uVar2;
    uVar3 = DAT_cc005024;
    DAT_cc005024 = uVar3 & 0xfc00 | (ushort)local_5c;
    uVar3 = DAT_cc005026;
    DAT_cc005026 = uVar3 & 0x1f | (ushort)local_58;
    uVar3 = DAT_cc005028;
    DAT_cc005028 = uVar3 | 0x8000;
    uVar3 = DAT_cc005028;
    DAT_cc005028 = uVar3 & 0xfc00;
    uVar3 = DAT_cc00502a;
    DAT_cc00502a = uVar3 & 0x1f | 0x20;
    do {
      uVar3 = DAT_cc00500a;
    } while ((uVar3 & 0x200) != 0);
    uVar3 = DAT_cc00500a;
    DAT_cc00500a = uVar3 & 0xff77 | 0x20;
    FUN_80240a74();
    if (aiStack_120[0] == aiStack_a0[0]) {
      DAT_803deca4 = 0x200000;
      uVar5 = 0x1200000;
    }
    else {
      FUN_800033a8((int)aiStack_120,0,0x20);
      FUN_802420e0((uint)aiStack_120,0x20);
      uVar3 = DAT_cc005020;
      DAT_cc005020 = uVar3 & 0xfc00 | uVar1;
      uVar3 = DAT_cc005022;
      DAT_cc005022 = uVar3 & 0x1f | uVar2;
      uVar3 = DAT_cc005024;
      DAT_cc005024 = uVar3 & 0xfc00 | (ushort)local_60;
      uVar3 = DAT_cc005026;
      DAT_cc005026 = uVar3 & 0x1f | (ushort)local_54;
      uVar3 = DAT_cc005028;
      DAT_cc005028 = uVar3 | 0x8000;
      uVar3 = DAT_cc005028;
      DAT_cc005028 = uVar3 & 0xfc00;
      uVar3 = DAT_cc00502a;
      DAT_cc00502a = uVar3 & 0x1f | 0x20;
      do {
        uVar3 = DAT_cc00500a;
      } while ((uVar3 & 0x200) != 0);
      uVar3 = DAT_cc00500a;
      DAT_cc00500a = uVar3 & 0xff77 | 0x20;
      FUN_80240a74();
      if (aiStack_120[0] == aiStack_a0[0]) {
        DAT_803deca4 = 0x400000;
        uVar4 = 0xb;
        uVar5 = 0x1400000;
      }
      else {
        FUN_800033a8((int)aiStack_120,0,0x20);
        FUN_802420e0((uint)aiStack_120,0x20);
        uVar3 = DAT_cc005020;
        DAT_cc005020 = uVar3 & 0xfc00 | uVar1;
        uVar3 = DAT_cc005022;
        DAT_cc005022 = uVar3 & 0x1f | uVar2;
        uVar3 = DAT_cc005024;
        DAT_cc005024 = uVar3 & 0xfc00 | (ushort)local_64;
        uVar3 = DAT_cc005026;
        DAT_cc005026 = uVar3 & 0x1f | (ushort)local_50;
        uVar3 = DAT_cc005028;
        DAT_cc005028 = uVar3 | 0x8000;
        uVar3 = DAT_cc005028;
        DAT_cc005028 = uVar3 & 0xfc00;
        uVar3 = DAT_cc00502a;
        DAT_cc00502a = uVar3 & 0x1f | 0x20;
        do {
          uVar3 = DAT_cc00500a;
        } while ((uVar3 & 0x200) != 0);
        uVar3 = DAT_cc00500a;
        DAT_cc00500a = uVar3 & 0xff77 | 0x20;
        FUN_80240a74();
        if (aiStack_120[0] == aiStack_a0[0]) {
          DAT_803deca4 = 0x800000;
          uVar4 = 0x13;
          uVar5 = 0x1800000;
        }
        else {
          FUN_800033a8((int)aiStack_120,0,0x20);
          FUN_802420e0((uint)aiStack_120,0x20);
          uVar3 = DAT_cc005020;
          DAT_cc005020 = uVar3 & 0xfc00 | uVar1;
          uVar1 = DAT_cc005022;
          DAT_cc005022 = uVar1 & 0x1f | uVar2;
          uVar1 = DAT_cc005024;
          DAT_cc005024 = uVar1 & 0xfc00 | 0x140;
          uVar1 = DAT_cc005026;
          DAT_cc005026 = uVar1 & 0x1f;
          uVar1 = DAT_cc005028;
          DAT_cc005028 = uVar1 | 0x8000;
          uVar1 = DAT_cc005028;
          DAT_cc005028 = uVar1 & 0xfc00;
          uVar1 = DAT_cc00502a;
          DAT_cc00502a = uVar1 & 0x1f | 0x20;
          do {
            uVar1 = DAT_cc00500a;
          } while ((uVar1 & 0x200) != 0);
          uVar1 = DAT_cc00500a;
          DAT_cc00500a = uVar1 & 0xff77 | 0x20;
          FUN_80240a74();
          if (aiStack_120[0] == aiStack_a0[0]) {
            DAT_803deca4 = 0x1000000;
            uVar4 = 0x1b;
            uVar5 = 0x2000000;
          }
          else {
            DAT_803deca4 = 0x2000000;
            uVar4 = 0x23;
            uVar5 = 0x3000000;
          }
        }
      }
    }
    uVar1 = DAT_cc005012;
    DAT_cc005012 = uVar1 & 0xffc0 | uVar4;
  }
  _DAT_c00000d0 = uVar5;
  DAT_803dec9c = uVar5;
  return;
}

