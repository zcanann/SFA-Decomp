// Function: FUN_8005009c
// Entry: 8005009c
// Size: 508 bytes

void FUN_8005009c(int param_1)

{
  if (param_1 != 0) {
    FUN_80258674(DAT_803dda08,1,1,0x1e,0,0x7d);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
    FUN_8025c1a4(DAT_803dda10,0xf,10,0xb,8);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dd9b0 = 1;
    if (param_1 != 0) {
      if (*(char *)(param_1 + 0x48) == '\0') {
        FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda08 = DAT_803dda08 + 1;
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,0xff,0xff,5);
    FUN_8025c1a4(DAT_803dda10,0xf,10,0xb,0);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
  }
  return;
}

