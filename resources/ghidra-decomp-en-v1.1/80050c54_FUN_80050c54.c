// Function: FUN_80050c54
// Entry: 80050c54
// Size: 848 bytes

void FUN_80050c54(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4)

{
  int iVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  float local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  float afStack_58 [11];
  float local_2c;
  undefined4 local_28;
  uint uStack_24;
  
  uVar4 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  local_70 = DAT_802c24d0;
  local_6c = DAT_802c24d4;
  local_68 = DAT_802c24d8;
  local_64 = DAT_802c24dc;
  local_60 = DAT_802c24e0;
  local_5c = DAT_802c24e4;
  if ((DAT_803dc248 & 1) != 0) {
    FUN_8025b9e8(1,&local_70,'\0');
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08 + (int)uVar4,DAT_803dda0c);
    if (param_4 != 0) {
      uVar2 = FUN_8005383c(param_4);
      uVar2 = (uint)*(ushort *)(uVar2 + 10) /
              ((uint)*(ushort *)(iVar1 + 10) * ((param_3 & 0xf) * 4 + 1));
      if (uVar2 != 0) {
        FUN_8025bb48(DAT_803dd9fc,*(uint *)(&DAT_8030da9c + uVar2 * 4),
                     *(uint *)(&DAT_8030da9c + uVar2 * 4));
      }
    }
    uStack_24 = (int)(param_3 & 0xf0) >> 4 ^ 0x80000000;
    local_28 = 0x43300000;
    dVar3 = (double)(FLOAT_803df75c *
                    FLOAT_803df7b8 *
                    ((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df7b0) /
                     FLOAT_803df7bc - FLOAT_803df748));
    FUN_80247a7c(dVar3,dVar3,(double)FLOAT_803df74c,afStack_58);
    local_2c = FLOAT_803df748;
    FUN_8025d8c4(afStack_58,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,2,0x1e,0,DAT_803dda00);
    FUN_80258674(DAT_803dda08 + 1,1,3,0x1e,0,DAT_803dda00);
    FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,3,5,6,6,0,0,0);
    FUN_8025b94c(DAT_803dda10 + 1,DAT_803dd9fc,0,3,9,6,6,1,0,0);
    FUN_8025b94c(DAT_803dda10 + 2,DAT_803dd9fc,0,0,0,0,0,1,0,0);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c + 1 | 0x100,0xff);
    FUN_8025c000(DAT_803dda10,4);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c + 1 | 0x100,0xff);
    FUN_8025c000(DAT_803dda10 + 1,4);
    if (iVar1 != 0) {
      if (*(char *)(iVar1 + 0x48) == '\0') {
        FUN_8025b054((uint *)(iVar1 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(iVar1 + 0x20),*(uint **)(iVar1 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda00 = DAT_803dda00 + 3;
    DAT_803dd9fc = DAT_803dd9fc + 1;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x02';
    DAT_803dd9e8 = DAT_803dd9e8 + '\x01';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x02';
  }
  FUN_8028688c();
  return;
}

