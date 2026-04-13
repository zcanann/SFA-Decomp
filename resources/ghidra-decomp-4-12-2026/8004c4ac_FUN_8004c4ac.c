// Function: FUN_8004c4ac
// Entry: 8004c4ac
// Size: 1148 bytes

void FUN_8004c4ac(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  double dVar8;
  undefined8 uVar9;
  undefined4 uStack_50;
  int local_4c;
  undefined4 local_48;
  undefined4 local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  float local_2c;
  
  uVar9 = FUN_80286830();
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  local_40 = DAT_802c25a8;
  local_3c = (float)DAT_802c25ac;
  local_38 = DAT_802c25b0;
  local_34 = DAT_802c25b4;
  local_30 = DAT_802c25b8;
  local_2c = (float)DAT_802c25bc;
  if (DAT_803dd9ac == 0) {
    DAT_803dd9ac = FUN_80054e14(0x20,0x20,4,'\0',0,1,1,1,1);
    uVar7 = 0;
    do {
      uVar6 = 0;
      do {
        iVar1 = DAT_803dd9ac + (uVar7 & 3) * 2;
        uVar3 = FUN_80022264(0x80,0xff);
        uVar4 = FUN_80022264(0,0x40);
        uVar5 = FUN_80022264(0x40,0x80);
        *(ushort *)
         (iVar1 + ((int)uVar7 >> 2) * 0x20 + (uVar6 & 3) * 8 + ((int)uVar6 >> 2) * 0x100 + 0x60) =
             (ushort)((int)(uVar3 & 0xf8) >> 3) |
             (ushort)((uVar3 - uVar4 & 0xf8) << 8) | (ushort)((uVar3 - uVar5 & 0xfc) << 3);
        uVar6 = uVar6 + 1;
      } while ((int)uVar6 < 0x20);
      uVar7 = uVar7 + 1;
    } while ((int)uVar7 < 0x20);
    FUN_802420e0(DAT_803dd9ac + 0x60,*(int *)(DAT_803dd9ac + 0x44));
  }
  FUN_8006cc38(&local_44,&local_48);
  dVar8 = (double)FUN_802945e0();
  local_3c = (float)((double)FLOAT_803df760 * dVar8 + (double)FLOAT_803df75c);
  dVar8 = (double)FUN_802945e0();
  local_2c = (float)((double)FLOAT_803df760 * dVar8 + (double)FLOAT_803df75c);
  FUN_8025c828(DAT_803dda10,0,DAT_803dda0c + 1,8);
  FUN_8025c65c(DAT_803dda10,0,0);
  if ((float *)uVar9 == (float *)0x0) {
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,0x7d);
  }
  else {
    FUN_8025d8c4((float *)uVar9,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,DAT_803dda00);
    DAT_803dda00 = DAT_803dda00 + 3;
  }
  FUN_8025b9e8(1,&local_40,(char)DAT_803dc254);
  FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08,DAT_803dda0c);
  FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,7,1,0,0,0,0,3);
  FUN_8004c104(&DAT_803dc258,'\x01','\0',&local_4c,&uStack_50);
  FUN_8025c584(DAT_803dda10,local_4c);
  FUN_8025c1a4(DAT_803dda10,0xe,8,0xb,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8025c828(DAT_803dda10 + 1,0xff,0xff,0xff);
  FUN_8025be80(DAT_803dda10 + 1);
  FUN_8025c1a4(DAT_803dda10 + 1,2,0,1,0xf);
  FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
  FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  if (iVar2 != 0) {
    if (*(char *)(iVar2 + 0x48) == '\0') {
      FUN_8025b054((uint *)(iVar2 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(iVar2 + 0x20),*(uint **)(iVar2 + 0x40),DAT_803dda0c);
    }
  }
  if (DAT_803dd9ac != 0) {
    if (*(char *)(DAT_803dd9ac + 0x48) == '\0') {
      FUN_8025b054((uint *)(DAT_803dd9ac + 0x20),DAT_803dda0c + 1);
    }
    else {
      FUN_8025aeac((uint *)(DAT_803dd9ac + 0x20),*(uint **)(DAT_803dd9ac + 0x40),DAT_803dda0c + 1);
    }
  }
  DAT_803dd9f8 = DAT_803dd9f8 + 1;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 2;
  DAT_803dda0c = DAT_803dda0c + 2;
  DAT_803dd9ea = DAT_803dd9ea + '\x02';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  DAT_803dd9e8 = DAT_803dd9e8 + '\x01';
  FUN_8028687c();
  return;
}

