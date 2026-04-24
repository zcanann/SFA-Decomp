// Function: FUN_8004c330
// Entry: 8004c330
// Size: 1148 bytes

void FUN_8004c330(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  double dVar8;
  undefined8 uVar9;
  undefined auStack80 [4];
  undefined4 local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  float local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  float local_2c;
  
  uVar9 = FUN_802860cc();
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  local_40 = DAT_802c1e28;
  local_3c = (float)DAT_802c1e2c;
  local_38 = DAT_802c1e30;
  local_34 = DAT_802c1e34;
  local_30 = DAT_802c1e38;
  local_2c = (float)DAT_802c1e3c;
  if (DAT_803dcd2c == 0) {
    DAT_803dcd2c = FUN_80054c98(0x20,0x20,4,0,0,1,1,1,1);
    uVar7 = 0;
    do {
      uVar6 = 0;
      do {
        iVar1 = DAT_803dcd2c + (uVar7 & 3) * 2;
        uVar3 = FUN_800221a0(0x80,0xff);
        iVar4 = FUN_800221a0(0,0x40);
        iVar5 = FUN_800221a0(0x40,0x80);
        *(ushort *)
         (iVar1 + ((int)uVar7 >> 2) * 0x20 + (uVar6 & 3) * 8 + ((int)uVar6 >> 2) * 0x100 + 0x60) =
             (ushort)((int)(uVar3 & 0xf8) >> 3) |
             (ushort)((uVar3 - iVar4 & 0xf8) << 8) | (ushort)((uVar3 - iVar5 & 0xfc) << 3);
        uVar6 = uVar6 + 1;
      } while ((int)uVar6 < 0x20);
      uVar7 = uVar7 + 1;
    } while ((int)uVar7 < 0x20);
    FUN_802419e8(DAT_803dcd2c + 0x60,*(undefined4 *)(DAT_803dcd2c + 0x44));
  }
  FUN_8006cabc(&local_44,&local_48);
  dVar8 = (double)FUN_80293e80((double)(FLOAT_803dead8 * local_44));
  local_3c = (float)((double)FLOAT_803deae0 * dVar8 + (double)FLOAT_803deadc);
  dVar8 = (double)FUN_80293e80((double)(FLOAT_803dead8 * local_48));
  local_2c = (float)((double)FLOAT_803deae0 * dVar8 + (double)FLOAT_803deadc);
  FUN_8025c0c4(DAT_803dcd90,0,DAT_803dcd8c + 1,8);
  FUN_8025bef8(DAT_803dcd90,0,0);
  if ((int)uVar9 == 0) {
    FUN_80257f10(DAT_803dcd88,1,DAT_803dcd78,0x3c,0,0x7d);
  }
  else {
    FUN_8025d160((int)uVar9,DAT_803dcd80,0);
    FUN_80257f10(DAT_803dcd88,1,DAT_803dcd78,0x3c,0,DAT_803dcd80);
    DAT_803dcd80 = DAT_803dcd80 + 3;
  }
  FUN_8025b284(1,&local_40,(int)(char)DAT_803db5f4);
  FUN_8025b5b8(DAT_803dcd7c,DAT_803dcd88,DAT_803dcd8c);
  FUN_8025b1e8(DAT_803dcd90,DAT_803dcd7c,0,7,1,0,0,0,0,3);
  FUN_8004bf88(&DAT_803db5f8,1,0,&local_4c,auStack80);
  FUN_8025be20(DAT_803dcd90,local_4c);
  FUN_8025ba40(DAT_803dcd90,0xe,8,0xb,0xf);
  FUN_8025bac0(DAT_803dcd90,7,7,7,0);
  FUN_8025bb44(DAT_803dcd90,0,0,0,1,1);
  FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
  FUN_8025c0c4(DAT_803dcd90 + 1,0xff,0xff,0xff);
  FUN_8025b71c(DAT_803dcd90 + 1);
  FUN_8025ba40(DAT_803dcd90 + 1,2,0,1,0xf);
  FUN_8025bac0(DAT_803dcd90 + 1,7,7,7,0);
  FUN_8025bb44(DAT_803dcd90 + 1,0,0,0,1,0);
  FUN_8025bc04(DAT_803dcd90 + 1,0,0,0,1,0);
  DAT_803dcd30 = 1;
  if (iVar2 != 0) {
    if (*(char *)(iVar2 + 0x48) == '\0') {
      FUN_8025a8f0(iVar2 + 0x20,DAT_803dcd8c);
    }
    else {
      FUN_8025a748(iVar2 + 0x20,*(undefined4 *)(iVar2 + 0x40));
    }
  }
  if (DAT_803dcd2c != 0) {
    if (*(char *)(DAT_803dcd2c + 0x48) == '\0') {
      FUN_8025a8f0(DAT_803dcd2c + 0x20,DAT_803dcd8c + 1);
    }
    else {
      FUN_8025a748(DAT_803dcd2c + 0x20,*(undefined4 *)(DAT_803dcd2c + 0x40));
    }
  }
  DAT_803dcd78 = DAT_803dcd78 + 1;
  DAT_803dcd88 = DAT_803dcd88 + 1;
  DAT_803dcd90 = DAT_803dcd90 + 2;
  DAT_803dcd8c = DAT_803dcd8c + 2;
  DAT_803dcd6a = DAT_803dcd6a + '\x02';
  DAT_803dcd69 = DAT_803dcd69 + '\x01';
  DAT_803dcd68 = DAT_803dcd68 + '\x01';
  FUN_80286118();
  return;
}

