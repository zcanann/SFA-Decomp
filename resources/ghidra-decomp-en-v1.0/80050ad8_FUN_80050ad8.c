// Function: FUN_80050ad8
// Entry: 80050ad8
// Size: 848 bytes

void FUN_80050ad8(undefined4 param_1,undefined4 param_2,uint param_3,int param_4)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  undefined8 uVar6;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined auStack88 [44];
  float local_2c;
  undefined4 local_28;
  uint uStack36;
  
  uVar6 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar6 >> 0x20);
  local_70 = DAT_802c1d50;
  local_6c = DAT_802c1d54;
  local_68 = DAT_802c1d58;
  local_64 = DAT_802c1d5c;
  local_60 = DAT_802c1d60;
  local_5c = DAT_802c1d64;
  if ((DAT_803db5e8 & 1) == 0) {
    iVar3 = 0;
  }
  else {
    FUN_8025b284(1,&local_70,0);
    FUN_8025b5b8(DAT_803dcd7c,DAT_803dcd88 + (int)uVar6,DAT_803dcd8c);
    if (param_4 == 0) {
      iVar3 = 1;
    }
    else {
      iVar3 = (param_3 & 0xf) * 4 + 1;
      iVar4 = FUN_800536c0(param_4);
      uVar1 = (uint)*(ushort *)(iVar4 + 10) / ((uint)*(ushort *)(iVar2 + 10) * iVar3);
      if (uVar1 != 0) {
        FUN_8025b3e4(DAT_803dcd7c,*(undefined4 *)(&DAT_8030cedc + uVar1 * 4),
                     *(undefined4 *)(&DAT_8030cedc + uVar1 * 4));
        iVar3 = 0;
      }
    }
    uStack36 = (int)(param_3 & 0xf0) >> 4 ^ 0x80000000;
    local_28 = 0x43300000;
    dVar5 = (double)(FLOAT_803deadc *
                    FLOAT_803deb38 *
                    ((float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803deb30) /
                     FLOAT_803deb3c - FLOAT_803deac8));
    FUN_80247318(dVar5,dVar5,(double)FLOAT_803deacc,auStack88);
    local_2c = FLOAT_803deac8;
    FUN_8025d160(auStack88,DAT_803dcd80,0);
    FUN_80257f10(DAT_803dcd88,1,2,0x1e,0,DAT_803dcd80);
    FUN_80257f10(DAT_803dcd88 + 1,1,3,0x1e,0,DAT_803dcd80);
    FUN_8025b1e8(DAT_803dcd90,DAT_803dcd7c,0,3,5,6,6,0,0,0);
    FUN_8025b1e8(DAT_803dcd90 + 1,DAT_803dcd7c,0,3,9,6,6,1,0,0);
    FUN_8025b1e8(DAT_803dcd90 + 2,DAT_803dcd7c,0,0,0,0,0,1,0,0);
    FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c + 1U | 0x100,0xff);
    FUN_8025b89c(DAT_803dcd90,4);
    FUN_8025c0c4(DAT_803dcd90 + 1,DAT_803dcd88 + 1,DAT_803dcd8c + 1U | 0x100,0xff);
    FUN_8025b89c(DAT_803dcd90 + 1,4);
    if (iVar2 != 0) {
      if (*(char *)(iVar2 + 0x48) == '\0') {
        FUN_8025a8f0(iVar2 + 0x20,DAT_803dcd8c);
      }
      else {
        FUN_8025a748(iVar2 + 0x20,*(undefined4 *)(iVar2 + 0x40));
      }
    }
    DAT_803dcd80 = DAT_803dcd80 + 3;
    DAT_803dcd7c = DAT_803dcd7c + 1;
    DAT_803dcd88 = DAT_803dcd88 + 2;
    DAT_803dcd90 = DAT_803dcd90 + 2;
    DAT_803dcd8c = DAT_803dcd8c + 1;
    DAT_803dcd6a = DAT_803dcd6a + '\x02';
    DAT_803dcd68 = DAT_803dcd68 + '\x01';
    DAT_803dcd69 = DAT_803dcd69 + '\x02';
  }
  FUN_80286128(iVar3);
  return;
}

