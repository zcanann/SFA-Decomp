// Function: FUN_80207948
// Entry: 80207948
// Size: 492 bytes

void FUN_80207948(void)

{
  uint uVar1;
  char cVar5;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar6;
  undefined4 local_28;
  undefined4 local_24;
  
  uVar6 = FUN_802860dc();
  iVar4 = (int)((ulonglong)uVar6 >> 0x20);
  local_28 = DAT_803e6450;
  local_24 = DAT_803e6454;
  cVar5 = FUN_8002e04c();
  if (cVar5 == '\0') {
    uVar2 = 0;
  }
  else {
    uVar1 = (uint)uVar6 & 0xff;
    if ((&DAT_803ad138)[uVar1 * 2] == 0) {
      iVar3 = FUN_8002bdf4(0x2c,0x6e8);
      *(undefined *)(iVar3 + 6) = 0xff;
      *(undefined *)(iVar3 + 7) = 0xff;
      *(undefined *)(iVar3 + 4) = 2;
      *(undefined *)(iVar3 + 5) = 1;
      *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar4 + 0x14);
      *(undefined2 *)(iVar3 + 0x24) = 0xffff;
      *(undefined *)(iVar3 + 0x1a) = 0;
      *(undefined *)(iVar3 + 0x18) = 0;
      *(undefined *)(iVar3 + 0x19) = 0;
      cVar5 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar4 + 0xac));
      if (cVar5 == '\x02') {
        *(char *)(iVar3 + 0x1b) = (char)*(undefined2 *)((int)&local_28 + uVar1 * 2);
      }
      else {
        *(char *)(iVar3 + 0x1b) = (char)local_24;
      }
      *(undefined *)(iVar3 + 0x1c) = 0;
      *(undefined *)(iVar3 + 0x1d) = 0;
      *(undefined *)(iVar3 + 0x26) = 100;
      *(undefined *)(iVar3 + 0x27) = 0;
      *(undefined *)(iVar3 + 0x28) = 0;
      *(float *)(iVar3 + 0x20) = FLOAT_803e6478;
      *(undefined *)(iVar3 + 0x29) = 0xd2;
      *(undefined *)(iVar3 + 0x2a) = 0;
      uVar2 = FUN_8002df90(iVar3,5,(int)*(char *)(iVar4 + 0xac),0xffffffff,
                           *(undefined4 *)(iVar4 + 0x30));
      (&DAT_803ad138)[uVar1 * 2] = uVar2;
    }
    if ((&DAT_803ad13c)[uVar1 * 2] == 0) {
      iVar3 = FUN_8002bdf4(4,0x71c);
      *(undefined *)(iVar3 + 6) = 0xff;
      *(undefined *)(iVar3 + 7) = 0xff;
      *(undefined *)(iVar3 + 4) = 2;
      *(undefined *)(iVar3 + 5) = 1;
      *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar4 + 0x14);
      iVar4 = FUN_8002df90(iVar3,5,(int)*(char *)(iVar4 + 0xac),0xffffffff,
                           *(undefined4 *)(iVar4 + 0x30));
      (&DAT_803ad13c)[uVar1 * 2] = iVar4;
    }
    uVar2 = 1;
  }
  FUN_80286128(uVar2);
  return;
}

