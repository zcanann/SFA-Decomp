// Function: FUN_8000e964
// Entry: 8000e964
// Size: 308 bytes

void FUN_8000e964(void)

{
  undefined2 uVar1;
  undefined2 uVar2;
  uint uVar3;
  uint uVar4;
  
  DAT_803dd50d = 4;
  uVar3 = FUN_80070050();
  if ((*(uint *)(&DAT_802c65b0 + (uint)DAT_803dd50d * 0x34) & 1) == 0) {
    FUN_8005524c(0,0,0,0,(uVar3 & 0xffff) - 1,(uVar3 >> 0x10) - 1);
    uVar4 = (uint)DAT_803dd50d;
    if ((*(uint *)(&DAT_802c65b0 + uVar4 * 0x34) & 1) == 0) {
      uVar1 = (undefined2)(((uVar3 & 0xffff) >> 1) << 2);
      (&DAT_802c6658)[uVar4 * 8] = uVar1;
      uVar2 = (undefined2)((uVar3 >> 0x11) << 2);
      (&DAT_802c665a)[uVar4 * 8] = uVar2;
      (&DAT_802c6650)[uVar4 * 8] = uVar1;
      (&DAT_802c6652)[uVar4 * 8] = uVar2;
    }
  }
  else {
    FUN_8000f0d8();
    uVar3 = (uint)DAT_803dd50d;
    if ((*(uint *)(&DAT_802c65b0 + uVar3 * 0x34) & 1) == 0) {
      (&DAT_802c6658)[uVar3 * 8] = 0;
      (&DAT_802c665a)[uVar3 * 8] = 0;
      (&DAT_802c6650)[uVar3 * 8] = 0;
      (&DAT_802c6652)[uVar3 * 8] = 0;
    }
  }
  DAT_803dd50d = 0;
  return;
}

