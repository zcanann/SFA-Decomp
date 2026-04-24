// Function: FUN_8000e944
// Entry: 8000e944
// Size: 308 bytes

void FUN_8000e944(undefined4 param_1)

{
  undefined2 uVar1;
  undefined2 uVar2;
  uint uVar3;
  uint uVar4;
  
  DAT_803dc88d = 4;
  uVar3 = FUN_8006fed4();
  if ((*(uint *)(&DAT_802c5e30 + (uint)DAT_803dc88d * 0x34) & 1) == 0) {
    FUN_800550d0(0,0,0,0,(uVar3 & 0xffff) - 1,(uVar3 >> 0x10) - 1);
    uVar4 = (uint)DAT_803dc88d;
    if ((*(uint *)(&DAT_802c5e30 + uVar4 * 0x34) & 1) == 0) {
      uVar1 = (undefined2)(((uVar3 & 0xffff) >> 1) << 2);
      (&DAT_802c5ed8)[uVar4 * 8] = uVar1;
      uVar2 = (undefined2)((uVar3 >> 0x11) << 2);
      (&DAT_802c5eda)[uVar4 * 8] = uVar2;
      (&DAT_802c5ed0)[uVar4 * 8] = uVar1;
      (&DAT_802c5ed2)[uVar4 * 8] = uVar2;
    }
  }
  else {
    FUN_8000f0b8(param_1);
    uVar3 = (uint)DAT_803dc88d;
    if ((*(uint *)(&DAT_802c5e30 + uVar3 * 0x34) & 1) == 0) {
      (&DAT_802c5ed8)[uVar3 * 8] = 0;
      (&DAT_802c5eda)[uVar3 * 8] = 0;
      (&DAT_802c5ed0)[uVar3 * 8] = 0;
      (&DAT_802c5ed2)[uVar3 * 8] = 0;
    }
  }
  DAT_803dc88d = 0;
  return;
}

