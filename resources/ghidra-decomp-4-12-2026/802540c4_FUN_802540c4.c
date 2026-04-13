// Function: FUN_802540c4
// Entry: 802540c4
// Size: 372 bytes

undefined4 FUN_802540c4(int param_1)

{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  uint *puVar4;
  uint uVar5;
  undefined8 uVar6;
  
  if (param_1 == 2) {
    uVar1 = 1;
  }
  else {
    uVar1 = 1;
    FUN_80243e74();
    puVar4 = &DAT_cc006800 + param_1 * 5;
    uVar5 = *puVar4;
    if ((*(uint *)(&DAT_803af06c + param_1 * 0x40) & 8) == 0) {
      if ((uVar5 & 0x800) != 0) {
        *puVar4 = *puVar4 & 0x7f5 | 0x800;
        (&DAT_803af080)[param_1 * 0x10] = 0;
        (&DAT_800030c0)[param_1] = 0;
      }
      if ((uVar5 & 0x1000) == 0) {
        (&DAT_803af080)[param_1 * 0x10] = 0;
        (&DAT_800030c0)[param_1] = 0;
        uVar1 = 0;
      }
      else {
        uVar5 = DAT_800000f8 / 4000;
        uVar6 = FUN_802473b4();
        uVar6 = FUN_80286990((uint)((ulonglong)uVar6 >> 0x20),(uint)uVar6,0,uVar5);
        uVar6 = FUN_80286990((uint)((ulonglong)uVar6 >> 0x20),(uint)uVar6,0,100);
        piVar2 = &DAT_800030c0 + param_1;
        iVar3 = (int)uVar6 + 1;
        if (*piVar2 == 0) {
          *piVar2 = iVar3;
        }
        if (iVar3 - *piVar2 < 3) {
          uVar1 = 0;
        }
      }
    }
    else if (((uVar5 & 0x1000) == 0) || ((uVar5 & 0x800) != 0)) {
      (&DAT_803af080)[param_1 * 0x10] = 0;
      (&DAT_800030c0)[param_1] = 0;
      uVar1 = 0;
    }
    FUN_80243e9c();
  }
  return uVar1;
}

