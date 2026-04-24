// Function: FUN_8000dbb0
// Entry: 8000dbb0
// Size: 300 bytes

void FUN_8000dbb0(void)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  ushort *puVar4;
  uint uVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  uVar5 = (uint)(short)(DAT_803dd4f8 - 1);
  piVar3 = &DAT_80337af0 + uVar5;
  puVar4 = &DAT_803379f0 + uVar5;
  do {
    if ((short)uVar5 < 0) {
LAB_8000dcc4:
      FUN_8028688c();
      return;
    }
    if ((*piVar3 == iVar1) && (((uint)uVar6 & 0xffff) == (uint)*puVar4)) {
      uVar2 = (uint)DAT_803dd4f8;
      DAT_803dd4f8 = (ushort)(uVar2 - 1);
      uVar5 = uVar5 & 0xffff;
      FUN_8028fa2c((uint)(&DAT_80337af0 + uVar5),(uint)(&DAT_80337af0 + uVar5 + 1),
                   ((uVar2 - 1 & 0xffff) - uVar5) * 4 & 0xfffc);
      FUN_8028fa2c((uint)(&DAT_803379f0 + uVar5),(uint)(&DAT_803379f0 + uVar5 + 1),
                   (DAT_803dd4f8 - uVar5) * 2 & 0xfffe);
      FUN_8028fa2c((uint)(&DAT_80337970 + uVar5),uVar5 + 0x80337971,DAT_803dd4f8 - uVar5 & 0xffff);
      FUN_8000b844(iVar1,(short)uVar6);
      goto LAB_8000dcc4;
    }
    piVar3 = piVar3 + -1;
    puVar4 = puVar4 + -1;
    uVar5 = uVar5 - 1;
  } while( true );
}

