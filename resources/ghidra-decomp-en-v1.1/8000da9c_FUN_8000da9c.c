// Function: FUN_8000da9c
// Entry: 8000da9c
// Size: 276 bytes

void FUN_8000da9c(int param_1)

{
  uint uVar1;
  int *piVar2;
  uint uVar3;
  
  uVar3 = (uint)(short)(DAT_803dd4f8 - 1);
  piVar2 = &DAT_80337af0 + uVar3;
  while( true ) {
    if ((short)uVar3 < 0) {
      return;
    }
    if (*piVar2 == param_1) break;
    piVar2 = piVar2 + -1;
    uVar3 = uVar3 - 1;
  }
  FUN_8000b844(param_1,(&DAT_803379f0)[(short)uVar3]);
  uVar1 = (uint)DAT_803dd4f8;
  DAT_803dd4f8 = (ushort)(uVar1 - 1);
  uVar3 = uVar3 & 0xffff;
  FUN_8028fa2c((uint)(&DAT_80337af0 + uVar3),(uint)(&DAT_80337af0 + uVar3 + 1),
               ((uVar1 - 1 & 0xffff) - uVar3) * 4 & 0xfffc);
  FUN_8028fa2c((uint)(&DAT_803379f0 + uVar3),(uint)(&DAT_803379f0 + uVar3 + 1),
               (DAT_803dd4f8 - uVar3) * 2 & 0xfffe);
  FUN_8028fa2c((uint)(&DAT_80337970 + uVar3),uVar3 + 0x80337971,DAT_803dd4f8 - uVar3 & 0xffff);
  return;
}

