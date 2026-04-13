// Function: FUN_8000dcdc
// Entry: 8000dcdc
// Size: 184 bytes

void FUN_8000dcdc(uint param_1,ushort param_2)

{
  bool bVar1;
  short sVar2;
  uint *puVar3;
  ushort *puVar4;
  uint uVar5;
  
  sVar2 = 0;
  puVar3 = &DAT_80337af0;
  puVar4 = &DAT_803379f0;
  uVar5 = (uint)DAT_803dd4f8;
  do {
    if ((int)uVar5 <= (int)sVar2) {
      bVar1 = false;
LAB_8000dd44:
      if ((!bVar1) && (uVar5 != 0x80)) {
        (&DAT_80337af0)[uVar5] = param_1;
        (&DAT_803379f0)[uVar5] = param_2;
        (&DAT_80337970)[uVar5] = 0;
        DAT_803dd4f8 = DAT_803dd4f8 + 1;
        FUN_8000bb38(param_1,param_2);
      }
      return;
    }
    if ((*puVar3 == param_1) && (param_2 == *puVar4)) {
      bVar1 = true;
      goto LAB_8000dd44;
    }
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
    sVar2 = sVar2 + 1;
  } while( true );
}

