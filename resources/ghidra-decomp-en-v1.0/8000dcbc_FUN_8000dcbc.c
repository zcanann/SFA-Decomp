// Function: FUN_8000dcbc
// Entry: 8000dcbc
// Size: 184 bytes

void FUN_8000dcbc(int param_1,short param_2)

{
  bool bVar1;
  short sVar2;
  int *piVar3;
  short *psVar4;
  uint uVar5;
  
  sVar2 = 0;
  piVar3 = &DAT_80336e90;
  psVar4 = &DAT_80336d90;
  uVar5 = (uint)DAT_803dc878;
  do {
    if ((int)uVar5 <= (int)sVar2) {
      bVar1 = false;
LAB_8000dd24:
      if ((!bVar1) && (uVar5 != 0x80)) {
        (&DAT_80336e90)[uVar5] = param_1;
        (&DAT_80336d90)[uVar5] = param_2;
        (&DAT_80336d10)[uVar5] = 0;
        DAT_803dc878 = DAT_803dc878 + 1;
        FUN_8000bb18();
      }
      return;
    }
    if ((*piVar3 == param_1) && (param_2 == *psVar4)) {
      bVar1 = true;
      goto LAB_8000dd24;
    }
    piVar3 = piVar3 + 1;
    psVar4 = psVar4 + 1;
    sVar2 = sVar2 + 1;
  } while( true );
}

