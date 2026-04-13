// Function: FUN_8007db18
// Entry: 8007db18
// Size: 392 bytes

undefined4
FUN_8007db18(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  int iVar2;
  undefined8 uVar3;
  
  DAT_803ddcd8 = '\0';
  while( true ) {
    iVar2 = FUN_8007df88(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,'\0');
    if (iVar2 == 0) {
      bVar1 = false;
    }
    else {
      DAT_803ddcc0 = FUN_80023d8c(0xa000,-1);
      if (DAT_803ddcc0 == 0) {
        DAT_803dc360 = 8;
        bVar1 = false;
      }
      else {
        bVar1 = true;
      }
    }
    if (!bVar1) break;
    DAT_803dc360 = 0;
    iVar2 = FUN_80262b10(0,DAT_803ddcc0,&LAB_80080084);
    if ((iVar2 == 0) || (iVar2 == -6)) {
      iVar2 = FUN_8026218c(0);
    }
    if (iVar2 == 0) {
      iVar2 = FUN_80264624(0,DAT_803dc364);
    }
    FUN_80262bf4(0);
    uVar3 = FUN_800238c4(DAT_803ddcc0);
    DAT_803ddcc0 = 0;
    switch(iVar2) {
    case 0:
      DAT_803dc360 = 0xd;
      DAT_803ddcc0 = 0;
      return 1;
    case -0xd:
      DAT_803dc360 = 6;
      break;
    case -5:
      DAT_803dc360 = 4;
      break;
    case -3:
      if (DAT_803dc360 != 3) {
        DAT_803dc360 = 2;
      }
      break;
    case -2:
      DAT_803dc360 = 1;
    }
    param_1 = FUN_8007e328(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (DAT_803ddcd8 == '\0') {
      return 0;
    }
  }
  return 0;
}

