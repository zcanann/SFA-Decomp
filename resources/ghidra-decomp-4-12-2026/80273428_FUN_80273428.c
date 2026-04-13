// Function: FUN_80273428
// Entry: 80273428
// Size: 176 bytes

void FUN_80273428(uint param_1,undefined param_2,undefined4 param_3)

{
  int iVar1;
  
  FUN_80285258();
  (&DAT_803be624)[param_1 & 0xff] = 0;
  (&DAT_803be664)[param_1 & 0xff] = 0;
  (&DAT_803deed4)[param_1 & 0xff] = 0xff;
  iVar1 = (param_1 & 0xff) * 2;
  (&DAT_803deec4)[param_1 & 0xff] = 0xff;
  (&DAT_803be685)[iVar1] = 0;
  (&DAT_803be684)[iVar1] = 0;
  FUN_802842c4(param_1,param_2,param_3);
  FUN_80285220();
  return;
}

