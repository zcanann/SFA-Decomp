// Function: FUN_80285fb4
// Entry: 80285fb4
// Size: 92 bytes

int FUN_80285fb4(double param_1)

{
  int iVar1;
  bool bVar2;
  
  iVar1 = 0;
  if ((DAT_802c2920 <= param_1) && (iVar1 = -1, param_1 < DAT_802c2928)) {
    bVar2 = DAT_802c2930 <= param_1;
    if (bVar2) {
      param_1 = param_1 - DAT_802c2930;
    }
    iVar1 = (int)param_1;
    if (bVar2) {
      iVar1 = iVar1 + -0x80000000;
    }
  }
  return iVar1;
}

