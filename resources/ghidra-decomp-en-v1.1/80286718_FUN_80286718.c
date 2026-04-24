// Function: FUN_80286718
// Entry: 80286718
// Size: 92 bytes

int FUN_80286718(double param_1)

{
  int iVar1;
  bool bVar2;
  
  iVar1 = 0;
  if ((DAT_802c30a0 <= param_1) && (iVar1 = -1, param_1 < DAT_802c30a8)) {
    bVar2 = DAT_802c30b0 <= param_1;
    if (bVar2) {
      param_1 = param_1 - DAT_802c30b0;
    }
    iVar1 = (int)param_1;
    if (bVar2) {
      iVar1 = iVar1 + -0x80000000;
    }
  }
  return iVar1;
}

