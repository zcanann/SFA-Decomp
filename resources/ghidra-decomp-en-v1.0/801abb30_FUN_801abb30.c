// Function: FUN_801abb30
// Entry: 801abb30
// Size: 1048 bytes

void FUN_801abb30(int param_1)

{
  int iVar1;
  char cVar3;
  int iVar2;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  if (FLOAT_803e46d0 < *pfVar4) {
    FUN_80016870(0x34c);
    *pfVar4 = *pfVar4 - FLOAT_803db414;
    if (*pfVar4 < FLOAT_803e46d0) {
      *pfVar4 = FLOAT_803e46d0;
    }
  }
  iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(0);
  if (iVar1 == 0) {
    if ((pfVar4[2] != 2.802597e-43) && (pfVar4[2] = 2.802597e-43, ((uint)pfVar4[1] & 0x20) != 0)) {
      FUN_8000a518(200,1);
    }
  }
  else if ((pfVar4[2] != -NAN) && (pfVar4[2] = -NAN, ((uint)pfVar4[1] & 0x20) != 0)) {
    FUN_8000a518(200,0);
  }
  FUN_801d7ed4(pfVar4 + 1,2,0xffffffff,0xffffffff,0xb72,0x95);
  FUN_801d7ed4(pfVar4 + 1,0x20,0xffffffff,0xffffffff,0xc47,pfVar4[2]);
  FUN_801d7ed4(pfVar4 + 1,4,0xffffffff,0xffffffff,0xb45,0x37);
  FUN_801d7ed4(pfVar4 + 1,8,0xffffffff,0xffffffff,0xb73,0xbf);
  FUN_801d7ed4(pfVar4 + 1,0x10,0xffffffff,0xffffffff,0xb24,0xc0);
  FUN_801d7ed4(pfVar4 + 1,0x40,0xffffffff,0xffffffff,0x19e,0xcd);
  if (pfVar4[3] == 2.802597e-45) {
    FUN_801d8060(pfVar4 + 1,0x80,0xffffffff,0xffffffff,0x24,0xea);
  }
  iVar1 = FUN_8001ffb4(0x3d6);
  if ((iVar1 != 0) &&
     (cVar3 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),0x1f),
     cVar3 != '\0')) {
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x1f,0);
  }
  iVar1 = FUN_8001ffb4(0x161);
  if ((iVar1 != 0) &&
     (cVar3 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),0x1e),
     cVar3 == '\0')) {
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x1e,1);
  }
  iVar1 = FUN_8001ffb4(0x3d7);
  if ((iVar1 != 0) &&
     (cVar3 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0xac),0x1d),
     cVar3 == '\0')) {
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x1d,1);
  }
  iVar1 = FUN_8002b9ac();
  if (((uint)pfVar4[1] & 1) == 0) {
    iVar1 = FUN_8001ffb4(0x22d);
    if ((((iVar1 == 0) && (iVar1 = FUN_8001ffb4(0x22a), iVar1 != 0)) &&
        (iVar1 = FUN_8001ffb4(0x22e), iVar1 != 0)) && (iVar1 = FUN_8001ffb4(0x160), iVar1 == 0)) {
      pfVar4[1] = (float)((uint)pfVar4[1] | 1);
      (**(code **)(*DAT_803dca50 + 0x24))(1,1,0);
    }
  }
  else {
    iVar2 = FUN_8001ffb4(0x22d);
    if (((iVar2 != 0) || (iVar2 = FUN_8001ffb4(0x22e), iVar2 == 0)) ||
       ((*(ushort *)(iVar1 + 0xb0) & 0x1000) != 0)) {
      pfVar4[1] = (float)((uint)pfVar4[1] & 0xfffffffe);
      (**(code **)(*DAT_803dca50 + 0x24))(0,1,0);
    }
  }
  iVar1 = FUN_8001ffb4(0x3f0);
  iVar2 = FUN_8001ffb4(0xaf7);
  if ((iVar2 + iVar1 == 4) && (iVar1 = FUN_8001ffb4(0xf26), iVar1 == 0)) {
    FUN_8000bb18(param_1,0x7e);
    FUN_800200e8(0xf26,1);
  }
  return;
}

