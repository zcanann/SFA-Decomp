// Function: FUN_801ac0e4
// Entry: 801ac0e4
// Size: 1048 bytes

void FUN_801ac0e4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  int iVar1;
  uint uVar2;
  char cVar4;
  uint uVar3;
  float *pfVar5;
  
  pfVar5 = *(float **)(param_9 + 0xb8);
  if ((double)FLOAT_803e5368 < (double)*pfVar5) {
    FUN_800168a8((double)*pfVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x34c);
    *pfVar5 = *pfVar5 - FLOAT_803dc074;
    if (*pfVar5 < FLOAT_803e5368) {
      *pfVar5 = FLOAT_803e5368;
    }
  }
  iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar1 == 0) {
    if ((pfVar5[2] != 2.8026e-43) && (pfVar5[2] = 2.8026e-43, ((uint)pfVar5[1] & 0x20) != 0)) {
      FUN_8000a538((int *)0xc8,1);
    }
  }
  else if ((pfVar5[2] != -NAN) && (pfVar5[2] = -NAN, ((uint)pfVar5[1] & 0x20) != 0)) {
    FUN_8000a538((int *)0xc8,0);
  }
  FUN_801d84c4(pfVar5 + 1,2,-1,-1,0xb72,(int *)0x95);
  FUN_801d84c4(pfVar5 + 1,0x20,-1,-1,0xc47,(int *)pfVar5[2]);
  FUN_801d84c4(pfVar5 + 1,4,-1,-1,0xb45,(int *)0x37);
  FUN_801d84c4(pfVar5 + 1,8,-1,-1,0xb73,(int *)0xbf);
  FUN_801d84c4(pfVar5 + 1,0x10,-1,-1,0xb24,(int *)0xc0);
  FUN_801d84c4(pfVar5 + 1,0x40,-1,-1,0x19e,(int *)0xcd);
  if (pfVar5[3] == 2.8026e-45) {
    FUN_801d8650(pfVar5 + 1,0x80,-1,-1,0x24,(int *)0xea);
  }
  uVar2 = FUN_80020078(0x3d6);
  if ((uVar2 != 0) &&
     (cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0x1f),
     cVar4 != '\0')) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0x1f,0);
  }
  uVar2 = FUN_80020078(0x161);
  if ((uVar2 != 0) &&
     (cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0x1e),
     cVar4 == '\0')) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0x1e,1);
  }
  uVar2 = FUN_80020078(0x3d7);
  if ((uVar2 != 0) &&
     (cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0x1d),
     cVar4 == '\0')) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0x1d,1);
  }
  iVar1 = FUN_8002ba84();
  if (((uint)pfVar5[1] & 1) == 0) {
    uVar2 = FUN_80020078(0x22d);
    if ((((uVar2 == 0) && (uVar2 = FUN_80020078(0x22a), uVar2 != 0)) &&
        (uVar2 = FUN_80020078(0x22e), uVar2 != 0)) && (uVar2 = FUN_80020078(0x160), uVar2 == 0)) {
      pfVar5[1] = (float)((uint)pfVar5[1] | 1);
      (**(code **)(*DAT_803dd6d0 + 0x24))(1,1,0);
    }
  }
  else {
    uVar2 = FUN_80020078(0x22d);
    if (((uVar2 != 0) || (uVar2 = FUN_80020078(0x22e), uVar2 == 0)) ||
       ((*(ushort *)(iVar1 + 0xb0) & 0x1000) != 0)) {
      pfVar5[1] = (float)((uint)pfVar5[1] & 0xfffffffe);
      (**(code **)(*DAT_803dd6d0 + 0x24))(0,1,0);
    }
  }
  uVar2 = FUN_80020078(0x3f0);
  uVar3 = FUN_80020078(0xaf7);
  if ((uVar3 + uVar2 == 4) && (uVar2 = FUN_80020078(0xf26), uVar2 == 0)) {
    FUN_8000bb38(param_9,0x7e);
    FUN_800201ac(0xf26,1);
  }
  return;
}

