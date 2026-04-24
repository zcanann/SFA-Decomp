// Function: FUN_802929cc
// Entry: 802929cc
// Size: 376 bytes

void FUN_802929cc(undefined8 param_1,double param_2)

{
  float fVar1;
  float fVar2;
  double dVar3;
  short local_38;
  short local_36;
  float local_34;
  float local_30;
  longlong local_28;
  
  dVar3 = (double)FUN_8028604c();
  fVar1 = (float)dVar3;
  if (fVar1 == FLOAT_803e7ab8) {
    if (param_2 == (double)FLOAT_803e7ab8) {
      dVar3 = (double)FLOAT_803e7bc8;
    }
    else {
      dVar3 = (double)FLOAT_803e7ab8;
    }
  }
  else {
    local_36 = ((ushort)((uint)fVar1 >> 0x17) & 0xff) - 0x7f;
    fVar2 = (float)((uint)fVar1 & 0x7fffff | 0x3f800000) - FLOAT_803e7bc8;
    local_34 = fVar2 * (fVar2 * (FLOAT_803e7be4 * fVar2 + FLOAT_803e7be0) + FLOAT_803e7bdc) +
               FLOAT_803e7bd8;
    dVar3 = (double)FUN_80291e08(&local_36);
    local_34 = (float)(param_2 * (double)(float)((double)local_34 + dVar3));
    FUN_80291e24((double)local_34,&local_38);
    dVar3 = (double)FUN_80291e08(&local_38);
    local_34 = (float)((double)local_34 - dVar3);
    local_30 = FLOAT_803e7bc8;
    if (local_34 != FLOAT_803e7ab8) {
      local_30 = local_34 * (FLOAT_803e7bf0 * local_34 + FLOAT_803e7bec) + FLOAT_803e7be8;
    }
    if ((((uint)fVar1 & 0x80000000) != 0) &&
       (local_28 = (longlong)(int)param_2, ((int)param_2 & 1U) != 0)) {
      local_30 = -local_30;
    }
    local_30 = (float)((int)local_30 + local_38 * 0x800000);
    dVar3 = (double)local_30;
  }
  FUN_80286098(dVar3);
  return;
}

