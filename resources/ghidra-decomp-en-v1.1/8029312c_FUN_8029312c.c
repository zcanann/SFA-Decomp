// Function: FUN_8029312c
// Entry: 8029312c
// Size: 376 bytes

void FUN_8029312c(undefined8 param_1,double param_2)

{
  float fVar1;
  float fVar2;
  double dVar3;
  short local_38;
  short local_36;
  float local_34;
  float local_30;
  longlong local_28;
  
  dVar3 = (double)FUN_802867b0();
  fVar1 = (float)dVar3;
  if (fVar1 != FLOAT_803e8750) {
    local_36 = ((ushort)((uint)fVar1 >> 0x17) & 0xff) - 0x7f;
    fVar2 = (float)((uint)fVar1 & 0x7fffff | 0x3f800000) - FLOAT_803e8860;
    local_34 = fVar2 * (fVar2 * (FLOAT_803e887c * fVar2 + FLOAT_803e8878) + FLOAT_803e8874) +
               FLOAT_803e8870;
    dVar3 = FUN_80292568((float *)&local_36);
    local_34 = (float)(param_2 * (double)(float)((double)local_34 + dVar3));
    FUN_80292584((double)local_34,(float *)&local_38);
    dVar3 = FUN_80292568((float *)&local_38);
    local_34 = (float)((double)local_34 - dVar3);
    local_30 = FLOAT_803e8860;
    if (local_34 != FLOAT_803e8750) {
      local_30 = local_34 * (FLOAT_803e8888 * local_34 + FLOAT_803e8884) + FLOAT_803e8880;
    }
    if ((((uint)fVar1 & 0x80000000) != 0) &&
       (local_28 = (longlong)(int)param_2, ((int)param_2 & 1U) != 0)) {
      local_30 = -local_30;
    }
    local_30 = (float)((int)local_30 + local_38 * 0x800000);
  }
  FUN_802867fc();
  return;
}

