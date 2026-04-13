// Function: FUN_80061210
// Entry: 80061210
// Size: 320 bytes

/* WARNING: Removing unreachable block (ram,0x8006132c) */
/* WARNING: Removing unreachable block (ram,0x80061324) */
/* WARNING: Removing unreachable block (ram,0x80061228) */
/* WARNING: Removing unreachable block (ram,0x80061220) */

void FUN_80061210(double param_1,float *param_2,float *param_3)

{
  int iVar1;
  float *pfVar2;
  double dVar3;
  double dVar4;
  ushort local_48;
  short local_46;
  undefined2 local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  
  local_3c = FLOAT_803df8d8;
  local_38 = FLOAT_803df8d8;
  local_34 = FLOAT_803df8d8;
  local_40 = FLOAT_803df8e8;
  local_44 = 0;
  if (ABS(*param_2) <= ABS(param_2[2])) {
    iVar1 = FUN_80021884();
    local_46 = (short)iVar1;
  }
  else {
    iVar1 = FUN_80021884();
    local_46 = (short)iVar1;
  }
  if (0x2000 < local_46) {
    local_46 = 0x2000;
  }
  iVar1 = FUN_80021884();
  local_48 = (ushort)iVar1;
  iVar1 = 0;
  pfVar2 = (float *)&DAT_8038e43c;
  dVar4 = (double)FLOAT_803df8d8;
  do {
    *param_3 = *pfVar2;
    dVar3 = (double)pfVar2[1];
    if (dVar3 <= dVar4) {
      param_3[1] = (float)(param_1 * dVar3);
    }
    else {
      param_3[1] = pfVar2[1];
    }
    param_3[2] = pfVar2[2];
    FUN_80021b8c(&local_48,param_3);
    pfVar2 = pfVar2 + 3;
    param_3 = param_3 + 3;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 8);
  return;
}

