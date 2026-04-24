// Function: FUN_80061094
// Entry: 80061094
// Size: 320 bytes

/* WARNING: Removing unreachable block (ram,0x800611a8) */
/* WARNING: Removing unreachable block (ram,0x800611b0) */

void FUN_80061094(double param_1,float *param_2,undefined4 *param_3)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar5;
  undefined2 local_48;
  short local_46;
  undefined2 local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  local_3c = FLOAT_803dec58;
  local_38 = FLOAT_803dec58;
  local_34 = FLOAT_803dec58;
  local_40 = FLOAT_803dec68;
  local_44 = 0;
  if (ABS((double)*param_2) <= ABS((double)param_2[2])) {
    local_46 = FUN_800217c0(ABS((double)param_2[2]),(double)param_2[1]);
  }
  else {
    local_46 = FUN_800217c0(ABS((double)*param_2),(double)param_2[1]);
  }
  if (0x2000 < local_46) {
    local_46 = 0x2000;
  }
  local_48 = FUN_800217c0((double)*param_2,(double)param_2[2]);
  iVar1 = 0;
  puVar2 = &DAT_8038d7dc;
  dVar5 = (double)FLOAT_803dec58;
  do {
    *param_3 = *puVar2;
    dVar4 = (double)(float)puVar2[1];
    if (dVar4 <= dVar5) {
      param_3[1] = (float)(param_1 * dVar4);
    }
    else {
      param_3[1] = puVar2[1];
    }
    param_3[2] = puVar2[2];
    FUN_80021ac8(&local_48,param_3);
    puVar2 = puVar2 + 3;
    param_3 = param_3 + 3;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 8);
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  return;
}

