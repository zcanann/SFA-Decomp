// Function: FUN_801c8984
// Entry: 801c8984
// Size: 1636 bytes

void FUN_801c8984(short *param_1)

{
  float fVar1;
  int iVar2;
  undefined4 *puVar3;
  double dVar4;
  byte local_38 [4];
  int local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  float local_24;
  undefined8 local_20;
  undefined8 local_18;
  
  iVar2 = FUN_8002bac4();
  puVar3 = *(undefined4 **)(param_1 + 0x5c);
  local_2c = DAT_802c2b38;
  local_28 = DAT_802c2b3c;
  local_24 = DAT_802c2b40;
  local_30 = FLOAT_803e5cfc;
  local_34 = -1;
  local_38[0] = 0;
  if (DAT_803de848 == 0) {
    DAT_803de848 = FUN_80036f50(0xb,param_1,&local_30);
  }
  if ((DAT_803de848 != 0) && (*(short *)(DAT_803de848 + 0x44) != 0)) {
    (**(code **)(**(int **)(DAT_803de848 + 0x68) + 0x28))(&local_34,local_38);
    *param_1 = *param_1 + *(short *)(puVar3 + 0xb);
    if (((local_34 != 6) &&
        (((puVar3[7] = (float)puVar3[7] - FLOAT_803dc074, (float)puVar3[7] <= FLOAT_803e5d00 &&
          (puVar3[7] = FLOAT_803e5d04, local_34 != 3)) && (local_34 != 6)))) && (local_34 != 7)) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x270,0,0,0xffffffff,0);
    }
    puVar3[8] = (float)puVar3[8] - FLOAT_803dc074;
    if ((float)puVar3[8] <= FLOAT_803e5d00) {
      *(char *)((int)puVar3 + 0x2e) = -*(char *)((int)puVar3 + 0x2e);
      puVar3[8] = FLOAT_803e5d08;
    }
    local_20 = (double)CONCAT44(0x43300000,(int)*(char *)((int)puVar3 + 0x2e) ^ 0x80000000);
    *(float *)(param_1 + 8) =
         FLOAT_803e5d0c * (float)(local_20 - DOUBLE_803e5d28) + *(float *)(param_1 + 8);
    if ((local_34 == 1) && (puVar3[9] == 1)) {
      *(float *)(param_1 + 6) = (float)puVar3[3] * FLOAT_803dc074 + *(float *)(param_1 + 6);
      *(float *)(param_1 + 10) = (float)puVar3[5] * FLOAT_803dc074 + *(float *)(param_1 + 10);
      FUN_80036018((int)param_1);
      FUN_80035eec((int)param_1,10,1,0);
      FUN_80035f9c((int)param_1);
    }
    else {
      FUN_80036018((int)param_1);
      FUN_80035eec((int)param_1,0,0,0);
      FUN_80035f9c((int)param_1);
    }
    fVar1 = FLOAT_803e5d00;
    if (local_34 == 6) {
      if (*(float *)(param_1 + 8) < (float)puVar3[6]) {
        *(float *)(param_1 + 8) = FLOAT_803e5d10 * FLOAT_803dc074 + *(float *)(param_1 + 8);
      }
      if (*(byte *)((int)param_1 + 0x37) != 0xff) {
        local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)param_1 + 0x37));
        fVar1 = FLOAT_803e5d14 * FLOAT_803dc074 + (float)(local_20 - DOUBLE_803e5d30);
        if (FLOAT_803e5d18 <= fVar1) {
          fVar1 = FLOAT_803e5d18;
        }
        local_18 = (double)(longlong)(int)fVar1;
        *(char *)((int)param_1 + 0x37) = (char)(int)fVar1;
      }
      puVar3[7] = (float)puVar3[7] - FLOAT_803dc074;
      if ((float)puVar3[7] <= FLOAT_803e5d00) {
        puVar3[7] = FLOAT_803e5d04;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x271,0,0,0xffffffff,0);
      }
    }
    else if (local_34 == 7) {
      if ((float)puVar3[6] - FLOAT_803e5d1c < *(float *)(param_1 + 8)) {
        *(float *)(param_1 + 8) = -(FLOAT_803e5d10 * FLOAT_803dc074 - *(float *)(param_1 + 8));
        puVar3[7] = (float)puVar3[7] - FLOAT_803dc074;
        if ((float)puVar3[7] <= FLOAT_803e5d00) {
          puVar3[7] = FLOAT_803e5d04;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x271,0,0,0xffffffff,0);
        }
      }
      if (*(byte *)((int)param_1 + 0x37) != 0) {
        local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)param_1 + 0x37));
        fVar1 = -(FLOAT_803e5d14 * FLOAT_803dc074 - (float)(local_18 - DOUBLE_803e5d30));
        if (fVar1 <= FLOAT_803e5d00) {
          fVar1 = FLOAT_803e5d00;
        }
        *(char *)((int)param_1 + 0x37) = (char)(int)fVar1;
      }
    }
    else if ((local_34 == 8) && (puVar3[9] != 8)) {
      if (puVar3[10] == (uint)local_38[0]) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      }
      puVar3[9] = local_34;
    }
    else if ((local_34 == 1) && (puVar3[9] != 1)) {
      (**(code **)(**(int **)(DAT_803de848 + 0x68) + 0x24))(puVar3[10] & 0xff,&local_2c,&local_24);
      fVar1 = FLOAT_803e5d08;
      puVar3[3] = (local_2c - *(float *)(param_1 + 6)) / FLOAT_803e5d08;
      puVar3[5] = (local_24 - *(float *)(param_1 + 10)) / fVar1;
      *puVar3 = *(undefined4 *)(param_1 + 6);
      puVar3[2] = *(undefined4 *)(param_1 + 10);
      puVar3[9] = local_34;
    }
    else if ((local_34 == 0) && (puVar3[9] != 0)) {
      puVar3[3] = FLOAT_803e5d00;
      puVar3[5] = fVar1;
      puVar3[9] = 0;
    }
    else if ((local_34 == 2) && (puVar3[9] != 2)) {
      puVar3[3] = FLOAT_803e5d00;
      puVar3[5] = fVar1;
      (**(code **)(**(int **)(DAT_803de848 + 0x68) + 0x2c))
                ((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 10),puVar3[10] & 0xff)
      ;
      puVar3[9] = local_34;
    }
    else if ((local_34 == 3) && (puVar3[9] != 3)) {
      puVar3[9] = 3;
    }
    else if ((local_34 == 4) && (puVar3[9] != 4)) {
      (**(code **)(**(int **)(DAT_803de848 + 0x68) + 0x24))(puVar3[10] & 0xff,&local_2c,&local_24);
      *(float *)(param_1 + 6) = local_2c;
      *(float *)(param_1 + 10) = local_24;
      puVar3[9] = local_34;
    }
    else if ((((local_34 == 5) && (iVar2 != 0)) &&
             (dVar4 = (double)FUN_800217c8((float *)(param_1 + 0xc),(float *)(iVar2 + 0x18)),
             dVar4 < (double)FLOAT_803e5d20)) &&
            ((**(code **)(**(int **)(DAT_803de848 + 0x68) + 0x30))(puVar3[10] & 0xff),
            puVar3[10] == (uint)local_38[0])) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    }
  }
  return;
}

