// Function: FUN_80178310
// Entry: 80178310
// Size: 400 bytes

void FUN_80178310(ushort *param_1)

{
  int iVar1;
  undefined uVar2;
  float *pfVar3;
  ushort *puVar4;
  ushort local_28;
  ushort local_26;
  ushort local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar1 = FUN_8002bac4();
  pfVar3 = *(float **)(param_1 + 0x5c);
  if ((iVar1 != 0) && (puVar4 = *(ushort **)(iVar1 + 200), puVar4 != (ushort *)0x0)) {
    param_1[2] = puVar4[2];
    param_1[1] = puVar4[1];
    *param_1 = *puVar4;
    if (*(char *)(*(int *)(param_1 + 0x26) + 0x19) == '\0') {
      uVar2 = 1;
    }
    else {
      uVar2 = 3;
    }
    FUN_80035eec((int)param_1,0x10,uVar2,0);
    *pfVar3 = *pfVar3 - FLOAT_803dc074;
    local_1c = FLOAT_803e429c;
    if (*pfVar3 <= FLOAT_803e429c) {
      *pfVar3 = *pfVar3 + FLOAT_803e42a0;
      *(float *)(param_1 + 0x12) = local_1c;
      *(float *)(param_1 + 0x16) = local_1c;
      *(float *)(param_1 + 0x14) = FLOAT_803e42a4;
      local_18 = local_1c;
      local_14 = local_1c;
      local_20 = FLOAT_803e4298;
      local_24 = puVar4[2];
      local_26 = puVar4[1];
      local_28 = *puVar4;
      FUN_80021b8c(&local_28,(float *)(param_1 + 0x12));
      FUN_80038524(puVar4,0,(float *)(param_1 + 6),(undefined4 *)(param_1 + 8),
                   (float *)(param_1 + 10),0);
      FUN_80036018((int)param_1);
    }
    *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
    *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803dc074 + *(float *)(param_1 + 6);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803dc074 + *(float *)(param_1 + 8);
    *(float *)(param_1 + 10) =
         *(float *)(param_1 + 0x16) * FLOAT_803dc074 + *(float *)(param_1 + 10);
  }
  return;
}

