// Function: FUN_801719c8
// Entry: 801719c8
// Size: 948 bytes

void FUN_801719c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)

{
  undefined4 uVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  undefined2 *puVar6;
  float *pfVar7;
  float *pfVar8;
  undefined4 in_r10;
  float *pfVar9;
  double dVar10;
  undefined4 local_48;
  float local_44;
  float local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined2 local_30;
  undefined2 local_2e;
  undefined2 local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c [4];
  
  pfVar9 = *(float **)(param_9 + 0x5c);
  local_40 = DAT_802c29e0;
  local_3c = DAT_802c29e4;
  local_38 = DAT_802c29e8;
  local_34 = DAT_802c29ec;
  if (*(char *)((int)pfVar9 + 9) == '\0') {
    pfVar7 = &local_20;
    pfVar8 = local_1c;
    iVar4 = FUN_80036868((int)param_9,(undefined4 *)0x0,(int *)0x0,&local_48,&local_24,pfVar7,pfVar8
                        );
    if ((iVar4 != 0) &&
       (local_48._3_1_ = *(char *)((int)pfVar9 + 10) - (char)local_48,
       *(char *)((int)pfVar9 + 10) = (char)local_48, '\0' < (char)local_48)) {
      param_3 = (double)local_1c[0];
      FUN_8000bb00((double)local_24,(double)local_20,param_3,(uint)param_9,0x48);
      FUN_8002b95c((int)param_9,2 - *(char *)((int)pfVar9 + 10));
      local_28 = FLOAT_803e409c;
      param_2 = (double)FLOAT_803e409c;
      *pfVar9 = FLOAT_803e409c;
      pfVar9[1] = FLOAT_803e40a0;
      local_24 = local_24 + FLOAT_803dda58;
      local_1c[0] = local_1c[0] + FLOAT_803dda5c;
      local_2c = 0;
      local_2e = 0;
      local_30 = 0;
      pfVar7 = &local_40;
      pfVar8 = (float *)*DAT_803de734;
      (*(code *)pfVar8[1])(0,1,&local_30,0x401,0xffffffff);
    }
    if (*(char *)((int)pfVar9 + 10) < '\x01') {
      iVar4 = *(int *)(param_9 + 0x26);
      if (*(char *)((int)pfVar9 + 0xb) == '\0') {
        (**(code **)(*DAT_803dd72c + 100))((double)FLOAT_803e40a4,*(undefined4 *)(iVar4 + 0x14));
      }
      *(undefined *)((int)pfVar9 + 9) = 1;
      *(undefined *)(pfVar9 + 2) = 0;
      FUN_8000bb38((uint)param_9,0x4a);
      *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
      uVar5 = (uint)*(short *)(iVar4 + 0x1e);
      if (uVar5 != 0xffffffff) {
        FUN_800201ac(uVar5,1);
      }
      if ((*(char *)((int)pfVar9 + 0xb) == '\0') && (uVar5 = FUN_8002e144(), (uVar5 & 0xff) != 0)) {
        puVar6 = FUN_8002becc(0x30,0xb);
        puVar6[0xe] = 0xffff;
        *(undefined4 *)(puVar6 + 4) = *(undefined4 *)(param_9 + 6);
        dVar10 = (double)FLOAT_803e40a8;
        *(float *)(puVar6 + 6) = (float)(dVar10 + (double)*(float *)(param_9 + 8));
        *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(param_9 + 10);
        *(undefined *)(puVar6 + 0xd) = 3;
        puVar6[0x16] = 0xffff;
        puVar6[0x12] = 0xffff;
        FUN_8002e088(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar6,5,
                     *(undefined *)(param_9 + 0x56),0xffffffff,*(uint **)(param_9 + 0x18),pfVar7,
                     pfVar8,in_r10);
      }
      else {
        local_44 = FLOAT_803e40ac;
        puVar6 = (undefined2 *)FUN_80036f50(4,param_9,&local_44);
        if (puVar6 != (undefined2 *)0x0) {
          uVar1 = *(undefined4 *)(param_9 + 6);
          *(undefined4 *)(puVar6 + 0xc) = uVar1;
          *(undefined4 *)(puVar6 + 6) = uVar1;
          fVar3 = FLOAT_803e40a8 + *(float *)(param_9 + 8);
          *(float *)(puVar6 + 0xe) = fVar3;
          *(float *)(puVar6 + 8) = fVar3;
          uVar1 = *(undefined4 *)(param_9 + 10);
          *(undefined4 *)(puVar6 + 0x10) = uVar1;
          *(undefined4 *)(puVar6 + 10) = uVar1;
          *puVar6 = *param_9;
        }
      }
      (**(code **)(*DAT_803de730 + 4))(param_9,1,0,2,0xffffffff,0);
    }
    fVar3 = FLOAT_803e4098;
    if (FLOAT_803e4098 < *pfVar9) {
      *pfVar9 = FLOAT_803dc074 * pfVar9[1] + *pfVar9;
      fVar2 = *pfVar9;
      if (fVar3 <= fVar2) {
        if (FLOAT_803e40b0 < fVar2) {
          *pfVar9 = FLOAT_803e40b0 - (fVar2 - FLOAT_803e40b0);
          pfVar9[1] = -pfVar9[1];
        }
      }
      else {
        *pfVar9 = fVar3;
      }
    }
  }
  else if ((*(char *)((int)pfVar9 + 0xb) == '\0') &&
          (iVar4 = (**(code **)(*DAT_803dd72c + 0x68))
                             (*(undefined4 *)(*(int *)(param_9 + 0x26) + 0x14)), iVar4 != 0)) {
    *(undefined *)((int)pfVar9 + 9) = 0;
    *(undefined *)(pfVar9 + 2) = 1;
    *(undefined *)((int)pfVar9 + 10) = 2;
    *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 1;
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
  }
  return;
}

