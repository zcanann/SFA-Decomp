// Function: FUN_8017151c
// Entry: 8017151c
// Size: 948 bytes

void FUN_8017151c(undefined2 *param_1)

{
  undefined4 uVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  char cVar6;
  undefined2 *puVar5;
  float *pfVar7;
  undefined local_48 [3];
  char cStack69;
  float local_44;
  undefined4 local_40;
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
  
  pfVar7 = *(float **)(param_1 + 0x5c);
  local_40 = DAT_802c2260;
  local_3c = DAT_802c2264;
  local_38 = DAT_802c2268;
  local_34 = DAT_802c226c;
  if (*(char *)((int)pfVar7 + 9) == '\0') {
    iVar4 = FUN_80036770(param_1,0,0,local_48,&local_24,&local_20,local_1c);
    if ((iVar4 != 0) &&
       (cStack69 = *(char *)((int)pfVar7 + 10) - cStack69, *(char *)((int)pfVar7 + 10) = cStack69,
       '\0' < cStack69)) {
      FUN_8000bae0((double)local_24,(double)local_20,(double)local_1c[0],param_1,0x48);
      FUN_8002b884(param_1,2 - *(char *)((int)pfVar7 + 10));
      local_28 = FLOAT_803e3404;
      *pfVar7 = FLOAT_803e3404;
      pfVar7[1] = FLOAT_803e3408;
      local_24 = local_24 + FLOAT_803dcdd8;
      local_1c[0] = local_1c[0] + FLOAT_803dcddc;
      local_2c = 0;
      local_2e = 0;
      local_30 = 0;
      (**(code **)(*DAT_803ddab4 + 4))(0,1,&local_30,0x401,0xffffffff,&local_40);
    }
    if (*(char *)((int)pfVar7 + 10) < '\x01') {
      iVar4 = *(int *)(param_1 + 0x26);
      if (*(char *)((int)pfVar7 + 0xb) == '\0') {
        (**(code **)(*DAT_803dcaac + 100))((double)FLOAT_803e340c,*(undefined4 *)(iVar4 + 0x14));
      }
      *(undefined *)((int)pfVar7 + 9) = 1;
      *(undefined *)(pfVar7 + 2) = 0;
      FUN_8000bb18(param_1,0x4a);
      *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
      iVar4 = (int)*(short *)(iVar4 + 0x1e);
      if (iVar4 != -1) {
        FUN_800200e8(iVar4,1);
      }
      if ((*(char *)((int)pfVar7 + 0xb) == '\0') && (cVar6 = FUN_8002e04c(), cVar6 != '\0')) {
        iVar4 = FUN_8002bdf4(0x30,0xb);
        *(undefined2 *)(iVar4 + 0x1c) = 0xffff;
        *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(param_1 + 6);
        *(float *)(iVar4 + 0xc) = FLOAT_803e3410 + *(float *)(param_1 + 8);
        *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(param_1 + 10);
        *(undefined *)(iVar4 + 0x1a) = 3;
        *(undefined2 *)(iVar4 + 0x2c) = 0xffff;
        *(undefined2 *)(iVar4 + 0x24) = 0xffff;
        FUN_8002df90(iVar4,5,(int)*(char *)(param_1 + 0x56),0xffffffff,
                     *(undefined4 *)(param_1 + 0x18));
      }
      else {
        local_44 = FLOAT_803e3414;
        puVar5 = (undefined2 *)FUN_80036e58(4,param_1,&local_44);
        if (puVar5 != (undefined2 *)0x0) {
          uVar1 = *(undefined4 *)(param_1 + 6);
          *(undefined4 *)(puVar5 + 0xc) = uVar1;
          *(undefined4 *)(puVar5 + 6) = uVar1;
          fVar3 = FLOAT_803e3410 + *(float *)(param_1 + 8);
          *(float *)(puVar5 + 0xe) = fVar3;
          *(float *)(puVar5 + 8) = fVar3;
          uVar1 = *(undefined4 *)(param_1 + 10);
          *(undefined4 *)(puVar5 + 0x10) = uVar1;
          *(undefined4 *)(puVar5 + 10) = uVar1;
          *puVar5 = *param_1;
        }
      }
      (**(code **)(*DAT_803ddab0 + 4))(param_1,1,0,2,0xffffffff,0);
    }
    fVar3 = FLOAT_803e3400;
    if (FLOAT_803e3400 < *pfVar7) {
      *pfVar7 = FLOAT_803db414 * pfVar7[1] + *pfVar7;
      fVar2 = *pfVar7;
      if (fVar3 <= fVar2) {
        if (FLOAT_803e3418 < fVar2) {
          *pfVar7 = FLOAT_803e3418 - (fVar2 - FLOAT_803e3418);
          pfVar7[1] = -pfVar7[1];
        }
      }
      else {
        *pfVar7 = fVar3;
      }
    }
  }
  else if ((*(char *)((int)pfVar7 + 0xb) == '\0') &&
          (iVar4 = (**(code **)(*DAT_803dcaac + 0x68))
                             (*(undefined4 *)(*(int *)(param_1 + 0x26) + 0x14)), iVar4 != 0)) {
    *(undefined *)((int)pfVar7 + 9) = 0;
    *(undefined *)(pfVar7 + 2) = 1;
    *(undefined *)((int)pfVar7 + 10) = 2;
    *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) | 1;
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  }
  return;
}

