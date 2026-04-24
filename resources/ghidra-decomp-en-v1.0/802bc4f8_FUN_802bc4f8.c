// Function: FUN_802bc4f8
// Entry: 802bc4f8
// Size: 388 bytes

void FUN_802bc4f8(undefined2 *param_1)

{
  float fVar1;
  undefined uVar2;
  int iVar3;
  uint *puVar4;
  double dVar5;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined auStack80 [72];
  
  puVar4 = *(uint **)(param_1 + 0x5c);
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
  if (((&DAT_803dc750)[*(short *)(puVar4 + 0x9d)] & 8) == 0) {
    uVar2 = FUN_800353a4(param_1,&DAT_803351a8,1,*(undefined *)(puVar4 + 0x17f),puVar4 + 0xe4);
    *(undefined *)(puVar4 + 0x17f) = uVar2;
    if (*(char *)(puVar4 + 0x17f) != '\0') {
      FUN_8003a168(param_1,puVar4 + 0xd7);
      FUN_8003b310(param_1,puVar4 + 0xd7);
      return;
    }
  }
  FUN_8003b310(param_1,puVar4 + 0xd7);
  local_5c = *(undefined4 *)(param_1 + 6);
  local_58 = *(undefined4 *)(param_1 + 8);
  local_54 = *(undefined4 *)(param_1 + 10);
  local_68 = *param_1;
  local_66 = param_1[1];
  local_64 = param_1[2];
  local_60 = *(undefined4 *)(param_1 + 4);
  FUN_80021ee8(auStack80,&local_68);
  iVar3 = *(int *)(param_1 + 0x32);
  dVar5 = (double)FLOAT_803e82c0;
  FUN_800226cc(dVar5,dVar5,dVar5,auStack80,iVar3 + 0x20,iVar3 + 0x24,iVar3 + 0x28);
  *(undefined *)(puVar4 + 0xd5) = 0;
  *puVar4 = *puVar4 & 0xffff7fff;
  fVar1 = FLOAT_803e82c0;
  puVar4[0xa4] = (uint)FLOAT_803e82c0;
  puVar4[0xa3] = (uint)fVar1;
  puVar4[199] = 0;
  puVar4[0xc6] = 0;
  *(undefined2 *)(puVar4 + 0xcc) = 0;
  *puVar4 = *puVar4 | 0x400000;
  (**(code **)(*DAT_803dca8c + 8))
            ((double)FLOAT_803db414,(double)FLOAT_803db414,param_1,puVar4,&DAT_803db160,
             &DAT_803de4c8);
  FUN_800e8370(param_1);
  return;
}

