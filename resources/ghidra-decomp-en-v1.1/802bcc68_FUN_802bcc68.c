// Function: FUN_802bcc68
// Entry: 802bcc68
// Size: 388 bytes

void FUN_802bcc68(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  float fVar1;
  undefined uVar2;
  int iVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint *puVar4;
  double dVar5;
  ushort local_68;
  ushort local_66;
  ushort local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float afStack_50 [18];
  
  puVar4 = *(uint **)(param_9 + 0x5c);
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
  if (((&DAT_803dd3b8)[*(short *)(puVar4 + 0x9d)] & 8) == 0) {
    uVar2 = FUN_8003549c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         &DAT_80335e08,1,(uint)*(byte *)(puVar4 + 0x17f),(float *)(puVar4 + 0xe4),
                         in_r8,in_r9,in_r10);
    *(undefined *)(puVar4 + 0x17f) = uVar2;
    if (*(char *)(puVar4 + 0x17f) != '\0') {
      FUN_8003a260((int)param_9,(int)(puVar4 + 0xd7));
      FUN_8003b408((int)param_9,(int)(puVar4 + 0xd7));
      return;
    }
  }
  FUN_8003b408((int)param_9,(int)(puVar4 + 0xd7));
  local_5c = *(undefined4 *)(param_9 + 6);
  local_58 = *(undefined4 *)(param_9 + 8);
  local_54 = *(undefined4 *)(param_9 + 10);
  local_68 = *param_9;
  local_66 = param_9[1];
  local_64 = param_9[2];
  local_60 = *(undefined4 *)(param_9 + 4);
  FUN_80021fac(afStack_50,&local_68);
  iVar3 = *(int *)(param_9 + 0x32);
  dVar5 = (double)FLOAT_803e8f58;
  FUN_80022790(dVar5,dVar5,dVar5,afStack_50,(float *)(iVar3 + 0x20),(float *)(iVar3 + 0x24),
               (float *)(iVar3 + 0x28));
  *(undefined *)(puVar4 + 0xd5) = 0;
  *puVar4 = *puVar4 & 0xffff7fff;
  fVar1 = FLOAT_803e8f58;
  puVar4[0xa4] = (uint)FLOAT_803e8f58;
  puVar4[0xa3] = (uint)fVar1;
  puVar4[199] = 0;
  puVar4[0xc6] = 0;
  *(undefined2 *)(puVar4 + 0xcc) = 0;
  *puVar4 = *puVar4 | 0x400000;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)FLOAT_803dc074,(double)FLOAT_803dc074,param_9,puVar4,&DAT_803dbdc0,
             &DAT_803df148);
  FUN_800e85f4((int)param_9);
  return;
}

