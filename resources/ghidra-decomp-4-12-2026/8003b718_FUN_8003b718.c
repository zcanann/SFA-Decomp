// Function: FUN_8003b718
// Entry: 8003b718
// Size: 664 bytes

void FUN_8003b718(undefined4 param_1,undefined4 param_2,int *param_3)

{
  undefined2 *puVar1;
  float *pfVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  
  uVar9 = FUN_80286830();
  puVar1 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  if ((1 < *(byte *)(*(int *)(puVar1 + 0x28) + 0x58)) && (puVar1[0x22] == 0x2d)) {
    iVar6 = *(int *)(puVar1 + 0x5c);
    iVar8 = 1;
    iVar5 = 0x18;
    iVar3 = iVar6;
    for (iVar7 = 0; iVar7 < *(short *)(iVar6 + 0xb0); iVar7 = iVar7 + 1) {
      if (iVar8 < (int)(uint)*(byte *)(*(int *)(puVar1 + 0x28) + 0x58)) {
        pfVar2 = (float *)FUN_80028630(param_3,(int)*(char *)(*(int *)(*(int *)(puVar1 + 0x28) +
                                                                      0x2c) +
                                                             iVar5 + *(char *)((int)puVar1 + 0xad) +
                                                             0x2a));
        iVar4 = *(int *)(*(int *)(puVar1 + 0x28) + 0x2c);
        local_3c = *(float *)(iVar4 + iVar5 + 0x18);
        local_38 = *(float *)(iVar4 + iVar5 + 0x1c);
        local_34 = *(float *)(iVar4 + iVar5 + 0x20);
        FUN_80247bf8(pfVar2,&local_3c,&local_3c);
        local_3c = local_3c + FLOAT_803dda58;
        local_34 = local_34 + FLOAT_803dda5c;
        *(float *)(iVar3 + 0x6c) = local_3c;
        *(float *)(iVar3 + 0x74) = local_38;
        *(float *)(iVar3 + 0x7c) = local_34;
      }
      if (iVar8 < (int)(uint)*(byte *)(*(int *)(puVar1 + 0x28) + 0x58)) {
        iVar4 = *(int *)(*(int *)(puVar1 + 0x28) + 0x2c);
        local_48 = *(float *)(iVar4 + iVar5);
        local_44 = *(float *)(iVar4 + iVar5 + 4);
        local_40 = *(float *)(iVar4 + iVar5 + 8);
        FUN_80247bf8((float *)(param_3[(*(ushort *)(param_3 + 6) & 1) + 3] +
                              *(char *)(iVar4 + iVar5 + *(char *)((int)puVar1 + 0xad) + 0x12) * 0x40
                              ),&local_48,&local_48);
        local_48 = local_48 + FLOAT_803dda58;
        local_40 = local_40 + FLOAT_803dda5c;
        *(float *)(iVar3 + 0x54) = local_48;
        *(float *)(iVar3 + 0x5c) = local_44;
        *(float *)(iVar3 + 100) = local_40;
      }
      iVar8 = iVar8 + 2;
      iVar5 = iVar5 + 0x30;
      iVar3 = iVar3 + 4;
    }
    if (*(short *)(iVar6 + 0xb0) != 0) {
      iVar6 = iVar6 + *(short *)(iVar6 + 0xb2) * 4;
      local_3c = *(float *)(iVar6 + 0x6c);
      local_38 = *(float *)(iVar6 + 0x74);
      local_34 = *(float *)(iVar6 + 0x7c);
      (**(code **)(**(int **)(puVar1 + 0x34) + 0x28))(puVar1,(int)uVar9,&local_48);
      local_3c = local_3c - local_48;
      local_38 = local_38 - local_44;
      local_34 = local_34 - local_40;
      iVar3 = FUN_80021884();
      *puVar1 = (short)iVar3;
      FUN_80293900((double)(local_3c * local_3c + local_34 * local_34));
      iVar3 = FUN_80021884();
      puVar1[1] = 0x4000 - (short)iVar3;
      puVar1[2] = 0;
    }
  }
  FUN_8028687c();
  return;
}

