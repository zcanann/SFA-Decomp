// Function: FUN_8003b620
// Entry: 8003b620
// Size: 664 bytes

void FUN_8003b620(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined2 *puVar1;
  undefined4 uVar2;
  undefined2 uVar3;
  short sVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined8 uVar11;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  
  uVar11 = FUN_802860cc();
  puVar1 = (undefined2 *)((ulonglong)uVar11 >> 0x20);
  if ((1 < *(byte *)(*(int *)(puVar1 + 0x28) + 0x58)) && (puVar1[0x22] == 0x2d)) {
    iVar7 = *(int *)(puVar1 + 0x5c);
    iVar10 = 1;
    iVar6 = 0x18;
    iVar9 = iVar7;
    for (iVar8 = 0; iVar8 < *(short *)(iVar7 + 0xb0); iVar8 = iVar8 + 1) {
      if (iVar10 < (int)(uint)*(byte *)(*(int *)(puVar1 + 0x28) + 0x58)) {
        uVar2 = FUN_8002856c(param_3,(int)*(char *)(*(int *)(*(int *)(puVar1 + 0x28) + 0x2c) +
                                                   iVar6 + *(char *)((int)puVar1 + 0xad) + 0x2a));
        iVar5 = *(int *)(*(int *)(puVar1 + 0x28) + 0x2c);
        local_3c = *(float *)(iVar5 + iVar6 + 0x18);
        local_38 = *(float *)(iVar5 + iVar6 + 0x1c);
        local_34 = *(float *)(iVar5 + iVar6 + 0x20);
        FUN_80247494(uVar2,&local_3c,&local_3c);
        local_3c = local_3c + FLOAT_803dcdd8;
        local_34 = local_34 + FLOAT_803dcddc;
        *(float *)(iVar9 + 0x6c) = local_3c;
        *(float *)(iVar9 + 0x74) = local_38;
        *(float *)(iVar9 + 0x7c) = local_34;
      }
      if (iVar10 < (int)(uint)*(byte *)(*(int *)(puVar1 + 0x28) + 0x58)) {
        iVar5 = *(int *)(*(int *)(puVar1 + 0x28) + 0x2c);
        local_48 = *(float *)(iVar5 + iVar6);
        local_44 = *(float *)(iVar5 + iVar6 + 4);
        local_40 = *(float *)(iVar5 + iVar6 + 8);
        FUN_80247494(*(int *)(param_3 + (*(ushort *)(param_3 + 0x18) & 1) * 4 + 0xc) +
                     *(char *)((int)(float *)(iVar5 + iVar6) + *(char *)((int)puVar1 + 0xad) + 0x12)
                     * 0x40,&local_48,&local_48);
        local_48 = local_48 + FLOAT_803dcdd8;
        local_40 = local_40 + FLOAT_803dcddc;
        *(float *)(iVar9 + 0x54) = local_48;
        *(float *)(iVar9 + 0x5c) = local_44;
        *(float *)(iVar9 + 100) = local_40;
      }
      iVar10 = iVar10 + 2;
      iVar6 = iVar6 + 0x30;
      iVar9 = iVar9 + 4;
    }
    if (*(short *)(iVar7 + 0xb0) != 0) {
      iVar7 = iVar7 + *(short *)(iVar7 + 0xb2) * 4;
      local_3c = *(float *)(iVar7 + 0x6c);
      local_38 = *(float *)(iVar7 + 0x74);
      local_34 = *(float *)(iVar7 + 0x7c);
      (**(code **)(**(int **)(puVar1 + 0x34) + 0x28))(puVar1,(int)uVar11,&local_48);
      local_3c = local_3c - local_48;
      local_38 = local_38 - local_44;
      local_34 = local_34 - local_40;
      uVar3 = FUN_800217c0();
      *puVar1 = uVar3;
      uVar11 = FUN_802931a0((double)(local_3c * local_3c + local_34 * local_34));
      sVar4 = FUN_800217c0((double)local_38,uVar11);
      puVar1[1] = 0x4000 - sVar4;
      puVar1[2] = 0;
    }
  }
  FUN_80286118();
  return;
}

