// Function: FUN_80038524
// Entry: 80038524
// Size: 444 bytes

void FUN_80038524(undefined4 param_1,undefined4 param_2,float *param_3,undefined4 *param_4,
                 float *param_5,int param_6)

{
  ushort *puVar1;
  int *piVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  undefined2 local_118;
  undefined2 local_116;
  undefined2 local_114;
  float local_10c;
  undefined4 local_108;
  float local_104;
  float afStack_100 [16];
  float afStack_c0 [3];
  float local_b4;
  undefined4 local_a4;
  float local_94;
  float afStack_90 [12];
  float afStack_60 [24];
  
  uVar6 = FUN_80286838();
  puVar1 = (ushort *)((ulonglong)uVar6 >> 0x20);
  iVar5 = (int)uVar6;
  if ((iVar5 < 0) || ((int)(uint)*(byte *)(*(int *)(puVar1 + 0x28) + 0x58) <= iVar5)) {
    *param_3 = *(float *)(puVar1 + 6);
    *param_4 = *(undefined4 *)(puVar1 + 8);
    *param_5 = *(float *)(puVar1 + 10);
  }
  else {
    piVar2 = (int *)FUN_8002b660((int)puVar1);
    iVar5 = iVar5 * 0x18;
    iVar4 = (int)*(char *)(*(int *)(*(int *)(puVar1 + 0x28) + 0x2c) + iVar5 +
                           (int)*(char *)((int)puVar1 + 0xad) + 0x12);
    if ((iVar4 < -1) || ((int)(uint)*(byte *)(*piVar2 + 0xf3) <= iVar4)) {
      *param_3 = *(float *)(puVar1 + 6);
      *param_4 = *(undefined4 *)(puVar1 + 8);
      *param_5 = *(float *)(puVar1 + 10);
    }
    else {
      if (iVar4 == -1) {
        FUN_8002b554(puVar1,afStack_60,'\0');
        pfVar3 = afStack_60;
      }
      else {
        pfVar3 = (float *)FUN_80028630(piVar2,iVar4);
      }
      if (param_6 == 0) {
        local_10c = *(float *)(*(int *)(*(int *)(puVar1 + 0x28) + 0x2c) + iVar5);
        iVar5 = *(int *)(*(int *)(puVar1 + 0x28) + 0x2c) + iVar5;
        local_108 = *(undefined4 *)(iVar5 + 4);
        local_104 = *(float *)(iVar5 + 8);
        local_118 = *(undefined2 *)(iVar5 + 0xc);
        local_116 = *(undefined2 *)(iVar5 + 0xe);
        local_114 = *(undefined2 *)(iVar5 + 0x10);
      }
      else {
        local_10c = *param_3;
        local_108 = *param_4;
        local_104 = *param_5;
        local_118 = 0;
        local_116 = 0;
        local_114 = 0;
      }
      FUN_80021c64(afStack_100,(int)&local_118);
      FUN_800216cc(afStack_100,afStack_90);
      FUN_80247618(pfVar3,afStack_90,afStack_c0);
      *param_3 = local_b4 + FLOAT_803dda58;
      *param_4 = local_a4;
      *param_5 = local_94 + FLOAT_803dda5c;
    }
  }
  FUN_80286884();
  return;
}

