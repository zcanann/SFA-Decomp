// Function: FUN_80161af8
// Entry: 80161af8
// Size: 332 bytes

undefined4 FUN_80161af8(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  double dVar3;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14 [2];
  
  iVar2 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2eb8,param_1,6,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2ef0;
  (**(code **)(**(int **)(*(int *)(iVar2 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar2 + 0x48) - FLOAT_803e2efc),*(int *)(iVar2 + 0x38),&local_28,
             &local_24,&local_20);
  (**(code **)(**(int **)(*(int *)(iVar2 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e2efc + *(float *)(iVar2 + 0x48)),*(int *)(iVar2 + 0x38),&local_1c,
             &local_18,local_14);
  local_28 = local_28 - local_1c;
  local_24 = local_24 - local_18;
  local_20 = local_20 - local_14[0];
  dVar3 = (double)FUN_802931a0((double)(local_28 * local_28 + local_20 * local_20));
  local_28 = (float)dVar3;
  sVar1 = FUN_800217c0((double)local_24,(double)(float)dVar3);
  *(short *)(param_1 + 2) = sVar1 * ((short)((int)*(char *)(iVar2 + 0x45) << 1) + -1);
  return 0;
}

