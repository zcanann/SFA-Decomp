// Function: FUN_80161c44
// Entry: 80161c44
// Size: 356 bytes

undefined4 FUN_80161c44(int param_1,int param_2)

{
  short sVar2;
  undefined4 uVar1;
  int iVar3;
  double dVar4;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14 [2];
  
  iVar3 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2eb8,param_1,5,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2ef0;
  (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar3 + 0x48) - FLOAT_803e2efc),*(int *)(iVar3 + 0x38),&local_28,
             &local_24,&local_20);
  (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e2efc + *(float *)(iVar3 + 0x48)),*(int *)(iVar3 + 0x38),&local_1c,
             &local_18,local_14);
  local_28 = local_28 - local_1c;
  local_24 = local_24 - local_18;
  local_20 = local_20 - local_14[0];
  dVar4 = (double)FUN_802931a0((double)(local_28 * local_28 + local_20 * local_20));
  local_28 = (float)dVar4;
  sVar2 = FUN_800217c0((double)local_24,(double)(float)dVar4);
  *(short *)(param_1 + 2) = sVar2 * ((short)((int)*(char *)(iVar3 + 0x45) << 1) + -1);
  if (*(char *)(param_2 + 0x346) == '\0') {
    uVar1 = 0;
  }
  else {
    uVar1 = 6;
  }
  return uVar1;
}

