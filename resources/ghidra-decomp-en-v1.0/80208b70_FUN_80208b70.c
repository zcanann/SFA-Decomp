// Function: FUN_80208b70
// Entry: 80208b70
// Size: 524 bytes

void FUN_80208b70(int param_1)

{
  char cVar1;
  float fVar2;
  undefined uVar3;
  int iVar4;
  int *piVar5;
  undefined auStack40 [12];
  float local_1c;
  float local_18;
  float local_14;
  
  piVar5 = *(int **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (*(short *)(param_1 + 0x46) == 0x4e0) {
    local_1c = FLOAT_803e648c;
    local_18 = FLOAT_803e64c4;
    local_14 = FLOAT_803e648c;
    FUN_80097734((double)FLOAT_803e64c8,(double)FLOAT_803e64c4,(double)FLOAT_803e64c4,
                 (double)FLOAT_803e64b0,param_1,5,1,2,0x32,auStack40,0);
  }
  else {
    if (*(char *)((int)piVar5 + 0x6b) == '\0') {
      uVar3 = FUN_8001ffb4((int)*(short *)((int)piVar5 + 0x66));
      *(undefined *)((int)piVar5 + 0x6b) = uVar3;
    }
    if (*(char *)((int)piVar5 + 0x6a) == '\0') {
      uVar3 = FUN_8001ffb4((int)*(short *)(piVar5 + 0x19));
      *(undefined *)((int)piVar5 + 0x6a) = uVar3;
    }
    fVar2 = FLOAT_803e64ac;
    if (((*(char *)((int)piVar5 + 0x6b) == '\0') && (*(char *)((int)piVar5 + 0x6a) != '\0')) &&
       (cVar1 = *(char *)((int)piVar5 + 0x69), cVar1 != '\x04')) {
      if ((cVar1 == '\0') || (cVar1 == '\x02')) {
        if (*(float *)(param_1 + 0x10) <= *(float *)(iVar4 + 0xc)) {
          *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803db414;
          if (*(float *)(iVar4 + 0xc) <= *(float *)(param_1 + 0x10)) {
            *(float *)(param_1 + 0x10) = *(float *)(iVar4 + 0xc);
            *(undefined *)((int)piVar5 + 0x69) = 1;
          }
        }
      }
      else if (cVar1 == '\x03') {
        if (*(float *)(iVar4 + 0xc) - FLOAT_803e64ac <= *(float *)(param_1 + 0x10)) {
          *(float *)(param_1 + 0x10) = FLOAT_803e6494 * FLOAT_803db414 + *(float *)(param_1 + 0x10);
          fVar2 = *(float *)(iVar4 + 0xc) - fVar2;
          if (*(float *)(param_1 + 0x10) <= fVar2) {
            *(float *)(param_1 + 0x10) = fVar2;
            *(undefined *)((int)piVar5 + 0x69) = 4;
            FUN_800200e8((int)*(short *)((int)piVar5 + 0x66),1);
          }
        }
      }
      else if (*piVar5 != 0) {
        (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1);
        (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,*piVar5);
        (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,*piVar5);
      }
    }
  }
  return;
}

