// Function: FUN_802091a8
// Entry: 802091a8
// Size: 524 bytes

void FUN_802091a8(int param_1)

{
  char cVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  undefined auStack_28 [12];
  float local_1c;
  float local_18;
  float local_14;
  
  piVar5 = *(int **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (*(short *)(param_1 + 0x46) == 0x4e0) {
    local_1c = FLOAT_803e7124;
    local_18 = FLOAT_803e715c;
    local_14 = FLOAT_803e7124;
    FUN_800979c0((double)FLOAT_803e7160,(double)FLOAT_803e715c,(double)FLOAT_803e715c,
                 (double)FLOAT_803e7148,param_1,5,1,2,0x32,(int)auStack_28,0);
  }
  else {
    if (*(char *)((int)piVar5 + 0x6b) == '\0') {
      uVar3 = FUN_80020078((int)*(short *)((int)piVar5 + 0x66));
      *(char *)((int)piVar5 + 0x6b) = (char)uVar3;
    }
    if (*(char *)((int)piVar5 + 0x6a) == '\0') {
      uVar3 = FUN_80020078((int)*(short *)(piVar5 + 0x19));
      *(char *)((int)piVar5 + 0x6a) = (char)uVar3;
    }
    fVar2 = FLOAT_803e7144;
    if (((*(char *)((int)piVar5 + 0x6b) == '\0') && (*(char *)((int)piVar5 + 0x6a) != '\0')) &&
       (cVar1 = *(char *)((int)piVar5 + 0x69), cVar1 != '\x04')) {
      if ((cVar1 == '\0') || (cVar1 == '\x02')) {
        if (*(float *)(param_1 + 0x10) <= *(float *)(iVar4 + 0xc)) {
          *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803dc074;
          if (*(float *)(iVar4 + 0xc) <= *(float *)(param_1 + 0x10)) {
            *(float *)(param_1 + 0x10) = *(float *)(iVar4 + 0xc);
            *(undefined *)((int)piVar5 + 0x69) = 1;
          }
        }
      }
      else if (cVar1 == '\x03') {
        if (*(float *)(iVar4 + 0xc) - FLOAT_803e7144 <= *(float *)(param_1 + 0x10)) {
          *(float *)(param_1 + 0x10) = FLOAT_803e712c * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
          fVar2 = *(float *)(iVar4 + 0xc) - fVar2;
          if (*(float *)(param_1 + 0x10) <= fVar2) {
            *(float *)(param_1 + 0x10) = fVar2;
            *(undefined *)((int)piVar5 + 0x69) = 4;
            FUN_800201ac((int)*(short *)((int)piVar5 + 0x66),1);
          }
        }
      }
      else if (*piVar5 != 0) {
        (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_1);
        (**(code **)(*DAT_803dd728 + 0x14))(param_1,*piVar5);
        (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_1,*piVar5);
      }
    }
  }
  return;
}

