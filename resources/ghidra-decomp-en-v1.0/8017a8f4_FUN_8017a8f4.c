// Function: FUN_8017a8f4
// Entry: 8017a8f4
// Size: 552 bytes

void FUN_8017a8f4(int param_1)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  pcVar4 = *(char **)(param_1 + 0xb8);
  if (*pcVar4 == '\0') {
    iVar2 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x18));
    if (iVar2 != 0) {
      *pcVar4 = '\x01';
    }
  }
  else {
    iVar2 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x18));
    if (iVar2 == 0) {
      *pcVar4 = '\0';
    }
  }
  fVar1 = FLOAT_803e3730;
  if (FLOAT_803e3730 < *(float *)(pcVar4 + 4)) {
    *(float *)(pcVar4 + 4) =
         *(float *)(pcVar4 + 4) -
         (float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e3740);
    if (fVar1 < *(float *)(pcVar4 + 4)) {
      return;
    }
    *(float *)(pcVar4 + 4) = fVar1;
    FUN_800200e8((int)*(short *)(iVar5 + 0x18),0);
  }
  if (*(float *)(pcVar4 + 8) == FLOAT_803e3730) {
    uVar3 = FUN_8003687c(param_1,0,0,0);
    if ((byte)pcVar4[1] == uVar3) {
      if (*pcVar4 == '\0') {
        if ((*(byte *)(iVar5 + 0x1e) & 3) == 3) {
          *(float *)(pcVar4 + 8) = FLOAT_803e3738;
        }
        else {
          *pcVar4 = '\x01';
          FUN_800200e8((int)*(short *)(iVar5 + 0x18),1);
          if ((*(byte *)(iVar5 + 0x1e) & 3) == 2) {
            *(float *)(pcVar4 + 4) =
                 FLOAT_803e3734 *
                 FLOAT_803e373c *
                 (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1a) ^ 0x80000000) -
                        DOUBLE_803e3748);
          }
        }
      }
      else if ((*(byte *)(iVar5 + 0x1e) & 3) == 1) {
        *pcVar4 = '\0';
        FUN_800200e8((int)*(short *)(iVar5 + 0x18),0);
      }
    }
  }
  else {
    *(float *)(pcVar4 + 8) = *(float *)(pcVar4 + 8) - FLOAT_803db414;
    if (*(float *)(pcVar4 + 8) < FLOAT_803e3734) {
      uVar3 = FUN_8003687c(param_1,0,0,0);
      if ((byte)pcVar4[1] == uVar3) {
        *(float *)(pcVar4 + 8) = FLOAT_803e3730;
        *pcVar4 = '\x01';
        FUN_800200e8((int)*(short *)(iVar5 + 0x18),1);
      }
      else if (*(float *)(pcVar4 + 8) <= FLOAT_803e3730) {
        *(float *)(pcVar4 + 8) = FLOAT_803e3730;
      }
    }
  }
  return;
}

