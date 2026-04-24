// Function: FUN_8017ae38
// Entry: 8017ae38
// Size: 552 bytes

void FUN_8017ae38(int param_1)

{
  float fVar1;
  uint uVar2;
  char *pcVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  pcVar3 = *(char **)(param_1 + 0xb8);
  if (*pcVar3 == '\0') {
    uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x18));
    if (uVar2 != 0) {
      *pcVar3 = '\x01';
    }
  }
  else {
    uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x18));
    if (uVar2 == 0) {
      *pcVar3 = '\0';
    }
  }
  fVar1 = FLOAT_803e43c8;
  if (FLOAT_803e43c8 < *(float *)(pcVar3 + 4)) {
    *(float *)(pcVar3 + 4) =
         *(float *)(pcVar3 + 4) -
         (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e43d8);
    if (fVar1 < *(float *)(pcVar3 + 4)) {
      return;
    }
    *(float *)(pcVar3 + 4) = fVar1;
    FUN_800201ac((int)*(short *)(iVar4 + 0x18),0);
  }
  if (*(float *)(pcVar3 + 8) == FLOAT_803e43c8) {
    uVar2 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if ((byte)pcVar3[1] == uVar2) {
      if (*pcVar3 == '\0') {
        if ((*(byte *)(iVar4 + 0x1e) & 3) == 3) {
          *(float *)(pcVar3 + 8) = FLOAT_803e43d0;
        }
        else {
          *pcVar3 = '\x01';
          FUN_800201ac((int)*(short *)(iVar4 + 0x18),1);
          if ((*(byte *)(iVar4 + 0x1e) & 3) == 2) {
            *(float *)(pcVar3 + 4) =
                 FLOAT_803e43cc *
                 FLOAT_803e43d4 *
                 (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 0x1a) ^ 0x80000000) -
                        DOUBLE_803e43e0);
          }
        }
      }
      else if ((*(byte *)(iVar4 + 0x1e) & 3) == 1) {
        *pcVar3 = '\0';
        FUN_800201ac((int)*(short *)(iVar4 + 0x18),0);
      }
    }
  }
  else {
    *(float *)(pcVar3 + 8) = *(float *)(pcVar3 + 8) - FLOAT_803dc074;
    if (*(float *)(pcVar3 + 8) < FLOAT_803e43cc) {
      uVar2 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if ((byte)pcVar3[1] == uVar2) {
        *(float *)(pcVar3 + 8) = FLOAT_803e43c8;
        *pcVar3 = '\x01';
        FUN_800201ac((int)*(short *)(iVar4 + 0x18),1);
      }
      else if (*(float *)(pcVar3 + 8) <= FLOAT_803e43c8) {
        *(float *)(pcVar3 + 8) = FLOAT_803e43c8;
      }
    }
  }
  return;
}

