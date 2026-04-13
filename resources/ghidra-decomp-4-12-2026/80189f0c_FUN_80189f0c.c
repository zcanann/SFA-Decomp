// Function: FUN_80189f0c
// Entry: 80189f0c
// Size: 560 bytes

void FUN_80189f0c(uint param_1,int param_2)

{
  double dVar1;
  int iVar2;
  uint uVar3;
  undefined8 local_18;
  
  dVar1 = DOUBLE_803e4868;
  if (((char)*(byte *)(param_2 + 0x1d) < '\0') && ((*(byte *)(param_2 + 0x1d) >> 6 & 1) == 0)) {
    if (*(char *)(param_2 + 0x1c) == '\0') {
      *(int *)(param_2 + 0xc) =
           (int)-(FLOAT_803e4860 * FLOAT_803dc074 -
                 (float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0xc) ^ 0x80000000) -
                        DOUBLE_803e4868));
      *(int *)(param_2 + 0x14) =
           (int)((float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0xc) ^ 0x80000000) - dVar1)
                 * FLOAT_803dc074 +
                (float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x14) ^ 0x80000000) - dVar1)
                );
      if (*(int *)(param_2 + 0x18) < *(int *)(param_2 + 0x14)) {
        *(int *)(param_2 + 0x18) = *(int *)(param_2 + 0x14);
      }
      if ((*(int *)(param_2 + 0x10) == 0x800) && (*(int *)(param_2 + 0x14) < 0x800)) {
        FUN_8000bb38(param_1,0x374);
      }
      if (*(int *)(param_2 + 0x14) < 0) {
        if (0 < *(int *)(param_2 + 0x10)) {
          FUN_8000bb38(param_1,0x6e);
          iVar2 = *(int *)(param_2 + 0x18) / 200 + (*(int *)(param_2 + 0x18) >> 0x1f);
          uVar3 = iVar2 - (iVar2 >> 0x1f);
          if (0 < (int)uVar3) {
            local_18 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
            FUN_80014acc((double)(float)(local_18 - DOUBLE_803e4868));
          }
        }
        *(undefined4 *)(param_2 + 0xc) = 0;
        *(undefined4 *)(param_2 + 0x14) = 0;
      }
    }
    else {
      *(undefined *)(param_2 + 0x1c) = 0;
      *(undefined4 *)(param_2 + 0x18) = 0;
    }
    if (((*(int *)(param_2 + 0x10) < 0x40) && (0x3f < *(int *)(param_2 + 0x14))) ||
       ((0x3f < *(int *)(param_2 + 0x10) && (*(int *)(param_2 + 0x14) < 0x40)))) {
      FUN_8000bb38(param_1,0x374);
    }
    FUN_80037c38(param_1,8,0xb4,0xf0,0xff,0x6f,(float *)(param_2 + 0x20));
    *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(param_2 + 0x14);
    local_18 = (double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x14) ^ 0x80000000);
    FUN_800303fc((double)((float)(local_18 - DOUBLE_803e4868) / FLOAT_803e4864),param_1);
  }
  return;
}

