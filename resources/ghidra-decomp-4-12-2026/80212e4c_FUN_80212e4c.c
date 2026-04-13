// Function: FUN_80212e4c
// Entry: 80212e4c
// Size: 324 bytes

undefined4 FUN_80212e4c(int param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if ((*(ushort *)(DAT_803de9d4 + 0xfa) & 8) == 0) {
      fVar1 = *(float *)(DAT_803de9d4 + 4) - FLOAT_803dc074;
      *(float *)(DAT_803de9d4 + 4) = fVar1;
      if (FLOAT_803e7450 < fVar1) goto LAB_80212f74;
    }
    if ((*(ushort *)(DAT_803de9d4 + 0xfa) & 8) != 0) {
      *(char *)(DAT_803de9d4 + 0x102) = *(char *)(DAT_803de9d4 + 0x102) + -1;
      *(undefined *)(param_2 + 0x354) = 3;
    }
    *(ushort *)(DAT_803de9d4 + 0xfa) = *(ushort *)(DAT_803de9d4 + 0xfa) & 0xffef;
    if (*(char *)(DAT_803de9d4 + 0x102) == '\0') {
      uVar2 = 2;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      uVar2 = 10;
    }
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,7);
    *(float *)(DAT_803de9d4 + 4) =
         (float)((double)CONCAT44(0x43300000,
                                  (uint)*(ushort *)
                                         (iVar3 + (*(byte *)(DAT_803de9d4 + 0x101) & 0xfffffffe) +
                                         0x4a)) - DOUBLE_803e7478);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
LAB_80212f74:
    uVar2 = 0;
  }
  return uVar2;
}

