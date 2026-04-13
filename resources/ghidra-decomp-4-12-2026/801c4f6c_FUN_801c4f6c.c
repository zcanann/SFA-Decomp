// Function: FUN_801c4f6c
// Entry: 801c4f6c
// Size: 344 bytes

undefined4 FUN_801c4f6c(int param_1)

{
  float fVar1;
  float fVar2;
  char cVar4;
  undefined4 uVar3;
  int iVar5;
  undefined8 local_18;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if ((*(uint *)(iVar5 + 0x18) & 0x20) == 0) {
    FUN_8011f9b8(1);
    *(uint *)(iVar5 + 0x18) = *(uint *)(iVar5 + 0x18) | 0x20;
    fVar1 = FLOAT_803e5bd8;
    *(float *)(iVar5 + 4) = FLOAT_803e5bd8;
    *(float *)(iVar5 + 8) = fVar1;
    *(float *)(iVar5 + 0xc) = fVar1;
  }
  cVar4 = FUN_80014cec(0);
  fVar2 = FLOAT_803e5be0;
  local_18 = (double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000);
  *(float *)(iVar5 + 8) =
       ((float)(local_18 - DOUBLE_803e5bd0) / FLOAT_803e5bdc) * FLOAT_803e5be0 * FLOAT_803dc074 +
       *(float *)(iVar5 + 8);
  fVar1 = *(float *)(iVar5 + 0x10);
  if ((FLOAT_803e5bd8 <= fVar1) || (*(float *)(iVar5 + 0xc) <= fVar1)) {
    if ((FLOAT_803e5bd8 < fVar1) && (*(float *)(iVar5 + 0xc) < fVar1)) {
      *(float *)(iVar5 + 0xc) = FLOAT_803e5be0 * FLOAT_803dc074 + *(float *)(iVar5 + 0xc);
    }
  }
  else {
    *(float *)(iVar5 + 0xc) = -(fVar2 * FLOAT_803dc074 - *(float *)(iVar5 + 0xc));
  }
  *(float *)(iVar5 + 4) =
       FLOAT_803dc074 * (*(float *)(iVar5 + 8) + *(float *)(iVar5 + 0xc)) + *(float *)(iVar5 + 4);
  iVar5 = (int)(FLOAT_803e5be4 * *(float *)(iVar5 + 4));
  FUN_8011f9c4(0x60,0x39,(short)iVar5);
  if ((iVar5 < 0x3a) && (-0x3a < iVar5)) {
    uVar3 = 0;
  }
  else {
    uVar3 = 1;
  }
  return uVar3;
}

