// Function: FUN_8010cd5c
// Entry: 8010cd5c
// Size: 348 bytes

void FUN_8010cd5c(int param_1,undefined4 param_2,undefined4 *param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  *(undefined4 *)(param_1 + 0x11c) = *param_3;
  iVar5 = *(int *)(param_1 + 0xa4);
  if (DAT_803dd568 == (float *)0x0) {
    DAT_803dd568 = (float *)FUN_80023cc8(0x1c,0xf,0);
  }
  fVar1 = FLOAT_803e18c4;
  DAT_803dd568[1] = FLOAT_803e18c4;
  DAT_803dd568[2] = FLOAT_803e18c0;
  *(undefined *)((int)DAT_803dd568 + 0x12) = 0;
  *(undefined *)((int)DAT_803dd568 + 0x11) = 0;
  *(undefined *)((int)DAT_803dd568 + 0x13) = 1;
  *(undefined *)(DAT_803dd568 + 5) = 1;
  DAT_803dd568[6] = fVar1;
  if (*(short *)(iVar5 + 0x44) == 1) {
    iVar4 = *(int *)(param_1 + 0x11c);
    if (iVar4 == 0) {
      *(undefined *)((int)DAT_803dd568 + 0x12) = 1;
    }
    else {
      if (*(int *)(iVar4 + 0x74) == 0) {
        fVar1 = *(float *)(iVar5 + 0x18) - *(float *)(iVar4 + 0x18);
        fVar2 = *(float *)(iVar5 + 0x20) - *(float *)(iVar4 + 0x20);
      }
      else {
        iVar3 = *(int *)(iVar4 + 0x74) + (uint)*(byte *)(iVar4 + 0xe4) * 0x18;
        fVar1 = *(float *)(iVar3 + 0xc) - *(float *)(iVar5 + 0x18);
        fVar2 = *(float *)(iVar3 + 0x14) - *(float *)(iVar5 + 0x20);
      }
      if (*(short *)(iVar4 + 0x44) == 0x6d) {
        *DAT_803dd568 = FLOAT_803e1940;
      }
      else {
        dVar6 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
        *DAT_803dd568 = (float)dVar6;
      }
      *(undefined *)(DAT_803dd568 + 4) = 0;
    }
  }
  else {
    *(undefined *)((int)DAT_803dd568 + 0x12) = 1;
  }
  return;
}

