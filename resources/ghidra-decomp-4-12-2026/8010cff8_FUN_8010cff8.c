// Function: FUN_8010cff8
// Entry: 8010cff8
// Size: 348 bytes

void FUN_8010cff8(int param_1,undefined4 param_2,undefined4 *param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  *(undefined4 *)(param_1 + 0x11c) = *param_3;
  iVar5 = *(int *)(param_1 + 0xa4);
  if (DAT_803de1e0 == (float *)0x0) {
    DAT_803de1e0 = (float *)FUN_80023d8c(0x1c,0xf);
  }
  fVar1 = FLOAT_803e2544;
  DAT_803de1e0[1] = FLOAT_803e2544;
  DAT_803de1e0[2] = FLOAT_803e2540;
  *(undefined *)((int)DAT_803de1e0 + 0x12) = 0;
  *(undefined *)((int)DAT_803de1e0 + 0x11) = 0;
  *(undefined *)((int)DAT_803de1e0 + 0x13) = 1;
  *(undefined *)(DAT_803de1e0 + 5) = 1;
  DAT_803de1e0[6] = fVar1;
  if (*(short *)(iVar5 + 0x44) == 1) {
    iVar4 = *(int *)(param_1 + 0x11c);
    if (iVar4 == 0) {
      *(undefined *)((int)DAT_803de1e0 + 0x12) = 1;
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
        *DAT_803de1e0 = FLOAT_803e25c0;
      }
      else {
        dVar6 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
        *DAT_803de1e0 = (float)dVar6;
      }
      *(undefined *)(DAT_803de1e0 + 4) = 0;
    }
  }
  else {
    *(undefined *)((int)DAT_803de1e0 + 0x12) = 1;
  }
  return;
}

