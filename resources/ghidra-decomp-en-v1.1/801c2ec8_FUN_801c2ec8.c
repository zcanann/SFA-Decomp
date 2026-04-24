// Function: FUN_801c2ec8
// Entry: 801c2ec8
// Size: 852 bytes

/* WARNING: Removing unreachable block (ram,0x801c31f4) */
/* WARNING: Removing unreachable block (ram,0x801c2ed8) */

void FUN_801c2ec8(ushort *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 local_30;
  
  iVar4 = *(int *)(param_1 + 0x26);
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_8002bac4();
  if ((param_1[3] & 0x4000) == 0) {
    *(short *)(iVar3 + 0x14) =
         *(short *)(iVar3 + 0x14) + (short)(int)(FLOAT_803e5ae8 * FLOAT_803dc074);
    *(short *)(iVar3 + 0x16) =
         *(short *)(iVar3 + 0x16) + (short)(int)(FLOAT_803e5aec * FLOAT_803dc074);
    *(short *)(iVar3 + 0x18) =
         *(short *)(iVar3 + 0x18) + (short)(int)(FLOAT_803e5af0 * FLOAT_803dc074);
    dVar5 = (double)FUN_802945e0();
    *(float *)(param_1 + 8) = FLOAT_803e5af4 + (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
    dVar5 = (double)FUN_802945e0();
    dVar6 = (double)FUN_802945e0();
    param_1[2] = (ushort)(int)(FLOAT_803e5b00 * (float)(dVar6 + dVar5));
    dVar5 = (double)FUN_802945e0();
    dVar6 = (double)FUN_802945e0();
    param_1[1] = (ushort)(int)(FLOAT_803e5b00 * (float)(dVar6 + dVar5));
    FUN_8002fb40((double)FLOAT_803e5b04,(double)FLOAT_803dc074);
    if (iVar1 != 0) {
      uVar2 = FUN_80021884();
      uVar2 = (uVar2 & 0xffff) - (uint)*param_1;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *param_1 = *param_1 +
                 (short)(int)(((float)(local_30 - DOUBLE_803e5b18) * FLOAT_803dc074) /
                             FLOAT_803e5b08);
      dVar5 = (double)FUN_80021754((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      if ((double)FLOAT_803e5b0c < dVar5) {
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      else {
        *(char *)(param_1 + 0x1b) =
             (char)(int)(FLOAT_803e5b10 * (float)(dVar5 / (double)FLOAT_803e5b0c));
      }
    }
  }
  else {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
  }
  return;
}

