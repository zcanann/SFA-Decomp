// Function: FUN_801d3b8c
// Entry: 801d3b8c
// Size: 672 bytes

void FUN_801d3b8c(int param_1,int param_2)

{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  uVar1 = *(ushort *)(iVar4 + 0x1c);
  uVar2 = FUN_80022264(0,100);
  if ((int)uVar2 < 10) {
    if (*(float *)(param_2 + 0x2a0) <= FLOAT_803e602c) {
      uVar2 = FUN_80022264(2000,4000);
      *(short *)(param_2 + 0x2ac) = (short)uVar2;
      uVar2 = FUN_80022264(0,1);
      if (uVar2 != 0) {
        *(short *)(param_2 + 0x2ac) = -*(short *)(param_2 + 0x2ac);
      }
      *(short *)(param_2 + 0x2ac) = *(short *)(param_2 + 0x2ac) + *(short *)(param_2 + 0x2a8);
      iVar3 = (int)*(short *)(param_2 + 0x2ac) - (uint)uVar1;
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      if (*(short *)(iVar4 + 0x1a) < iVar3) {
        *(ushort *)(param_2 + 0x2ac) = uVar1 + *(short *)(iVar4 + 0x1a);
      }
      if (iVar3 < -(int)*(short *)(iVar4 + 0x1a)) {
        *(ushort *)(param_2 + 0x2ac) = uVar1 - *(short *)(iVar4 + 0x1a);
      }
      *(float *)(param_2 + 0x2a0) = FLOAT_803e6040;
    }
  }
  uVar2 = FUN_80022264(0,100);
  if ((int)uVar2 < 10) {
    if (*(float *)(param_2 + 0x2a0) <= FLOAT_803e602c) {
      uVar2 = FUN_80022264(0xffffff38,200);
      *(float *)(param_2 + 0x280) =
           *(float *)(param_2 + 0x278) +
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6038) /
           FLOAT_803e6028;
      if (FLOAT_803e6044 <= *(float *)(param_2 + 0x280)) {
        if (FLOAT_803e6048 < *(float *)(param_2 + 0x280)) {
          *(float *)(param_2 + 0x280) = FLOAT_803e6048;
        }
      }
      else {
        *(float *)(param_2 + 0x280) = FLOAT_803e6044;
      }
    }
  }
  iVar4 = (int)*(short *)(param_2 + 0x2ac) - (uint)*(ushort *)(param_2 + 0x2a8);
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  *(short *)(param_2 + 0x2a8) =
       *(short *)(param_2 + 0x2a8) + (short)((int)(iVar4 * (uint)DAT_803dc070) >> 4);
  *(float *)(param_2 + 0x278) =
       FLOAT_803e604c * (*(float *)(param_2 + 0x280) - *(float *)(param_2 + 0x278)) * FLOAT_803dc074
       + *(float *)(param_2 + 0x278);
  dVar5 = (double)FUN_802945e0();
  *(float *)(param_2 + 0x288) = (float)((double)*(float *)(param_2 + 0x278) * dVar5);
  dVar5 = (double)FUN_80294964();
  *(float *)(param_2 + 0x28c) = (float)((double)*(float *)(param_2 + 0x278) * dVar5);
  return;
}

