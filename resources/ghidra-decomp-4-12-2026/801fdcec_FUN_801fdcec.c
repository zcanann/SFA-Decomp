// Function: FUN_801fdcec
// Entry: 801fdcec
// Size: 852 bytes

/* WARNING: Removing unreachable block (ram,0x801fe01c) */
/* WARNING: Removing unreachable block (ram,0x801fdcfc) */

void FUN_801fdcec(uint param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined auStack_58 [8];
  undefined4 local_50;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36));
  dVar5 = local_40 - DOUBLE_803e6e38;
  *(float *)(iVar4 + 0xc) =
       FLOAT_803dc074 * ((FLOAT_803e6df8 * *(float *)(iVar4 + 0x10)) / FLOAT_803e6df8) +
       *(float *)(iVar4 + 0xc);
  fVar1 = (float)dVar5;
  if (FLOAT_803e6dfc < *(float *)(iVar4 + 0xc)) {
    uVar2 = FUN_80022264(0x32,100);
    local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(float *)(iVar4 + 0x10) = (float)(local_40 - DOUBLE_803e6e40);
    uVar2 = FUN_80022264(0x15e,800);
    local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x1a) ^ 0x80000000);
    *(float *)(iVar4 + 8) =
         FLOAT_803e6e00 /
         ((float)(local_30 - DOUBLE_803e6e40) / (float)(local_38 - DOUBLE_803e6e40));
    *(float *)(iVar4 + 0xc) = FLOAT_803e6e04;
    FUN_8000bb38(param_1,0x111);
    fVar1 = FLOAT_803e6e08;
  }
  dVar6 = (double)fVar1;
  local_30 = (double)(longlong)(int)*(float *)(iVar4 + 0xc);
  local_38 = (double)CONCAT44(0x43300000,(int)(short)(int)*(float *)(iVar4 + 0xc) ^ 0x80000000);
  dVar5 = (double)FUN_802945e0();
  FLOAT_803de950 = (float)dVar5;
  *(float *)(param_1 + 8) =
       FLOAT_803e6e14 * *(float *)(iVar4 + 8) +
       FLOAT_803e6e18 * *(float *)(iVar4 + 8) * (float)dVar5;
  if (((FLOAT_803e6e1c < *(float *)(iVar4 + 0xc)) && (*(float *)(iVar4 + 0xc) < FLOAT_803e6e20)) &&
     (local_50 = *(undefined4 *)(iVar4 + 8), (*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x3a2,auStack_58,2,0xffffffff,0);
  }
  fVar1 = *(float *)(iVar4 + 0xc);
  if (FLOAT_803e6e24 < fVar1) {
    local_30 = (double)(longlong)(int)(FLOAT_803e6e08 * FLOAT_803de950);
    local_38 = (double)CONCAT44(0x43300000,
                                (int)(short)(int)(FLOAT_803e6e08 * FLOAT_803de950) ^ 0x80000000);
    dVar6 = (double)(float)(local_38 - DOUBLE_803e6e40);
  }
  if (fVar1 < FLOAT_803e6e28) {
    dVar6 = (double)(FLOAT_803e6e08 * (fVar1 / FLOAT_803e6e28));
  }
  dVar5 = (double)FLOAT_803e6e04;
  if ((dVar5 <= dVar6) && (dVar5 = dVar6, (double)FLOAT_803e6e08 < dVar6)) {
    dVar5 = (double)FLOAT_803e6e08;
  }
  local_40 = (double)(longlong)(int)dVar5;
  *(char *)(param_1 + 0x36) = (char)(int)dVar5;
  iVar3 = FUN_800395a4(param_1,0);
  if (iVar3 != 0) {
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 10) ^ 0x80000000);
    fVar1 = (float)(local_30 - DOUBLE_803e6e40) + FLOAT_803e6df8;
    if (FLOAT_803e6e2c <= fVar1) {
      fVar1 = fVar1 - FLOAT_803e6e2c;
    }
    local_38 = (double)(longlong)(int)fVar1;
    *(short *)(iVar3 + 10) = (short)(int)fVar1;
  }
  iVar3 = FUN_800395a4(param_1,1);
  if (iVar3 != 0) {
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 10) ^ 0x80000000);
    fVar1 = (float)(local_30 - DOUBLE_803e6e40) + FLOAT_803e6e30;
    if (FLOAT_803e6e2c <= fVar1) {
      fVar1 = fVar1 - FLOAT_803e6e2c;
    }
    *(short *)(iVar3 + 10) = (short)(int)fVar1;
  }
  return;
}

