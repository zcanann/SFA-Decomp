// Function: FUN_801949b8
// Entry: 801949b8
// Size: 608 bytes

/* WARNING: Removing unreachable block (ram,0x80194bf8) */
/* WARNING: Removing unreachable block (ram,0x80194bf0) */
/* WARNING: Removing unreachable block (ram,0x80194be8) */
/* WARNING: Removing unreachable block (ram,0x80194be0) */
/* WARNING: Removing unreachable block (ram,0x80194bd8) */
/* WARNING: Removing unreachable block (ram,0x801949e8) */
/* WARNING: Removing unreachable block (ram,0x801949e0) */
/* WARNING: Removing unreachable block (ram,0x801949d8) */
/* WARNING: Removing unreachable block (ram,0x801949d0) */
/* WARNING: Removing unreachable block (ram,0x801949c8) */

void FUN_801949b8(void)

{
  float fVar1;
  float fVar2;
  ushort *puVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  int iVar7;
  int iVar8;
  double in_f27;
  double dVar9;
  double in_f28;
  double dVar10;
  double in_f29;
  double dVar11;
  double in_f30;
  double dVar12;
  double in_f31;
  double dVar13;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar14;
  float local_a8;
  float local_a4;
  float local_a0;
  ushort local_9c [6];
  float local_90;
  float local_8c;
  float local_88;
  undefined4 local_80;
  uint uStack_7c;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  uVar14 = FUN_80286838();
  puVar3 = (ushort *)((ulonglong)uVar14 >> 0x20);
  iVar5 = (int)uVar14;
  iVar8 = *(int *)(puVar3 + 0x26);
  iVar7 = 6;
  dVar9 = (double)FLOAT_803e4c68;
  dVar10 = (double)FLOAT_803e4c6c;
  dVar11 = (double)FLOAT_803e4c70;
  dVar12 = (double)FLOAT_803e4c74;
  dVar13 = DOUBLE_803e4c88;
  do {
    uStack_7c = FUN_80022264(0xffffff9c,100);
    uStack_7c = uStack_7c ^ 0x80000000;
    local_80 = 0x43300000;
    local_a8 = (float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,uStack_7c) - dVar13));
    local_a4 = (float)dVar10;
    local_a0 = (float)dVar10;
    uVar4 = FUN_80022264(0xffff8001,0x8000);
    local_9c[2] = (ushort)uVar4;
    local_9c[1] = 0;
    local_9c[0] = 0;
    FUN_80021b8c(local_9c,&local_a8);
    local_a0 = (float)((double)local_a0 - dVar11);
    FUN_80021b8c(puVar3,&local_a8);
    local_9c[2] = *(undefined2 *)(iVar8 + 0x1c);
    local_9c[0] = *puVar3;
    local_90 = *(float *)(puVar3 + 0xc) + local_a8;
    local_8c = (float)(dVar12 + (double)(*(float *)(puVar3 + 0xe) + local_a4));
    local_88 = *(float *)(puVar3 + 0x10) + local_a0;
    (**(code **)(*DAT_803dd708 + 8))(puVar3,0xca,local_9c,0x200001,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(puVar3,0xcb,local_9c,0x200001,0xffffffff,0);
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  puVar6 = *(uint **)(puVar3 + 0x5c);
  fVar1 = *(float *)(iVar5 + 0x10) - *(float *)(puVar3 + 8);
  if (((FLOAT_803e4c78 <= fVar1) && (fVar1 <= FLOAT_803e4c7c)) &&
     (fVar1 = *(float *)(iVar5 + 0xc) - *(float *)(puVar3 + 6),
     fVar2 = *(float *)(iVar5 + 0x14) - *(float *)(puVar3 + 10),
     fVar1 * fVar1 + fVar2 * fVar2 <= FLOAT_803e4c80)) {
    *puVar6 = *puVar6 + 0x3c;
    uStack_7c = *puVar6 ^ 0x80000000;
    local_80 = 0x43300000;
  }
  FUN_80286884();
  return;
}

