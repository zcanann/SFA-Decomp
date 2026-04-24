// Function: FUN_801860cc
// Entry: 801860cc
// Size: 1880 bytes

/* WARNING: Removing unreachable block (ram,0x80186804) */
/* WARNING: Removing unreachable block (ram,0x801860dc) */

void FUN_801860cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  ushort *puVar2;
  ushort *puVar3;
  uint uVar4;
  ushort *puVar5;
  undefined uVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar7;
  int *piVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  double in_f31;
  double in_ps31_1;
  float fStack_98;
  float local_94;
  undefined auStack_90 [8];
  undefined4 local_88;
  undefined auStack_78 [8];
  undefined4 local_70;
  undefined auStack_60 [8];
  undefined4 local_58;
  ushort local_48 [4];
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined8 local_30;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  puVar2 = (ushort *)FUN_80286840();
  iVar9 = *(int *)(puVar2 + 0x26);
  local_94 = FLOAT_803e46f4;
  (**(code **)(*DAT_803dd6d8 + 0x18))(&local_94);
  piVar8 = *(int **)(puVar2 + 0x5c);
  puVar3 = (ushort *)FUN_8002bac4();
  iVar7 = *(int *)(puVar3 + 0x5c);
  dVar10 = (double)FUN_800217c8((float *)(puVar3 + 0xc),(float *)(puVar2 + 0xc));
  if (*(short *)((int)piVar8 + 0x1a) < 1) {
    *(undefined2 *)(piVar8 + 4) = 1;
    *(undefined *)((int)piVar8 + 0x23) = 0;
    *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
    fVar1 = FLOAT_803e46f0;
    *(float *)(puVar2 + 0x12) = FLOAT_803e46f0;
    *(float *)(puVar2 + 0x16) = fVar1;
  }
  if (*(short *)((int)piVar8 + 0x1e) != 0) {
    FUN_8000bb38((uint)puVar2,0x70);
    *(ushort *)((int)piVar8 + 0x1e) = *(short *)((int)piVar8 + 0x1e) - (ushort)DAT_803dc070;
    uVar4 = FUN_80022264(0,2);
    if (uVar4 == 2) {
      in_r7 = 0xffffffff;
      in_r8 = 0;
      in_r9 = *DAT_803dd708;
      (**(code **)(in_r9 + 8))(puVar2,0x51c,0,1);
    }
    if (*(short *)((int)piVar8 + 0x1e) < 1) {
      FUN_80185dc0(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)puVar2);
      goto LAB_80186804;
    }
  }
  if (*piVar8 != 0) {
    local_30 = (double)(longlong)(int)(FLOAT_803dc074 * local_94);
    *piVar8 = *piVar8 - (int)(short)(int)(FLOAT_803dc074 * local_94);
    if (*piVar8 < 1) {
      *piVar8 = 0;
      *(undefined2 *)(piVar8 + 4) = 0;
      FUN_80036018((int)puVar2);
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) & 0xf7;
      puVar2[0x7a] = 0;
      puVar2[0x7b] = 0;
    }
    goto LAB_80186804;
  }
  if (*(short *)(piVar8 + 4) != 0) {
    FUN_8000b7dc((int)puVar2,0x40);
    *(ushort *)(piVar8 + 4) = *(short *)(piVar8 + 4) - (ushort)DAT_803dc070;
    if (*(short *)(piVar8 + 4) < 1) {
      if (piVar8[1] == 0) {
        *piVar8 = 1;
      }
      else {
        *piVar8 = piVar8[1];
      }
    }
    if (*(short *)(piVar8 + 4) < 0x33) goto LAB_80186804;
  }
  if (*(char *)((int)piVar8 + 0x23) == '\0') {
    if (*(char *)((int)piVar8 + 0x21) == '\0') {
      puVar5 = (ushort *)(**(code **)(*DAT_803dd6d0 + 0x3c))();
      uVar6 = 0;
      if (((puVar5 != puVar2) && ((*(byte *)((int)puVar2 + 0xaf) & 1) != 0)) &&
         (*(int *)(puVar2 + 0x7c) == 0)) {
        FUN_80014b68(0,0x100);
        FUN_800386e0(puVar2,(int)puVar3,&fStack_98);
        *(undefined2 *)(piVar8 + 3) = 0x8000;
        *(undefined2 *)((int)piVar8 + 0xe) = 0;
        uVar6 = 1;
      }
      *(undefined *)((int)piVar8 + 0x21) = uVar6;
      if (*(char *)((int)piVar8 + 0x21) != '\0') {
        *(undefined *)((int)piVar8 + 0x22) = 1;
        *(undefined2 *)((int)piVar8 + 0x1e) = 600;
      }
      if (*(int *)(puVar2 + 0x7c) == 0) {
        FUN_80036018((int)puVar2);
        *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) & 0xf7;
      }
      *(undefined4 *)(puVar2 + 0x40) = *(undefined4 *)(puVar2 + 6);
      *(undefined4 *)(puVar2 + 0x42) = *(undefined4 *)(puVar2 + 10);
      *(undefined4 *)(puVar2 + 0x44) = *(undefined4 *)(puVar2 + 10);
    }
    else {
      uVar11 = FUN_80035ff8((int)puVar2);
      *(undefined4 *)(*(int *)(puVar2 + 0x2a) + 0x10) = *(undefined4 *)(puVar2 + 6);
      *(undefined4 *)(*(int *)(puVar2 + 0x2a) + 0x14) = *(undefined4 *)(puVar2 + 8);
      *(undefined4 *)(*(int *)(puVar2 + 0x2a) + 0x18) = *(undefined4 *)(puVar2 + 10);
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
      uVar4 = FUN_80014e9c(0);
      if ((uVar4 & 0x100) != 0) {
        *(undefined *)((int)piVar8 + 0x22) = 0;
      }
      if (*(char *)((int)piVar8 + 0x22) != '\0') {
        *(undefined2 *)(piVar8 + 4) = 0;
        *piVar8 = 0;
        FUN_800379bc(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar3,
                     0x100010,(uint)puVar2,
                     CONCAT22(*(undefined2 *)((int)piVar8 + 0xe),*(undefined2 *)(piVar8 + 3)),in_r7,
                     in_r8,in_r9,in_r10);
      }
      if (*(int *)(puVar2 + 0x7c) == 1) {
        *(undefined *)((int)piVar8 + 0x21) = 2;
      }
      if (((*(char *)((int)piVar8 + 0x21) == '\x02') && (*(int *)(puVar2 + 0x7c) == 0)) &&
         (puVar3[0x50] != 0x447)) {
        *(undefined *)((int)piVar8 + 0x21) = 0;
        *(undefined *)((int)piVar8 + 0x23) = 1;
        local_3c = FLOAT_803e46f0;
        *(float *)(puVar2 + 0x12) = FLOAT_803e46f0;
        *(float *)(puVar2 + 0x14) = FLOAT_803e46fc * *(float *)(iVar7 + 0x298) + FLOAT_803e46f8;
        *(float *)(puVar2 + 0x16) = FLOAT_803e4704 * *(float *)(iVar7 + 0x298) + FLOAT_803e4700;
        local_38 = local_3c;
        local_34 = local_3c;
        local_40 = FLOAT_803e46f4;
        local_48[2] = 0;
        local_48[1] = 0;
        local_48[0] = *puVar3;
        FUN_80021b8c(local_48,(float *)(puVar2 + 0x12));
        FUN_8000bb38((uint)puVar2,0x6a);
      }
      else if ((*(char *)((int)piVar8 + 0x21) == '\x02') && (*(int *)(puVar2 + 0x7c) == 0)) {
        *(undefined *)((int)piVar8 + 0x21) = 0;
        *(undefined *)((int)piVar8 + 0x23) = 2;
        fVar1 = FLOAT_803e46f0;
        *(float *)(puVar2 + 0x12) = FLOAT_803e46f0;
        *(float *)(puVar2 + 0x14) = fVar1;
        *(float *)(puVar2 + 0x16) = fVar1;
        FUN_8000bb38((uint)puVar2,0x6a);
      }
    }
  }
  if ((*(char *)((int)piVar8 + 0x23) == '\0') && (*(char *)((int)piVar8 + 0x21) == '\0')) {
    iVar7 = FUN_80036974((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if (iVar7 != 0) {
      iVar7 = *(int *)(puVar2 + 0x5c);
      local_58 = *(undefined4 *)(iVar7 + 8);
      (**(code **)(*DAT_803de754 + 4))(puVar2,0,auStack_60,2,0xffffffff,0);
      *(undefined2 *)(iVar7 + 0x1e) = 1;
      goto LAB_80186804;
    }
  }
  else if (*(char *)((int)piVar8 + 0x23) != '\0') {
    *(ushort *)((int)piVar8 + 0x1a) = *(short *)((int)piVar8 + 0x1a) - (ushort)DAT_803dc070;
    if (*(char *)((int)piVar8 + 0x23) == '\x01') {
      FUN_80035eec((int)puVar2,0xe,3,0);
      if (FLOAT_803e4708 < *(float *)(puVar2 + 0x14)) {
        *(float *)(puVar2 + 0x14) = FLOAT_803e470c * FLOAT_803dc074 + *(float *)(puVar2 + 0x14);
      }
      FUN_80036018((int)puVar2);
    }
    if ((*(char *)(*(int *)(puVar2 + 0x2a) + 0xad) != '\0') &&
       (*(char *)((int)piVar8 + 0x23) == '\x01')) {
      *(float *)(puVar2 + 0x14) = FLOAT_803e46f0;
      *(undefined *)((int)piVar8 + 0x23) = 0;
      iVar7 = *(int *)(puVar2 + 0x5c);
      local_70 = *(undefined4 *)(iVar7 + 8);
      (**(code **)(*DAT_803de754 + 4))(puVar2,0,auStack_78,2,0xffffffff,0);
      *(undefined2 *)(iVar7 + 0x1e) = 1;
      goto LAB_80186804;
    }
    if ((*(char *)(*(int *)(puVar2 + 0x2a) + 0xad) != '\0') &&
       (*(char *)((int)piVar8 + 0x23) == '\x02')) {
      *(undefined *)((int)piVar8 + 0x23) = 0;
      iVar7 = *(int *)(puVar2 + 0x5c);
      local_88 = *(undefined4 *)(iVar7 + 8);
      (**(code **)(*DAT_803de754 + 4))(puVar2,0,auStack_90,2,0xffffffff,0);
      *(undefined2 *)(iVar7 + 0x1e) = 1;
      *(float *)(puVar2 + 0x14) = FLOAT_803e46f0;
      goto LAB_80186804;
    }
    *(float *)(puVar2 + 6) = *(float *)(puVar2 + 0x12) * FLOAT_803dc074 + *(float *)(puVar2 + 6);
    *(float *)(puVar2 + 8) = *(float *)(puVar2 + 0x14) * FLOAT_803dc074 + *(float *)(puVar2 + 8);
    *(float *)(puVar2 + 10) = *(float *)(puVar2 + 0x16) * FLOAT_803dc074 + *(float *)(puVar2 + 10);
  }
  *(undefined4 *)(puVar2 + 0xc) = *(undefined4 *)(puVar2 + 6);
  *(undefined4 *)(puVar2 + 0xe) = *(undefined4 *)(puVar2 + 8);
  *(undefined4 *)(puVar2 + 0x10) = *(undefined4 *)(puVar2 + 10);
  *(ushort *)((int)piVar8 + 0x16) = *(short *)((int)piVar8 + 0x16) - (ushort)DAT_803dc070;
  if (*(char *)((int)piVar8 + 0x21) != '\0') {
    dVar10 = FUN_80021730((float *)(puVar2 + 0xc),(float *)(iVar9 + 8));
    fVar1 = FLOAT_803e46f0;
    local_30 = (double)CONCAT44(0x43300000,
                                (int)*(short *)((int)piVar8 + 0x12) *
                                (int)*(short *)((int)piVar8 + 0x12) ^ 0x80000000);
    if ((double)(float)(local_30 - DOUBLE_803e4710) <= dVar10) {
      *(float *)(puVar2 + 0x12) = FLOAT_803e46f0;
      *(float *)(puVar2 + 0x16) = fVar1;
      *(undefined2 *)(piVar8 + 4) = 500;
      *(undefined *)((int)piVar8 + 0x23) = 0;
      puVar2[0x7c] = 0;
      puVar2[0x7d] = 0;
      FUN_80036018((int)puVar2);
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) & 0xf7;
      FUN_80035ea4((int)puVar2);
    }
  }
LAB_80186804:
  FUN_8028688c();
  return;
}

