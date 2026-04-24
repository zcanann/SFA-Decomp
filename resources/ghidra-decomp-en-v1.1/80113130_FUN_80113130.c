// Function: FUN_80113130
// Entry: 80113130
// Size: 680 bytes

/* WARNING: Removing unreachable block (ram,0x801133b8) */
/* WARNING: Removing unreachable block (ram,0x80113140) */

void FUN_80113130(undefined4 param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  ushort *puVar2;
  uint uVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  double extraout_f1;
  double dVar8;
  undefined8 uVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f31;
  double dVar12;
  double in_ps31_1;
  undefined8 uVar13;
  char local_c0 [4];
  short asStack_bc [4];
  short asStack_b4 [4];
  float local_ac;
  float local_a8;
  undefined4 local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  int local_94 [35];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar13 = FUN_80286838();
  puVar2 = (ushort *)((ulonglong)uVar13 >> 0x20);
  bVar1 = false;
  dVar12 = extraout_f1;
  local_94[0] = FUN_8002bac4();
  local_94[1] = 0;
  for (piVar7 = local_94; (!bVar1 && (iVar6 = *piVar7, iVar6 != 0)); piVar7 = piVar7 + 1) {
    local_a0 = *(float *)(iVar6 + 0x18) - *(float *)(puVar2 + 0xc);
    dVar11 = (double)local_a0;
    local_9c = *(float *)(iVar6 + 0x1c) - *(float *)(puVar2 + 0xe);
    dVar10 = (double)local_9c;
    local_98 = *(float *)(iVar6 + 0x20) - *(float *)(puVar2 + 0x10);
    dVar8 = FUN_80293900((double)(local_98 * local_98 +
                                 (float)(dVar11 * dVar11) + (float)(dVar10 * dVar10)));
    if ((dVar8 < dVar12) && (*(char *)((int)uVar13 + 0x354) != '\0')) {
      dVar8 = FUN_8029686c(iVar6);
      if ((double)FLOAT_803e28e4 < dVar8) {
        bVar1 = true;
      }
      dVar8 = -(double)local_98;
      uVar3 = FUN_80021884();
      if (*(short **)(puVar2 + 0x18) == (short *)0x0) {
        iVar5 = (uVar3 & 0xffff) - (uint)*puVar2;
        if (0x8000 < iVar5) {
          iVar5 = iVar5 + -0xffff;
        }
        if (iVar5 < -0x8000) {
          iVar5 = iVar5 + 0xffff;
        }
      }
      else {
        iVar5 = (uVar3 & 0xffff) -
                ((int)(short)*puVar2 + (int)**(short **)(puVar2 + 0x18) & 0xffffU);
        if (0x8000 < iVar5) {
          iVar5 = iVar5 + -0xffff;
        }
        if (iVar5 < -0x8000) {
          iVar5 = iVar5 + 0xffff;
        }
      }
      if ((iVar5 < param_3) && (-param_3 < iVar5)) {
        bVar1 = true;
      }
      uVar3 = FUN_80296164(iVar6,1);
      if (uVar3 == 0) {
        bVar1 = false;
      }
      iVar5 = FUN_80297248(iVar6);
      if (iVar5 < 1) {
        bVar1 = false;
      }
      else {
        local_ac = *(float *)(puVar2 + 6);
        local_a8 = FLOAT_803e28e8 + *(float *)(puVar2 + 8);
        local_a4 = *(undefined4 *)(puVar2 + 10);
        FUN_80012d20(&local_ac,asStack_bc);
        local_ac = *(float *)(iVar6 + 0xc);
        local_a8 = FLOAT_803e28e8 + *(float *)(iVar6 + 0x10);
        local_a4 = *(undefined4 *)(iVar6 + 0x14);
        uVar9 = FUN_80012d20(&local_ac,asStack_b4);
        cVar4 = FUN_800128fc(uVar9,dVar8,dVar10,dVar11,in_f5,in_f6,in_f7,in_f8,asStack_b4,asStack_bc
                             ,(undefined4 *)0x0,local_c0,0);
        if ((local_c0[0] == '\x01') || (cVar4 != '\0')) {
          iVar6 = FUN_80064248(puVar2 + 6,&local_ac,(float *)0x0,local_94 + 3,(int *)puVar2,4,
                               0xffffffff,0,0);
          if (iVar6 != 0) {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
    }
  }
  FUN_80286884();
  return;
}

