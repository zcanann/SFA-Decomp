// Function: FUN_800e03b8
// Entry: 800e03b8
// Size: 696 bytes

/* WARNING: Removing unreachable block (ram,0x800e0650) */
/* WARNING: Removing unreachable block (ram,0x800e0648) */
/* WARNING: Removing unreachable block (ram,0x800e0640) */
/* WARNING: Removing unreachable block (ram,0x800e03d8) */
/* WARNING: Removing unreachable block (ram,0x800e03d0) */
/* WARNING: Removing unreachable block (ram,0x800e03c8) */

void FUN_800e03b8(undefined4 param_1,undefined4 param_2,int param_3,int param_4,char param_5)

{
  float fVar1;
  int *piVar2;
  char cVar4;
  int iVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  double dVar9;
  undefined8 uVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar13;
  double dVar14;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar15;
  char local_d0 [4];
  short asStack_cc [4];
  short asStack_c4 [4];
  float local_bc;
  float local_b8;
  int local_b4;
  int aiStack_b0 [34];
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
  uVar15 = FUN_8028682c();
  piVar2 = (int *)((ulonglong)uVar15 >> 0x20);
  dVar13 = (double)FLOAT_803e12bc;
  local_bc = (float)piVar2[3];
  local_b8 = FLOAT_803e12c0 + (float)piVar2[4];
  local_b4 = piVar2[5];
  dVar14 = dVar13;
  FUN_80012d20(&local_bc,asStack_cc);
  piVar8 = &DAT_803a2448;
  for (iVar7 = 0; iVar7 < DAT_803de0f0; iVar7 = iVar7 + 1) {
    iVar6 = *piVar8;
    iVar5 = 0;
    do {
      if (((int)*(char *)(iVar6 + 0x19) == *(int *)((int)uVar15 + iVar5 * 4)) || (param_3 < 1)) {
        dVar11 = (double)(*(float *)(iVar6 + 8) - (float)piVar2[3]);
        dVar12 = (double)(*(float *)(iVar6 + 0xc) - (float)piVar2[4]);
        fVar1 = *(float *)(iVar6 + 0x10) - (float)piVar2[5];
        dVar9 = FUN_80293900((double)(fVar1 * fVar1 +
                                     (float)(dVar11 * dVar11 + (double)(float)(dVar12 * dVar12))));
        if (dVar9 < dVar14) {
          local_bc = *(float *)(iVar6 + 8);
          local_b8 = FLOAT_803e12c0 + *(float *)(iVar6 + 0xc);
          local_b4 = *(int *)(iVar6 + 0x10);
          uVar10 = FUN_80012d20(&local_bc,asStack_c4);
          cVar4 = FUN_800128fc(uVar10,dVar11,dVar12,in_f4,in_f5,in_f6,in_f7,in_f8,asStack_c4,
                               asStack_cc,(undefined4 *)0x0,local_d0,0);
          if (((local_d0[0] == '\x01') || (cVar4 != '\0')) &&
             (iVar5 = FUN_80064248(piVar2 + 3,&local_bc,(float *)0x0,aiStack_b0,piVar2,(int)param_5,
                                   0xffffffff,0,0), iVar5 == 0)) {
            dVar14 = dVar9;
          }
        }
        iVar5 = param_3;
        if ((*(char *)(iVar6 + 0x18) == param_4) && (dVar9 < dVar13)) {
          local_bc = *(float *)(iVar6 + 8);
          local_b8 = FLOAT_803e12c0 + *(float *)(iVar6 + 0xc);
          local_b4 = *(int *)(iVar6 + 0x10);
          uVar10 = FUN_80012d20(&local_bc,asStack_c4);
          cVar4 = FUN_800128fc(uVar10,dVar11,dVar12,in_f4,in_f5,in_f6,in_f7,in_f8,asStack_c4,
                               asStack_cc,(undefined4 *)0x0,local_d0,0);
          if (((local_d0[0] == '\x01') || (cVar4 != '\0')) &&
             (iVar3 = FUN_80064248(piVar2 + 3,&local_bc,(float *)0x0,aiStack_b0,piVar2,(int)param_5,
                                   0xffffffff,0,0), iVar3 == 0)) {
            dVar13 = dVar9;
          }
        }
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < param_3);
    piVar8 = piVar8 + 1;
  }
  FUN_80286878();
  return;
}

