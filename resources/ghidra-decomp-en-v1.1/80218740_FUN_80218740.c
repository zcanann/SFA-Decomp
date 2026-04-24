// Function: FUN_80218740
// Entry: 80218740
// Size: 812 bytes

/* WARNING: Removing unreachable block (ram,0x80218a48) */
/* WARNING: Removing unreachable block (ram,0x80218a40) */
/* WARNING: Removing unreachable block (ram,0x80218758) */
/* WARNING: Removing unreachable block (ram,0x80218750) */

void FUN_80218740(double param_1,undefined2 *param_2,int param_3,int param_4)

{
  float fVar1;
  int iVar2;
  int *piVar3;
  undefined4 in_r9;
  undefined4 in_r10;
  uint *puVar4;
  double dVar5;
  undefined8 uVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  short asStack_78 [4];
  short asStack_70 [4];
  short asStack_68 [4];
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  longlong local_38;
  
  puVar4 = *(uint **)(param_2 + 0x5c);
  local_48 = *(float *)(param_4 + 0xc) - *(float *)(param_3 + 0xc);
  dVar8 = (double)local_48;
  local_44 = *(float *)(param_4 + 0x10) - *(float *)(param_3 + 0x10);
  local_40 = *(float *)(param_4 + 0x14) - *(float *)(param_3 + 0x14);
  dVar5 = FUN_80293900((double)(local_40 * local_40 + (float)(dVar8 * dVar8) + local_44 * local_44))
  ;
  fVar1 = (float)(dVar5 / param_1);
  if (fVar1 != FLOAT_803e75f4) {
    local_48 = local_48 / fVar1;
    local_44 = local_44 / fVar1;
    local_40 = local_40 / fVar1;
  }
  *(undefined4 *)(param_2 + 6) = *(undefined4 *)(param_3 + 0xc);
  *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x10);
  *(undefined4 *)(param_2 + 10) = *(undefined4 *)(param_3 + 0x14);
  *(float *)(param_2 + 0x12) = local_48;
  *(float *)(param_2 + 0x14) = local_44;
  *(float *)(param_2 + 0x16) = local_40;
  FUN_80293900((double)(*(float *)(param_2 + 0x12) * *(float *)(param_2 + 0x12) +
                       *(float *)(param_2 + 0x16) * *(float *)(param_2 + 0x16)));
  iVar2 = FUN_80021884();
  *param_2 = (short)iVar2;
  iVar2 = FUN_80021884();
  param_2[1] = -(short)iVar2;
  param_2[2] = 0;
  FUN_80036018((int)param_2);
  *(undefined *)(puVar4 + 1) = 3;
  dVar7 = (double)(FLOAT_803e75f8 * *(float *)(param_2 + 0x12));
  dVar5 = (double)(FLOAT_803e75f8 * *(float *)(param_2 + 0x14));
  local_60 = (float)((double)*(float *)(param_2 + 6) + dVar7);
  local_5c = (float)((double)*(float *)(param_2 + 8) + dVar5);
  local_58 = *(float *)(param_2 + 10) + FLOAT_803e75f8 * *(float *)(param_2 + 0x16);
  FUN_80012d20((float *)(param_2 + 6),asStack_68);
  uVar6 = FUN_80012d20(&local_60,asStack_70);
  iVar2 = FUN_800128fc(uVar6,dVar5,dVar7,dVar8,in_f5,in_f6,in_f7,in_f8,asStack_68,asStack_70,
                       (undefined4 *)asStack_78,(undefined *)0x0,0);
  if (iVar2 == 0) {
    FUN_80012e2c(&local_60,asStack_78);
    local_54 = local_60 - *(float *)(param_2 + 6);
    dVar8 = (double)local_54;
    local_50 = local_5c - *(float *)(param_2 + 8);
    dVar7 = (double)local_50;
    local_4c = local_58 - *(float *)(param_2 + 10);
    dVar5 = FUN_80293900((double)(local_4c * local_4c +
                                 (float)(dVar8 * dVar8) + (float)(dVar7 * dVar7)));
    local_38 = (longlong)(int)(dVar5 / param_1);
    puVar4[2] = (int)(dVar5 / param_1);
  }
  else {
    puVar4[2] = 600;
  }
  if (*puVar4 != 0) {
    FUN_8001f448(*puVar4);
    *puVar4 = 0;
  }
  piVar3 = FUN_8001f58c((int)param_2,'\x01');
  if (piVar3 != (int *)0x0) {
    FUN_8001dbf0((int)piVar3,2);
    FUN_8001dbb4((int)piVar3,0,0xff,0xff,0);
    FUN_8001dbd8((int)piVar3,1);
    dVar5 = (double)FLOAT_803e75dc;
    FUN_8001dcfc((double)FLOAT_803e75d8,dVar5,(int)piVar3);
    FUN_8001d7f4((double)FLOAT_803e75e0,dVar5,dVar7,dVar8,in_f5,in_f6,in_f7,in_f8,piVar3,0,0,0xff,
                 0xff,0x80,in_r9,in_r10);
    FUN_8001d7d8((double)FLOAT_803e75e4,(int)piVar3);
  }
  *puVar4 = (uint)piVar3;
  *(undefined *)(param_2 + 0x1b) = 0xff;
  *(float *)(param_2 + 4) = FLOAT_803e75f0 * *(float *)(*(int *)(param_2 + 0x28) + 4);
  FUN_8000bb38((uint)param_2,0x173);
  return;
}

