// Function: FUN_801b810c
// Entry: 801b810c
// Size: 488 bytes

void FUN_801b810c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)

{
  undefined uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar5;
  int *piVar6;
  double dVar7;
  undefined8 uVar8;
  
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  piVar6 = *(int **)(param_9 + 0x5c);
  piVar5 = *(int **)(*(int *)(param_9 + 0x3e) + *(char *)((int)param_9 + 0xad) * 4);
  uVar4 = 0;
  FUN_80027a90((double)FLOAT_803e5720,piVar5,0,-1,0,0);
  FUN_80027a44((double)FLOAT_803e5710,piVar5,0);
  *(undefined2 *)(piVar6 + 6) = *(undefined2 *)(param_10 + 0x1a);
  if (*(short *)(piVar6 + 6) < 0xf) {
    *(undefined2 *)(piVar6 + 6) = 0xf;
  }
  *(undefined2 *)((int)piVar6 + 0x1a) = *(undefined2 *)(param_10 + 0x1c);
  if (*(short *)((int)piVar6 + 0x1a) < 0xf) {
    *(undefined2 *)((int)piVar6 + 0x1a) = 0xf;
  }
  dVar7 = (double)FLOAT_803e5720;
  piVar6[2] = (int)(float)(dVar7 * (double)*(float *)(param_9 + 4));
  piVar6[2] = (int)((float)piVar6[2] * (float)piVar6[2]);
  piVar6[3] = (int)(float)(dVar7 * (double)*(float *)(param_9 + 4));
  piVar6[3] = (int)((float)piVar6[3] * (float)piVar6[3]);
  uVar2 = FUN_80020078(0x1f0);
  if (uVar2 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = 2;
  }
  *(undefined *)((int)piVar6 + 0x1d) = uVar1;
  for (iVar3 = 0; iVar3 < 4; iVar3 = iVar3 + 1) {
    if ((&DAT_803dcb88)[iVar3] == '\0') {
      (&DAT_803dcb88)[iVar3] = 1;
      *(char *)((int)piVar6 + 0x1f) = (char)iVar3;
      iVar3 = 4;
    }
  }
  iVar3 = FUN_80023d8c(0x28,0x12);
  *piVar6 = iVar3;
  uVar8 = FUN_8001f7e0(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar6,0xc,
                       *(short *)(&DAT_803dcb80 + (uint)*(byte *)((int)piVar6 + 0x1f) * 2) * 0x28,
                       0x28,uVar4,in_r8,in_r9,in_r10);
  iVar3 = FUN_80023d8c(0x28,0x12);
  piVar6[1] = iVar3;
  FUN_8001f7e0(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar6[1],0xc,
               (*(short *)(&DAT_803dcb80 + (uint)*(byte *)((int)piVar6 + 0x1f) * 2) + 1) * 0x28,0x28
               ,uVar4,in_r8,in_r9,in_r10);
  param_9[0x58] = param_9[0x58] | 0x2000;
  return;
}

