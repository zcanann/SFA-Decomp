// Function: FUN_8026b9ec
// Entry: 8026b9ec
// Size: 1124 bytes

int FUN_8026b9ec(undefined2 *param_1,int *param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int extraout_r4;
  int extraout_r4_00;
  int extraout_r4_01;
  uint uVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  undefined2 *puVar10;
  ulonglong uVar11;
  undefined auStack68 [8];
  byte local_3c;
  byte local_3b;
  
  if ((param_1 == (undefined2 *)0x0) || (param_2 == (int *)0x0)) {
    iVar2 = 0;
  }
  else {
    iVar2 = *param_2;
    if (param_3 == 1) {
      iVar9 = 1;
      puVar10 = param_1 + param_2[1];
    }
    else {
      puVar10 = param_1 + 1;
      iVar9 = 2;
    }
    if (*param_2 == 0) {
      FUN_8026bee0(auStack68,param_2 + 0x14);
      iVar7 = (int)*(short *)(param_2 + 0x12);
      iVar2 = (int)*(short *)((int)param_2 + 0x4a);
      for (uVar8 = 0; uVar8 < (uint)param_2[1]; uVar8 = uVar8 + 1) {
        iVar3 = FUN_8026be50(auStack68);
        uVar1 = (iVar3 << (uint)local_3b) * 0x800;
        uVar6 = (int)*(short *)((int)param_2 + (uint)local_3c * 4 + 10) * (int)(short)iVar2;
        uVar5 = (int)*(short *)(param_2 + local_3c + 2) * (int)(short)iVar7;
        uVar11 = FUN_80286448(((int)uVar6 >> 0x1f) +
                              ((int)uVar5 >> 0x1f) + (uint)CARRY4(uVar6,uVar5) +
                              ((int)(uVar1 | (uint)(iVar3 << (uint)local_3b) >> 0x15) >> 0x1f) +
                              (uint)CARRY4(uVar6 + uVar5,uVar1),uVar6 + uVar5 + uVar1,5);
        uVar1 = (uint)uVar11 & 0xffff;
        if (uVar1 < 0x8001) {
          if ((uVar1 == 0x8000) && ((uVar11 & 0x10000) != 0)) {
            uVar11 = uVar11 + 0x10000;
          }
        }
        else {
          uVar11 = uVar11 + 0x10000;
        }
        if (0x80000000 < (uint)(0x7fffffff < (uint)uVar11) + ((uint)(uVar11 >> 0x20) ^ 0x80000000))
        {
          uVar11 = 0x7fffffff;
        }
        if (((uint)(uVar11 >> 0x20) ^ 0x80000000) < ((uint)uVar11 < 0x80000000) + 0x7fffffff) {
          uVar11 = 0xffffffff80000000;
        }
        FUN_80286490((int)(uVar11 >> 0x20),(int)uVar11,0x10);
        *puVar10 = (short)extraout_r4;
        *param_1 = (short)extraout_r4;
        puVar10 = puVar10 + iVar9;
        param_1 = param_1 + iVar9;
        iVar2 = iVar7;
        iVar7 = extraout_r4;
      }
    }
    else {
      FUN_8026bee0(auStack68,param_2 + 0x14);
      iVar3 = (int)*(short *)(param_2 + 0x12);
      iVar7 = (int)*(short *)((int)param_2 + 0x4a);
      for (uVar8 = 0; uVar8 < (uint)param_2[1]; uVar8 = uVar8 + 1) {
        iVar4 = FUN_8026be50(auStack68);
        uVar1 = (iVar4 << (uint)local_3b) * 0x800;
        uVar6 = (int)*(short *)((int)param_2 + (uint)local_3c * 4 + 10) * (int)(short)iVar7;
        uVar5 = (int)*(short *)(param_2 + local_3c + 2) * (int)(short)iVar3;
        uVar11 = FUN_80286448(((int)uVar6 >> 0x1f) +
                              ((int)uVar5 >> 0x1f) + (uint)CARRY4(uVar6,uVar5) +
                              ((int)(uVar1 | (uint)(iVar4 << (uint)local_3b) >> 0x15) >> 0x1f) +
                              (uint)CARRY4(uVar6 + uVar5,uVar1),uVar6 + uVar5 + uVar1,5);
        uVar1 = (uint)uVar11 & 0xffff;
        if (uVar1 < 0x8001) {
          if ((uVar1 == 0x8000) && ((uVar11 & 0x10000) != 0)) {
            uVar11 = uVar11 + 0x10000;
          }
        }
        else {
          uVar11 = uVar11 + 0x10000;
        }
        if (0x80000000 < (uint)(0x7fffffff < (uint)uVar11) + ((uint)(uVar11 >> 0x20) ^ 0x80000000))
        {
          uVar11 = 0x7fffffff;
        }
        if (((uint)(uVar11 >> 0x20) ^ 0x80000000) < ((uint)uVar11 < 0x80000000) + 0x7fffffff) {
          uVar11 = 0xffffffff80000000;
        }
        FUN_80286490((int)(uVar11 >> 0x20),(int)uVar11,0x10);
        *puVar10 = (short)extraout_r4_00;
        puVar10 = puVar10 + iVar9;
        iVar7 = iVar3;
        iVar3 = extraout_r4_00;
      }
      FUN_8026bee0(auStack68,(int)param_2 + iVar2 + 0x50);
      iVar7 = (int)*(short *)(param_2 + 0x13);
      iVar2 = (int)*(short *)((int)param_2 + 0x4e);
      for (uVar8 = 0; uVar8 < (uint)param_2[1]; uVar8 = uVar8 + 1) {
        iVar3 = FUN_8026be50(auStack68);
        uVar1 = (iVar3 << (uint)local_3b) * 0x800;
        uVar6 = (int)*(short *)((int)param_2 + (uint)local_3c * 4 + 0x2a) * (int)(short)iVar2;
        uVar5 = (int)*(short *)(param_2 + local_3c + 10) * (int)(short)iVar7;
        uVar11 = FUN_80286448(((int)uVar6 >> 0x1f) +
                              ((int)uVar5 >> 0x1f) + (uint)CARRY4(uVar6,uVar5) +
                              ((int)(uVar1 | (uint)(iVar3 << (uint)local_3b) >> 0x15) >> 0x1f) +
                              (uint)CARRY4(uVar6 + uVar5,uVar1),uVar6 + uVar5 + uVar1,5);
        uVar1 = (uint)uVar11 & 0xffff;
        if (uVar1 < 0x8001) {
          if ((uVar1 == 0x8000) && ((uVar11 & 0x10000) != 0)) {
            uVar11 = uVar11 + 0x10000;
          }
        }
        else {
          uVar11 = uVar11 + 0x10000;
        }
        if (0x80000000 < (uint)(0x7fffffff < (uint)uVar11) + ((uint)(uVar11 >> 0x20) ^ 0x80000000))
        {
          uVar11 = 0x7fffffff;
        }
        if (((uint)(uVar11 >> 0x20) ^ 0x80000000) < ((uint)uVar11 < 0x80000000) + 0x7fffffff) {
          uVar11 = 0xffffffff80000000;
        }
        FUN_80286490((int)(uVar11 >> 0x20),(int)uVar11,0x10);
        *param_1 = (short)extraout_r4_01;
        param_1 = param_1 + iVar9;
        iVar2 = iVar7;
        iVar7 = extraout_r4_01;
      }
    }
    iVar2 = param_2[1];
  }
  return iVar2;
}

