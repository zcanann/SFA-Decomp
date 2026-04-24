// Function: FUN_80081bf8
// Entry: 80081bf8
// Size: 644 bytes

int FUN_80081bf8(double param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
                undefined4 param_10,undefined4 param_11,int *param_12,int *param_13,int param_14,
                int *param_15,int param_16)

{
  short sVar1;
  float fVar2;
  int *piVar3;
  int iVar4;
  int *extraout_r4;
  int *piVar5;
  undefined *puVar6;
  int *piVar7;
  undefined4 uStack_18;
  int local_14 [3];
  
  piVar5 = local_14;
  piVar3 = (int *)FUN_8002e1f4(&uStack_18,piVar5);
  piVar7 = *(int **)(param_9 + 0xb8);
  puVar6 = *(undefined **)(param_9 + 0x4c);
  if (*(short *)(param_9 + 0x44) == 0x11) {
    *piVar7 = 0;
    return -1;
  }
  sVar1 = *(short *)(puVar6 + 0x1c);
  if (sVar1 == 2) {
    iVar4 = FUN_8002ba84();
    *piVar7 = iVar4;
    goto LAB_80081e28;
  }
  if (sVar1 < 2) {
    if (sVar1 == 0) {
      *piVar7 = 0;
      goto LAB_80081e28;
    }
    if (-1 < sVar1) {
      iVar4 = FUN_8002bac4();
      *piVar7 = iVar4;
      goto LAB_80081e28;
    }
  }
  else if (sVar1 < 4) {
    piVar5 = (int *)0x0;
    *piVar7 = 0;
    *(char *)((int)piVar7 + 0x7b) = (char)*(undefined2 *)(puVar6 + 0x1c) + -2;
    if (DAT_803ddce4 != 0) {
      DAT_803ddce4 = 0;
    }
    if (((&DAT_8039aab0)[*(char *)((int)piVar7 + 0x57)] & 0x10) == 0) {
      puVar6 = (undefined *)*DAT_803dd6d0;
      param_1 = (double)(**(code **)(puVar6 + 0x5c))(0x41,1);
      piVar5 = extraout_r4;
    }
    goto LAB_80081e28;
  }
  *piVar7 = 0;
  piVar5 = (int *)(int)*(short *)(puVar6 + 0x1c);
  param_15 = piVar5 + -1;
  if ((param_15 == (int *)0x1f) || (param_15 == (int *)0x0)) {
    iVar4 = FUN_8002bac4();
    *piVar7 = iVar4;
  }
  else if (piVar7[0x43] == 0) {
    param_2 = (double)FLOAT_803dfc70;
    piVar5 = (int *)0x80390000;
    puVar6 = &DAT_80397578;
    for (param_16 = 0; param_16 < local_14[0]; param_16 = param_16 + 1) {
      param_14 = *piVar3;
      piVar5 = (int *)0x0;
      param_13 = (int *)(&DAT_80397578 + *(char *)((int)piVar7 + 0x57) * 0x80);
      iVar4 = 0x10;
      param_12 = param_13;
      do {
        if (*param_12 == param_14) {
          piVar5 = (int *)((int)piVar5 * 8);
          iVar4 = *(int *)((int)param_13 + (int)(piVar5 + 1));
          goto LAB_80081da4;
        }
        param_12 = param_12 + 2;
        piVar5 = (int *)((int)piVar5 + 1);
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
      iVar4 = 0;
LAB_80081da4:
      if (iVar4 == param_9) {
        *piVar7 = param_14;
        break;
      }
      if ((iVar4 == 0) && ((int *)(int)*(short *)(param_14 + 0x46) == param_15)) {
        param_3 = (double)(*(float *)(param_9 + 0xc) - *(float *)(param_14 + 0xc));
        param_4 = (double)(*(float *)(param_9 + 0x10) - *(float *)(param_14 + 0x10));
        fVar2 = *(float *)(param_9 + 0x14) - *(float *)(param_14 + 0x14);
        param_1 = (double)(fVar2 * fVar2 +
                          (float)(param_3 * param_3 + (double)(float)(param_4 * param_4)));
        if ((param_2 < (double)FLOAT_803dfc30) || (param_1 < param_2)) {
          *piVar7 = param_14;
          param_2 = param_1;
        }
      }
      piVar3 = piVar3 + 1;
    }
  }
  else {
    iVar4 = FUN_8002e1ac(piVar7[0x43]);
    *piVar7 = iVar4;
  }
LAB_80081e28:
  if (*piVar7 == 0) {
    iVar4 = -1;
  }
  else {
    if ((*(char *)((int)piVar7 + 0x57) < '\x19') &&
       (iVar4 = (int)*(short *)(*piVar7 + 0xb4), iVar4 != -1)) {
      FUN_80080ea4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,piVar5,
                   (int)puVar6,param_12,param_13,param_14,param_15,param_16);
    }
    iVar4 = (int)*(short *)(*piVar7 + 0x48);
  }
  return iVar4;
}

