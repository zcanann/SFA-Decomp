// Function: FUN_80114e4c
// Entry: 80114e4c
// Size: 572 bytes

void FUN_80114e4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,float *param_11,short param_12,
                 undefined2 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  int iVar2;
  float fVar3;
  uint *puVar4;
  int iVar5;
  undefined2 *puVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  short local_28;
  undefined2 local_26;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar8 = FUN_8028683c();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  iVar7 = (int)uVar8;
  uVar8 = extraout_f1;
  fVar3 = (float)FUN_8002bac4();
  *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) = *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) | 1;
  local_28 = param_12;
  local_26 = param_13;
  if (*(char *)(iVar7 + 0x56) == '\x04') {
    param_11[0x17e] = 1.12104e-43;
    *(ushort *)(iVar7 + 0x6e) = *(ushort *)(iVar7 + 0x6e) & 0xfff7;
    *(ushort *)(iVar7 + 0x6e) = *(ushort *)(iVar7 + 0x6e) & 0xfffd;
    *(undefined *)(param_11 + 0x180) = 3;
    *(undefined *)(iVar7 + 0x56) = 5;
    if ((*(byte *)((int)param_11 + 0x611) & 2) == 0) {
      *(ushort *)(iVar7 + 0x6e) = *(ushort *)(iVar7 + 0x6e) & 0xfffb;
    }
    *(code **)(iVar7 + 0xe8) = FUN_80114db8;
    goto LAB_80115070;
  }
  if (((*(char *)(iVar7 + 0x56) != '\x05') || (*(byte *)(param_11 + 0x180) < 2)) ||
     (7 < *(byte *)(param_11 + 0x180))) goto LAB_80115070;
  puVar4 = FUN_80039598();
  bVar1 = *(byte *)(param_11 + 0x180);
  if (bVar1 == 6) {
    *(undefined *)(param_11 + 0x180) = 7;
LAB_80114fc8:
    *param_11 = FLOAT_803e2944;
  }
  else if (bVar1 < 6) {
    if (bVar1 == 3) {
      uVar8 = FUN_8003adf4(iVar2,puVar4,(uint)*(byte *)(param_11 + 0x184),(int)(param_11 + 7));
      param_11[0x17e] = 0.0;
      *(undefined *)(param_11 + 0x180) = 2;
    }
    else if ((2 < bVar1) || (bVar1 < 2)) goto LAB_80114fd0;
    iVar5 = FUN_801158ec(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,fVar3,
                         (int *)(param_11 + 0x17f),(int)param_11,param_11,&local_28,param_11 + 4,
                         param_16);
    if (iVar5 == 0) {
      *(undefined *)(param_11 + 0x180) = 6;
    }
  }
  else if (bVar1 < 8) goto LAB_80114fc8;
LAB_80114fd0:
  param_11[0x181] = fVar3;
  uStack_1c = (uint)DAT_803dc070;
  local_20 = 0x43300000;
  FUN_8002fb40((double)*param_11,
               (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2928));
  if (*(char *)(param_11 + 0x180) == '\a') {
    *(ushort *)(iVar7 + 0x6e) = *(ushort *)(iVar7 + 0x6e) | 8;
    puVar6 = (undefined2 *)FUN_800396d0(iVar2,0);
    if (puVar6 != (undefined2 *)0x0) {
      *(undefined2 *)(iVar7 + 0x114) = puVar6[1];
      *(undefined2 *)(iVar7 + 0x116) = *puVar6;
    }
    *(undefined *)(param_11 + 0x180) = 0;
    *(undefined *)(iVar7 + 0x56) = 0;
    *(ushort *)(iVar7 + 0x6e) = *(ushort *)(iVar7 + 0x6e) | 4;
  }
LAB_80115070:
  FUN_80286888();
  return;
}

