// Function: FUN_80114bb0
// Entry: 80114bb0
// Size: 572 bytes

void FUN_80114bb0(undefined4 param_1,undefined4 param_2,float *param_3,undefined2 param_4,
                 undefined2 param_5)

{
  byte bVar1;
  int iVar2;
  float fVar3;
  undefined4 uVar4;
  int iVar5;
  undefined2 *puVar6;
  int iVar7;
  undefined8 uVar8;
  undefined2 local_28;
  undefined2 local_26;
  undefined4 local_20;
  uint uStack28;
  
  local_28 = param_4;
  local_26 = param_5;
  uVar8 = FUN_802860d8();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  iVar7 = (int)uVar8;
  fVar3 = (float)FUN_8002b9ec();
  *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) = *(ushort *)(*(int *)(iVar2 + 0x54) + 0x60) | 1;
  if (*(char *)(iVar7 + 0x56) == '\x04') {
    param_3[0x17e] = 1.121039e-43;
    *(ushort *)(iVar7 + 0x6e) = *(ushort *)(iVar7 + 0x6e) & 0xfff7;
    *(ushort *)(iVar7 + 0x6e) = *(ushort *)(iVar7 + 0x6e) & 0xfffd;
    *(undefined *)(param_3 + 0x180) = 3;
    *(undefined *)(iVar7 + 0x56) = 5;
    if ((*(byte *)((int)param_3 + 0x611) & 2) == 0) {
      *(ushort *)(iVar7 + 0x6e) = *(ushort *)(iVar7 + 0x6e) & 0xfffb;
    }
    *(code **)(iVar7 + 0xe8) = FUN_80114b1c;
    goto LAB_80114dd4;
  }
  if (((*(char *)(iVar7 + 0x56) != '\x05') || (*(byte *)(param_3 + 0x180) < 2)) ||
     (7 < *(byte *)(param_3 + 0x180))) goto LAB_80114dd4;
  uVar4 = FUN_800394a0();
  bVar1 = *(byte *)(param_3 + 0x180);
  if (bVar1 == 6) {
    *(undefined *)(param_3 + 0x180) = 7;
LAB_80114d2c:
    *param_3 = FLOAT_803e1cc4;
  }
  else if (bVar1 < 6) {
    if (bVar1 == 3) {
      FUN_8003acfc(iVar2,uVar4,*(undefined *)(param_3 + 0x184),param_3 + 7);
      param_3[0x17e] = 0.0;
      *(undefined *)(param_3 + 0x180) = 2;
    }
    else if ((2 < bVar1) || (bVar1 < 2)) goto LAB_80114d34;
    iVar5 = FUN_80115650(iVar2,fVar3,param_3 + 0x17f,param_3,param_3,&local_28,param_3 + 4);
    if (iVar5 == 0) {
      *(undefined *)(param_3 + 0x180) = 6;
    }
  }
  else if (bVar1 < 8) goto LAB_80114d2c;
LAB_80114d34:
  param_3[0x181] = fVar3;
  uStack28 = (uint)DAT_803db410;
  local_20 = 0x43300000;
  FUN_8002fa48((double)*param_3,
               (double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e1ca8),iVar2,0);
  if (*(char *)(param_3 + 0x180) == '\a') {
    *(ushort *)(iVar7 + 0x6e) = *(ushort *)(iVar7 + 0x6e) | 8;
    puVar6 = (undefined2 *)FUN_800395d8(iVar2,0);
    if (puVar6 != (undefined2 *)0x0) {
      *(undefined2 *)(iVar7 + 0x114) = puVar6[1];
      *(undefined2 *)(iVar7 + 0x116) = *puVar6;
    }
    *(undefined *)(param_3 + 0x180) = 0;
    *(undefined *)(iVar7 + 0x56) = 0;
    *(ushort *)(iVar7 + 0x6e) = *(ushort *)(iVar7 + 0x6e) | 4;
  }
LAB_80114dd4:
  FUN_80286124(0);
  return;
}

