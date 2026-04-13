// Function: FUN_8020fd58
// Entry: 8020fd58
// Size: 1040 bytes

void FUN_8020fd58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined2 *puVar4;
  undefined4 uVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  undefined8 uVar9;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  float local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined2 local_1c;
  
  iVar1 = FUN_8028683c();
  local_28 = FLOAT_803e73a0;
  piVar7 = *(int **)(iVar1 + 0xb8);
  *(undefined *)((int)piVar7 + 0xa1) = 1;
  uVar9 = FUN_80035ff8(iVar1);
  if (*piVar7 != 0) {
    uVar9 = FUN_80035ff8(*piVar7);
  }
  if ((*(short *)(iVar1 + 0xb4) == -1) ||
     (((*(short *)(iVar1 + 0x46) != 0x16d && (*(short *)(iVar1 + 0x46) != 0x170)) ||
      (uVar2 = FUN_80020078(0x3a3), uVar2 == 0)))) {
    *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) & 0xbfff;
    iVar8 = *piVar7;
    *(undefined *)(piVar7 + 0x28) = 0xff;
    if ((iVar8 != 0) && ((*(ushort *)(iVar8 + 6) & 0x4000) != 0)) {
      *(ushort *)(iVar8 + 6) = *(ushort *)(iVar8 + 6) & 0xbfff;
      uVar9 = (**(code **)(**(int **)(iVar8 + 0x68) + 0x3c))(iVar8,2);
    }
    if (*(char *)(param_11 + 0x7e) == '\x02') {
      *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 8;
    }
    *(undefined2 *)(param_11 + 0x6e) = *(undefined2 *)(param_11 + 0x70);
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar6 = iVar6 + 1) {
      switch(*(undefined *)(param_11 + iVar6 + 0x81)) {
      case 1:
        iVar8 = *piVar7;
        if (iVar8 != 0) {
          uVar9 = (**(code **)(**(int **)(iVar8 + 0x68) + 0x3c))(iVar8,0);
          *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) | 4;
        }
        break;
      case 2:
        if (iVar8 != 0) {
          piVar7[2] = (int)FLOAT_803e73a4;
          piVar7[3] = piVar7[6];
          piVar7[4] = piVar7[7];
          piVar7[5] = piVar7[8];
          (**(code **)(**(int **)(iVar8 + 0x68) + 0x3c))(iVar8,2);
          uVar9 = FUN_8003042c((double)FLOAT_803e7388,param_2,param_3,param_4,param_5,param_6,
                               param_7,param_8,iVar1,(uint)*(ushort *)(piVar7 + 0x2a),1,param_12,
                               param_13,param_14,param_15,param_16);
          iVar3 = *(int *)(iVar1 + 100);
          if (iVar3 != 0) {
            *(uint *)(iVar3 + 0x30) = *(uint *)(iVar3 + 0x30) | 0x1000;
          }
          *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfffb;
        }
        break;
      case 3:
        *(undefined *)((int)piVar7 + 0xa2) = 0xff;
        break;
      case 4:
        uVar2 = FUN_80020078(0xb7d);
        if (uVar2 != 0) {
          *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 4;
        }
        break;
      case 5:
        uVar2 = FUN_80020078((int)*(short *)piVar7[1]);
        if (uVar2 != 0) {
          *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 4;
        }
        break;
      case 6:
        iVar3 = FUN_80036f50(0x1e,iVar1,&local_28);
        uVar9 = extraout_f1;
        if (iVar3 != 0) {
          uVar9 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,2);
          *(byte *)((int)piVar7 + 0xaa) = *(byte *)((int)piVar7 + 0xaa) & 0x7f;
        }
        break;
      case 7:
        iVar3 = FUN_80036f50(0x1e,iVar1,&local_28);
        uVar9 = extraout_f1_00;
        if (iVar3 != 0) {
          uVar9 = (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,0);
          *(byte *)((int)piVar7 + 0xaa) = *(byte *)((int)piVar7 + 0xaa) & 0x7f | 0x80;
        }
      }
      *(undefined *)(param_11 + iVar6 + 0x81) = 0;
    }
    local_24 = DAT_802c2cc0;
    local_20 = DAT_802c2cc4;
    local_1c = DAT_802c2cc8;
    if (*(char *)((int)piVar7 + 0xa2) != *(char *)((int)piVar7 + 0xa3)) {
      if (*(int *)(iVar1 + 200) != 0) {
        uVar9 = FUN_8002cc9c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *(int *)(iVar1 + 200));
        *(undefined4 *)(iVar1 + 200) = 0;
        *(undefined *)(iVar1 + 0xeb) = 0;
      }
      if (('\0' < *(char *)((int)piVar7 + 0xa2)) && (uVar2 = FUN_8002e144(), (uVar2 & 0xff) != 0)) {
        puVar4 = FUN_8002becc(0x18,*(undefined2 *)
                                    ((int)&local_24 + *(char *)((int)piVar7 + 0xa2) * 2));
        uVar5 = FUN_8002e088(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,4,
                             *(undefined *)(iVar1 + 0xac),0xffffffff,*(uint **)(iVar1 + 0x30),
                             param_14,param_15,param_16);
        *(undefined4 *)(iVar1 + 200) = uVar5;
        *(undefined *)(iVar1 + 0xeb) = 1;
      }
      *(undefined *)((int)piVar7 + 0xa3) = *(undefined *)((int)piVar7 + 0xa2);
    }
    if ((iVar8 != 0) && (iVar1 = (**(code **)(**(int **)(iVar8 + 0x68) + 0x38))(iVar8), iVar1 == 2))
    {
      *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfffc;
    }
  }
  else {
    (**(code **)(*DAT_803dd6d4 + 0x4c))((int)*(short *)(iVar1 + 0xb4));
    piVar7[0x2b] = (int)FLOAT_803e7388;
  }
  FUN_80286888();
  return;
}

