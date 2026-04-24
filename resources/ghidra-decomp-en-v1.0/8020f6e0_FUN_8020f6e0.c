// Function: FUN_8020f6e0
// Entry: 8020f6e0
// Size: 1040 bytes

void FUN_8020f6e0(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  char cVar5;
  int iVar6;
  int *piVar7;
  float local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined2 local_1c;
  
  iVar1 = FUN_802860d8();
  local_28 = FLOAT_803e6708;
  piVar7 = *(int **)(iVar1 + 0xb8);
  *(undefined *)((int)piVar7 + 0xa1) = 1;
  FUN_80035f00();
  if (*piVar7 != 0) {
    FUN_80035f00();
  }
  if ((*(short *)(iVar1 + 0xb4) == -1) ||
     (((*(short *)(iVar1 + 0x46) != 0x16d && (*(short *)(iVar1 + 0x46) != 0x170)) ||
      (iVar2 = FUN_8001ffb4(0x3a3), iVar2 == 0)))) {
    *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) & 0xbfff;
    iVar2 = *piVar7;
    *(undefined *)(piVar7 + 0x28) = 0xff;
    if ((iVar2 != 0) && ((*(ushort *)(iVar2 + 6) & 0x4000) != 0)) {
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x3c))(iVar2,2);
    }
    if (*(char *)(param_3 + 0x7e) == '\x02') {
      *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 8;
    }
    *(undefined2 *)(param_3 + 0x6e) = *(undefined2 *)(param_3 + 0x70);
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
      switch(*(undefined *)(param_3 + iVar6 + 0x81)) {
      case 1:
        iVar2 = *piVar7;
        if (iVar2 != 0) {
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x3c))(iVar2,0);
          *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) | 4;
        }
        break;
      case 2:
        if (iVar2 != 0) {
          piVar7[2] = (int)FLOAT_803e670c;
          piVar7[3] = piVar7[6];
          piVar7[4] = piVar7[7];
          piVar7[5] = piVar7[8];
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x3c))(iVar2,2);
          FUN_80030334((double)FLOAT_803e66f0,iVar1,*(undefined2 *)(piVar7 + 0x2a),1);
          iVar4 = *(int *)(iVar1 + 100);
          if (iVar4 != 0) {
            *(uint *)(iVar4 + 0x30) = *(uint *)(iVar4 + 0x30) | 0x1000;
          }
          *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffb;
        }
        break;
      case 3:
        *(undefined *)((int)piVar7 + 0xa2) = 0xff;
        break;
      case 4:
        iVar4 = FUN_8001ffb4(0xb7d);
        if (iVar4 != 0) {
          *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
        }
        break;
      case 5:
        iVar4 = FUN_8001ffb4((int)*(short *)piVar7[1]);
        if (iVar4 != 0) {
          *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
        }
        break;
      case 6:
        iVar4 = FUN_80036e58(0x1e,iVar1,&local_28);
        if (iVar4 != 0) {
          (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4,2);
          *(byte *)((int)piVar7 + 0xaa) = *(byte *)((int)piVar7 + 0xaa) & 0x7f;
        }
        break;
      case 7:
        iVar4 = FUN_80036e58(0x1e,iVar1,&local_28);
        if (iVar4 != 0) {
          (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4,0);
          *(byte *)((int)piVar7 + 0xaa) = *(byte *)((int)piVar7 + 0xaa) & 0x7f | 0x80;
        }
      }
      *(undefined *)(param_3 + iVar6 + 0x81) = 0;
    }
    local_24 = DAT_802c2540;
    local_20 = DAT_802c2544;
    local_1c = DAT_802c2548;
    if (*(char *)((int)piVar7 + 0xa2) != *(char *)((int)piVar7 + 0xa3)) {
      if (*(int *)(iVar1 + 200) != 0) {
        FUN_8002cbc4();
        *(undefined4 *)(iVar1 + 200) = 0;
        *(undefined *)(iVar1 + 0xeb) = 0;
      }
      if (('\0' < *(char *)((int)piVar7 + 0xa2)) && (cVar5 = FUN_8002e04c(), cVar5 != '\0')) {
        uVar3 = FUN_8002bdf4(0x18,(int)*(short *)((int)&local_24 + *(char *)((int)piVar7 + 0xa2) * 2
                                                 ));
        uVar3 = FUN_8002df90(uVar3,4,(int)*(char *)(iVar1 + 0xac),0xffffffff,
                             *(undefined4 *)(iVar1 + 0x30));
        *(undefined4 *)(iVar1 + 200) = uVar3;
        *(undefined *)(iVar1 + 0xeb) = 1;
      }
      *(undefined *)((int)piVar7 + 0xa3) = *(undefined *)((int)piVar7 + 0xa2);
    }
    if ((iVar2 != 0) && (iVar1 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x38))(iVar2), iVar1 == 2))
    {
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffc;
    }
    uVar3 = 0;
  }
  else {
    (**(code **)(*DAT_803dca54 + 0x4c))((int)*(short *)(iVar1 + 0xb4));
    piVar7[0x2b] = (int)FLOAT_803e66f0;
    uVar3 = 4;
  }
  FUN_80286124(uVar3);
  return;
}

