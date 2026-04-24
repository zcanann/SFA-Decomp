// Function: FUN_801b0924
// Entry: 801b0924
// Size: 708 bytes

void FUN_801b0924(int param_1)

{
  bool bVar1;
  byte bVar2;
  float fVar3;
  short sVar4;
  undefined4 uVar5;
  int iVar6;
  int *piVar7;
  float local_28;
  float local_24;
  float local_20;
  
  piVar7 = *(int **)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  bVar2 = *(byte *)((int)piVar7 + 0x1a);
  if (bVar2 != 3) {
    if (bVar2 < 3) {
      if (bVar2 == 1) {
        if (*piVar7 != 0) {
          FUN_8001db6c((double)FLOAT_803e4824,*piVar7,1);
        }
        FUN_8000bb18(param_1,0x72);
        piVar7[4] = (int)((float)piVar7[4] - FLOAT_803db414);
        if (FLOAT_803e4828 < (float)piVar7[4]) {
          uVar5 = 0;
        }
        else {
          uVar5 = 7;
          piVar7[4] = (int)((float)piVar7[4] + FLOAT_803e482c);
        }
        piVar7[5] = (int)((float)piVar7[5] - FLOAT_803db414);
        fVar3 = (float)piVar7[5];
        bVar1 = fVar3 <= FLOAT_803e4828;
        if (bVar1) {
          piVar7[5] = (int)(fVar3 + FLOAT_803e4820);
        }
        local_28 = FLOAT_803e4828;
        local_24 = FLOAT_803e482c;
        local_20 = FLOAT_803e4828;
        FUN_80098b18((double)*(float *)(param_1 + 8),param_1,2,uVar5,bVar1,&local_28);
        FUN_80035df4(param_1,0x1f,1,0);
        goto LAB_801b0b30;
      }
      if (bVar2 != 0) {
        if (*piVar7 != 0) {
          FUN_8001db6c((double)FLOAT_803e4824,*piVar7,0);
        }
        if (*(char *)(piVar7 + 7) < '\x01') {
          FUN_80035f00(param_1);
          *(undefined *)((int)piVar7 + 0x1a) = 1;
          *(undefined *)((int)piVar7 + 0x1d) = 1;
          FUN_800200e8((int)*(short *)(iVar6 + 0x1e),1);
        }
        iVar6 = FUN_8002b9ac();
        if (iVar6 != 0) {
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            (**(code **)(**(int **)(iVar6 + 0x68) + 0x28))(iVar6,param_1,1,4);
          }
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        }
        FUN_80035df4(param_1,0,0,0);
        goto LAB_801b0b30;
      }
    }
    else if (bVar2 < 5) goto LAB_801b0b30;
  }
  if (*(char *)(piVar7 + 6) == '\0') {
    *(undefined *)((int)piVar7 + 0x1a) = 1;
    *(undefined *)((int)piVar7 + 0x1d) = 1;
  }
  else {
    *(undefined *)((int)piVar7 + 0x1a) = 2;
  }
LAB_801b0b30:
  if (*(char *)((int)piVar7 + 0x1d) != '\0') {
    *(undefined *)((int)piVar7 + 0x1d) = 0;
  }
  iVar6 = *piVar7;
  if (((iVar6 != 0) && (*(char *)(iVar6 + 0x2f8) != '\0')) && (*(char *)(iVar6 + 0x4c) != '\0')) {
    sVar4 = FUN_800221a0(0xffffffe7,0x19);
    iVar6 = *piVar7;
    sVar4 = (ushort)*(byte *)(iVar6 + 0x2f9) + *(char *)(iVar6 + 0x2fa) + sVar4;
    if (sVar4 < 0) {
      sVar4 = 0;
      *(undefined *)(iVar6 + 0x2fa) = 0;
    }
    else if (0xff < sVar4) {
      sVar4 = 0xff;
      *(undefined *)(iVar6 + 0x2fa) = 0;
    }
    *(char *)(*piVar7 + 0x2f9) = (char)sVar4;
  }
  return;
}

