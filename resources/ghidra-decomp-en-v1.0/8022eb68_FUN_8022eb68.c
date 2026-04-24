// Function: FUN_8022eb68
// Entry: 8022eb68
// Size: 368 bytes

void FUN_8022eb68(short *param_1,int param_2)

{
  short sVar1;
  undefined2 uVar2;
  undefined *puVar3;
  
  puVar3 = *(undefined **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *(undefined *)(param_1 + 0x1b) = 1;
  sVar1 = param_1[0x23];
  if (sVar1 != 0x6ae) {
    if (sVar1 < 0x6ae) {
      if (sVar1 == 0x655) {
        FUN_80035960(param_1,1);
        *puVar3 = 0;
        puVar3[0x18] = 1;
        goto LAB_8022eca0;
      }
      if ((sVar1 < 0x655) && (sVar1 == 0x604)) {
        FUN_80035960(param_1,1);
        if (*(char *)((int)param_1 + 0xad) == '\0') {
          *puVar3 = 1;
          puVar3[0x18] = 2;
        }
        else {
          *puVar3 = 2;
          puVar3[0x18] = 2;
        }
        goto LAB_8022eca0;
      }
LAB_8022ec8c:
      FUN_80035960(param_1,1);
      *puVar3 = 2;
      goto LAB_8022eca0;
    }
    if (sVar1 == 0x80d) {
      uVar2 = FUN_800221a0(0xfffffe0c,500);
      *(undefined2 *)(puVar3 + 0x1a) = uVar2;
      uVar2 = FUN_800221a0(0xfffffe0c,500);
      *(undefined2 *)(puVar3 + 0x1c) = uVar2;
    }
    else if ((0x80c < sVar1) || (sVar1 != 0x7e4)) goto LAB_8022ec8c;
  }
  FUN_80035960(param_1,4);
  *puVar3 = 4;
  puVar3[0x18] = 2;
LAB_8022eca0:
  if (*(int *)(param_1 + 0x2a) != 0) {
    *(undefined2 *)(*(int *)(param_1 + 0x2a) + 0xb2) = 1;
  }
  FUN_80037200(param_1,2);
  return;
}

