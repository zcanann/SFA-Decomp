// Function: FUN_8022f22c
// Entry: 8022f22c
// Size: 368 bytes

void FUN_8022f22c(short *param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  undefined *puVar3;
  
  puVar3 = *(undefined **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *(undefined *)(param_1 + 0x1b) = 1;
  sVar1 = param_1[0x23];
  if (sVar1 != 0x6ae) {
    if (sVar1 < 0x6ae) {
      if (sVar1 == 0x655) {
        FUN_80035a58((int)param_1,1);
        *puVar3 = 0;
        puVar3[0x18] = 1;
        goto LAB_8022f364;
      }
      if ((sVar1 < 0x655) && (sVar1 == 0x604)) {
        FUN_80035a58((int)param_1,1);
        if (*(char *)((int)param_1 + 0xad) == '\0') {
          *puVar3 = 1;
          puVar3[0x18] = 2;
        }
        else {
          *puVar3 = 2;
          puVar3[0x18] = 2;
        }
        goto LAB_8022f364;
      }
LAB_8022f350:
      FUN_80035a58((int)param_1,1);
      *puVar3 = 2;
      goto LAB_8022f364;
    }
    if (sVar1 == 0x80d) {
      uVar2 = FUN_80022264(0xfffffe0c,500);
      *(short *)(puVar3 + 0x1a) = (short)uVar2;
      uVar2 = FUN_80022264(0xfffffe0c,500);
      *(short *)(puVar3 + 0x1c) = (short)uVar2;
    }
    else if ((0x80c < sVar1) || (sVar1 != 0x7e4)) goto LAB_8022f350;
  }
  FUN_80035a58((int)param_1,4);
  *puVar3 = 4;
  puVar3[0x18] = 2;
LAB_8022f364:
  if (*(int *)(param_1 + 0x2a) != 0) {
    *(undefined2 *)(*(int *)(param_1 + 0x2a) + 0xb2) = 1;
  }
  FUN_800372f8((int)param_1,2);
  return;
}

