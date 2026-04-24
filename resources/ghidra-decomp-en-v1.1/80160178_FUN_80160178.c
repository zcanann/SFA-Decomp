// Function: FUN_80160178
// Entry: 80160178
// Size: 664 bytes

void FUN_80160178(uint param_1)

{
  short sVar1;
  int iVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  int local_14 [3];
  
  FUN_8000faf8();
  FUN_8000e69c((double)FLOAT_803e3ae8);
  FUN_8000bb38(param_1,0x26a);
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x2cb) {
    iVar6 = *(int *)(param_1 + 0xc4);
    if (iVar6 != 0) {
      iVar5 = FUN_8002e1f4(&local_18,local_14);
      do {
        if (local_14[0] <= local_18) {
          bVar3 = false;
          goto LAB_80160208;
        }
        iVar4 = local_18 + 1;
        iVar2 = local_18 * 4;
        local_18 = iVar4;
      } while (iVar6 != *(int *)(iVar5 + iVar2));
      bVar3 = true;
LAB_80160208:
      if (bVar3) {
        (**(code **)(**(int **)(*(int *)(param_1 + 0xc4) + 0x68) + 0x20))
                  (*(int *)(param_1 + 0xc4),0x80);
      }
    }
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x340,0,1,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0x19);
  }
  else if (sVar1 == 100) {
    iVar6 = *(int *)(param_1 + 0xc4);
    if (iVar6 != 0) {
      iVar5 = FUN_8002e1f4(&local_20,&local_1c);
      do {
        if (local_1c <= local_20) {
          bVar3 = false;
          goto LAB_801602cc;
        }
        iVar4 = local_20 + 1;
        iVar2 = local_20 * 4;
        local_20 = iVar4;
      } while (iVar6 != *(int *)(iVar5 + iVar2));
      bVar3 = true;
LAB_801602cc:
      if (bVar3) {
        (**(code **)(**(int **)(*(int *)(param_1 + 0xc4) + 0x68) + 0x24))
                  (*(int *)(param_1 + 0xc4),0x80);
      }
    }
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x343,0,1,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0x19);
  }
  else if (sVar1 == 0x30a) {
    iVar6 = *(int *)(param_1 + 0xc4);
    if (iVar6 != 0) {
      iVar5 = FUN_8002e1f4(&local_28,&local_24);
      do {
        if (local_24 <= local_28) {
          bVar3 = false;
          goto LAB_80160390;
        }
        iVar4 = local_28 + 1;
        iVar2 = local_28 * 4;
        local_28 = iVar4;
      } while (iVar6 != *(int *)(iVar5 + iVar2));
      bVar3 = true;
LAB_80160390:
      if (bVar3) {
        (**(code **)(**(int **)(*(int *)(param_1 + 0xc4) + 0x68) + 0x24))
                  (*(int *)(param_1 + 0xc4),0x80,0);
      }
    }
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x343,0,1,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0x19);
  }
  return;
}

