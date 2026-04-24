// Function: FUN_802aa46c
// Entry: 802aa46c
// Size: 776 bytes

void FUN_802aa46c(undefined4 param_1,undefined4 param_2,undefined2 *param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,int param_8)

{
  short sVar1;
  undefined2 *puVar2;
  int iVar3;
  short sVar4;
  int iVar5;
  undefined8 uVar6;
  int local_48;
  undefined local_44 [2];
  short sStack_42;
  undefined local_40 [2];
  short sStack_3e;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  longlong local_30;
  
  uVar6 = FUN_80286838();
  puVar2 = (undefined2 *)((ulonglong)uVar6 >> 0x20);
  iVar5 = (int)uVar6;
  if (param_8 != 0) {
    iVar3 = FUN_800396d0((int)puVar2,0);
    if (iVar3 != 0) {
      sVar1 = *(short *)(iVar3 + 2);
      if (sVar1 < 1) {
        local_30 = (longlong)(int)(FLOAT_803e8ce8 * FLOAT_803dc074);
        *(short *)(iVar3 + 2) = sVar1 + (short)(int)(FLOAT_803e8ce8 * FLOAT_803dc074);
        if (0 < *(short *)(iVar3 + 2)) {
          *(undefined2 *)(iVar3 + 2) = 0;
        }
      }
      else {
        local_30 = (longlong)(int)(FLOAT_803e8ce8 * FLOAT_803dc074);
        *(short *)(iVar3 + 2) = sVar1 - (short)(int)(FLOAT_803e8ce8 * FLOAT_803dc074);
        if (*(short *)(iVar3 + 2) < 0) {
          *(undefined2 *)(iVar3 + 2) = 0;
        }
      }
    }
    (**(code **)(**(int **)(param_3 + 0x34) + 0x10))
              (param_3,param_4,param_5,param_6,param_7,0xffffffff);
    *(undefined4 *)(puVar2 + 0x46) = *(undefined4 *)(puVar2 + 0xc);
    *(undefined4 *)(puVar2 + 0x48) = *(undefined4 *)(puVar2 + 0xe);
    *(undefined4 *)(puVar2 + 0x4a) = *(undefined4 *)(puVar2 + 0x10);
    *(undefined4 *)(puVar2 + 0x40) = *(undefined4 *)(puVar2 + 6);
    *(undefined4 *)(puVar2 + 0x42) = *(undefined4 *)(puVar2 + 8);
    *(undefined4 *)(puVar2 + 0x44) = *(undefined4 *)(puVar2 + 10);
  }
  (**(code **)(**(int **)(param_3 + 0x34) + 0x28))(param_3,&local_34,&local_38,&local_3c);
  *(undefined4 *)(puVar2 + 6) = local_34;
  *(undefined4 *)(puVar2 + 8) = local_38;
  *(undefined4 *)(puVar2 + 10) = local_3c;
  if ((*(short *)(*(int *)(puVar2 + 0x5c) + 0x274) == 0x18) || ((puVar2[0x58] & 0x1000) != 0)) {
    puVar2[1] = param_3[1];
    puVar2[2] = param_3[2];
    *(undefined2 *)(iVar5 + 0x478) = *param_3;
  }
  else {
    local_48 = 1;
    (**(code **)(**(int **)(param_3 + 0x34) + 0x54))(param_3,2,local_40);
    sVar1 = *(short *)(iVar5 + 0x478) - sStack_3e;
    if (0x8000 < sVar1) {
      sVar1 = sVar1 + 1;
    }
    if (sVar1 < -0x8000) {
      sVar1 = sVar1 + -1;
    }
    (**(code **)(**(int **)(param_3 + 0x34) + 0x54))(param_3,3,local_44);
    sVar4 = -sStack_42;
    if ((sVar4 <= sVar1) && (sVar4 = sVar1, sStack_42 < sVar1)) {
      sVar4 = sStack_42;
    }
    *(short *)(iVar5 + 0x478) = sStack_3e + sVar4;
    (**(code **)(**(int **)(param_3 + 0x34) + 0x54))(param_3,4,&local_48);
    if (local_48 != 0) {
      puVar2[1] = param_3[1];
      puVar2[2] = param_3[2];
    }
  }
  *(undefined2 *)(iVar5 + 0x484) = *(undefined2 *)(iVar5 + 0x478);
  *puVar2 = *(undefined2 *)(iVar5 + 0x478);
  *(undefined4 *)(puVar2 + 0xc) = *(undefined4 *)(puVar2 + 6);
  *(undefined4 *)(puVar2 + 0xe) = *(undefined4 *)(puVar2 + 8);
  *(undefined4 *)(puVar2 + 0x10) = *(undefined4 *)(puVar2 + 10);
  *(undefined4 *)(puVar2 + 0x12) = *(undefined4 *)(param_3 + 0x12);
  *(undefined4 *)(puVar2 + 0x14) = *(undefined4 *)(param_3 + 0x14);
  *(undefined4 *)(puVar2 + 0x16) = *(undefined4 *)(param_3 + 0x16);
  FUN_802abd04((int)puVar2,iVar5,7);
  FUN_80286884();
  return;
}

