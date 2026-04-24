// Function: FUN_801c3710
// Entry: 801c3710
// Size: 612 bytes

void FUN_801c3710(int param_1)

{
  byte bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int local_28;
  int local_24;
  undefined4 local_20;
  uint uStack28;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  iVar7 = *(int *)(param_1 + 0xb8);
  if (((iVar2 != 0) && (*(short *)(iVar2 + 0x18) != -1)) && (*(int *)(iVar2 + 0x14) != 0x4ca62)) {
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(iVar7 + 0x8b); iVar2 = iVar2 + 1) {
      bVar1 = *(byte *)(iVar7 + iVar2 + 0x81);
      if (bVar1 == 2) {
        *(undefined *)(iVar7 + 0x144) = 1;
      }
      else if ((bVar1 < 2) && (bVar1 != 0)) {
        *(undefined *)(iVar7 + 0x144) = 0;
      }
    }
    uStack28 = (uint)DAT_803db411;
    local_20 = 0x43300000;
    local_28 = (**(code **)(*DAT_803dca54 + 0x14))
                         ((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e4ea0),
                          param_1);
    if ((local_28 != 0) && (*(short *)(param_1 + 0xb4) == -2)) {
      iVar6 = (int)*(char *)(iVar7 + 0x57);
      iVar2 = 0;
      piVar3 = (int *)FUN_8002e0fc(&local_28,&local_24);
      iVar5 = 0;
      for (local_28 = 0; local_28 < local_24; local_28 = local_28 + 1) {
        iVar4 = *piVar3;
        if (*(short *)(iVar4 + 0xb4) == iVar6) {
          iVar2 = iVar4;
        }
        if (((*(short *)(iVar4 + 0xb4) == -2) && (*(short *)(iVar4 + 0x44) == 0x10)) &&
           (iVar6 == *(char *)(*(int *)(iVar4 + 0xb8) + 0x57))) {
          iVar5 = iVar5 + 1;
        }
        piVar3 = piVar3 + 1;
      }
      if (((iVar5 < 2) && (iVar2 != 0)) && (*(short *)(iVar2 + 0xb4) != -1)) {
        *(undefined2 *)(iVar2 + 0xb4) = 0xffff;
        (**(code **)(*DAT_803dca54 + 0x4c))(iVar6);
      }
      *(undefined2 *)(param_1 + 0xb4) = 0xffff;
      FUN_8002cbc4(param_1);
    }
    *(float *)(iVar7 + 0x148) = *(float *)(iVar7 + 0x148) - FLOAT_803db414;
    if (*(float *)(iVar7 + 0x148) < FLOAT_803e4e9c) {
      iVar2 = FUN_8002b9ec();
      uStack28 = FUN_800221a0(0xb4,0xf0);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar7 + 0x148) = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e4ea8);
      if ((*(char *)(param_1 + 0xac) == -1) &&
         ((iVar2 == 0 ||
          (iVar2 = FUN_8005afac((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x14)),
          iVar2 == 0xb)))) {
        FUN_8000bb18(param_1,0x4a0);
      }
    }
  }
  return;
}

