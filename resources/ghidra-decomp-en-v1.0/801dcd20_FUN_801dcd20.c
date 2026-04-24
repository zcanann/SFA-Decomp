// Function: FUN_801dcd20
// Entry: 801dcd20
// Size: 752 bytes

/* WARNING: Removing unreachable block (ram,0x801dce98) */

void FUN_801dcd20(short *param_1)

{
  byte bVar1;
  int *piVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int local_28;
  int local_24;
  undefined4 local_20;
  uint uStack28;
  
  iVar7 = *(int *)(param_1 + 0x5c);
  if ((*(int *)(param_1 + 0x26) != 0) && (*(short *)(*(int *)(param_1 + 0x26) + 0x18) != -1)) {
    uStack28 = (uint)DAT_803db411;
    local_20 = 0x43300000;
    local_24 = (**(code **)(*DAT_803dca54 + 0x14))
                         ((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e55e8));
    if ((local_24 != 0) && (param_1[0x5a] == -2)) {
      iVar6 = (int)*(char *)(iVar7 + 0x57);
      iVar8 = 0;
      piVar2 = (int *)FUN_8002e0fc(&local_24,&local_28);
      iVar5 = 0;
      for (local_24 = 0; local_24 < local_28; local_24 = local_24 + 1) {
        iVar4 = *piVar2;
        if (*(short *)(iVar4 + 0xb4) == iVar6) {
          iVar8 = iVar4;
        }
        if (((*(short *)(iVar4 + 0xb4) == -2) && (*(short *)(iVar4 + 0x44) == 0x10)) &&
           (iVar7 = *(int *)(iVar4 + 0xb8), iVar6 == *(char *)(iVar7 + 0x57))) {
          iVar5 = iVar5 + 1;
        }
        piVar2 = piVar2 + 1;
      }
      if (((iVar5 < 2) && (iVar8 != 0)) && (*(short *)(iVar8 + 0xb4) != -1)) {
        *(undefined2 *)(iVar8 + 0xb4) = 0xffff;
        (**(code **)(*DAT_803dca54 + 0x4c))(iVar6);
      }
      param_1[0x5a] = -1;
    }
    for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(iVar7 + 0x8b); iVar8 = iVar8 + 1) {
      bVar1 = *(byte *)(iVar7 + iVar8 + 0x81);
      if (bVar1 == 1) {
        if (*(int *)(param_1 + 100) != 0) {
          FUN_80236b38(*(int *)(param_1 + 100),0);
        }
      }
      else if (bVar1 == 0) {
        if ((*(int *)(param_1 + 100) == 0) && (cVar3 = FUN_8002e04c(), cVar3 != '\0')) {
          iVar5 = FUN_8002bdf4(0x30,0x6e8);
          *(undefined *)(iVar5 + 0x1b) = 9;
          *(undefined *)(iVar5 + 0x1c) = 0;
          *(undefined *)(iVar5 + 0x1d) = 0;
          *(float *)(iVar5 + 0x20) = FLOAT_803e55e0;
          *(undefined *)(iVar5 + 0x26) = 0xff;
          *(undefined *)(iVar5 + 0x27) = 0xff;
          *(undefined *)(iVar5 + 0x28) = 0xff;
          *(undefined2 *)(iVar5 + 0x24) = 0xffff;
          *(undefined *)(iVar5 + 4) = 2;
          *(undefined *)(iVar5 + 5) = 1;
          *(undefined *)(iVar5 + 6) = 0xff;
          *(undefined *)(iVar5 + 7) = 0xff;
          *(undefined *)(iVar5 + 0x29) = 1;
          *(undefined *)(iVar5 + 0x2a) = 0;
          iVar5 = FUN_8002df90(iVar5,5,(int)*(char *)(param_1 + 0x56),0xffffffff,
                               *(undefined4 *)(param_1 + 0x18));
          *(ushort *)(iVar5 + 6) = *(ushort *)(iVar5 + 6) | 0x4000;
          FUN_80037d2c(param_1,iVar5,0);
          FUN_8000bb18(param_1,0x10f);
        }
      }
      else if ((bVar1 < 3) && (iVar5 = *(int *)(param_1 + 100), iVar5 != 0)) {
        FUN_80037cb0(param_1,iVar5);
        FUN_8002cbc4(iVar5);
      }
    }
    if (*(int *)(param_1 + 100) != 0) {
      *(short *)(*(int *)(param_1 + 100) + 4) = param_1[2];
      *(short *)(*(int *)(param_1 + 100) + 2) = param_1[1] + 0xe38;
      **(short **)(param_1 + 100) = *param_1 + -0x8000;
    }
  }
  return;
}

