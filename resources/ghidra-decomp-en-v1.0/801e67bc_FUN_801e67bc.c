// Function: FUN_801e67bc
// Entry: 801e67bc
// Size: 468 bytes

void FUN_801e67bc(void)

{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  int unaff_r27;
  undefined4 uVar5;
  int iVar6;
  undefined8 uVar7;
  int local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  
  uVar7 = FUN_802860dc();
  puVar2 = (undefined2 *)((ulonglong)uVar7 >> 0x20);
  local_2c = DAT_803e59d0;
  local_28 = DAT_803e59d4;
  iVar3 = FUN_8002b9ec();
  iVar6 = *(int *)(puVar2 + 0x5c);
  if ((*(char *)((int)uVar7 + 0x27a) != '\0') &&
     (iVar4 = FUN_800138b4(*(undefined4 *)(iVar6 + 0x9b0)), iVar4 != 0)) {
    iVar3 = (**(code **)(*DAT_803dca9c + 0x14))
                      ((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                       (double)*(float *)(iVar3 + 0x14),&local_2c,2,0xffffffff);
    if (iVar3 != -1) {
      unaff_r27 = (**(code **)(*DAT_803dca9c + 0x1c))();
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(unaff_r27 + 8);
      fVar1 = FLOAT_803e59e0;
      *(float *)(puVar2 + 8) = FLOAT_803e59e0 + *(float *)(unaff_r27 + 0xc);
      *(undefined4 *)(puVar2 + 10) = *(undefined4 *)(unaff_r27 + 0x10);
      *puVar2 = (short)((int)*(char *)(unaff_r27 + 0x2c) << 8);
      *(float *)(iVar6 + 0x9bc) = fVar1 + *(float *)(unaff_r27 + 0xc);
      *(undefined2 *)(iVar6 + 0x9ca) = 0;
      *(undefined *)(iVar6 + 0x9d3) = *(undefined *)(unaff_r27 + 0x19);
    }
    if (*(char *)(unaff_r27 + 0x19) == '\f') {
      local_30 = 1;
      uVar5 = *(undefined4 *)(iVar6 + 0x9b0);
      iVar3 = FUN_800138c4(uVar5);
      if (iVar3 == 0) {
        FUN_80013958(uVar5,&local_30);
      }
    }
    else {
      local_34 = 2;
      uVar5 = *(undefined4 *)(iVar6 + 0x9b0);
      iVar3 = FUN_800138c4(uVar5);
      if (iVar3 == 0) {
        FUN_80013958(uVar5,&local_34);
      }
    }
    *(float *)((int)uVar7 + 0x280) = FLOAT_803e59dc;
    *(byte *)(iVar6 + 0x9d4) = *(byte *)(iVar6 + 0x9d4) | 0x20;
  }
  *(undefined *)(iVar6 + 0x9d6) = 0xff;
  if (*(char *)(iVar6 + 0x9d6) == -1) {
    uVar5 = *(undefined4 *)(iVar6 + 0x9b0);
    local_38 = 0;
    iVar3 = FUN_800138b4(uVar5);
    if (iVar3 == 0) {
      FUN_800138e0(uVar5,&local_38);
    }
    iVar3 = local_38 + 1;
  }
  else {
    iVar3 = 0;
  }
  FUN_80286128(iVar3);
  return;
}

