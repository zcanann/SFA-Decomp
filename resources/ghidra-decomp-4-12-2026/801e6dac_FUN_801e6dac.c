// Function: FUN_801e6dac
// Entry: 801e6dac
// Size: 468 bytes

void FUN_801e6dac(void)

{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  int unaff_r27;
  short *psVar5;
  int iVar6;
  undefined8 uVar7;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  
  uVar7 = FUN_80286840();
  puVar2 = (undefined2 *)((ulonglong)uVar7 >> 0x20);
  local_2c = DAT_803e6668;
  local_28 = DAT_803e666c;
  iVar3 = FUN_8002bac4();
  iVar6 = *(int *)(puVar2 + 0x5c);
  if ((*(char *)((int)uVar7 + 0x27a) != '\0') &&
     (uVar4 = FUN_800138d4(*(short **)(iVar6 + 0x9b0)), uVar4 != 0)) {
    iVar3 = (**(code **)(*DAT_803dd71c + 0x14))
                      ((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                       (double)*(float *)(iVar3 + 0x14),&local_2c,2,0xffffffff);
    if (iVar3 != -1) {
      unaff_r27 = (**(code **)(*DAT_803dd71c + 0x1c))();
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(unaff_r27 + 8);
      fVar1 = FLOAT_803e6678;
      *(float *)(puVar2 + 8) = FLOAT_803e6678 + *(float *)(unaff_r27 + 0xc);
      *(undefined4 *)(puVar2 + 10) = *(undefined4 *)(unaff_r27 + 0x10);
      *puVar2 = (short)((int)*(char *)(unaff_r27 + 0x2c) << 8);
      *(float *)(iVar6 + 0x9bc) = fVar1 + *(float *)(unaff_r27 + 0xc);
      *(undefined2 *)(iVar6 + 0x9ca) = 0;
      *(undefined *)(iVar6 + 0x9d3) = *(undefined *)(unaff_r27 + 0x19);
    }
    if (*(char *)(unaff_r27 + 0x19) == '\f') {
      local_30 = 1;
      psVar5 = *(short **)(iVar6 + 0x9b0);
      uVar4 = FUN_800138e4(psVar5);
      if (uVar4 == 0) {
        FUN_80013978(psVar5,(uint)&local_30);
      }
    }
    else {
      local_34 = 2;
      psVar5 = *(short **)(iVar6 + 0x9b0);
      uVar4 = FUN_800138e4(psVar5);
      if (uVar4 == 0) {
        FUN_80013978(psVar5,(uint)&local_34);
      }
    }
    *(float *)((int)uVar7 + 0x280) = FLOAT_803e6674;
    *(byte *)(iVar6 + 0x9d4) = *(byte *)(iVar6 + 0x9d4) | 0x20;
  }
  *(undefined *)(iVar6 + 0x9d6) = 0xff;
  if (*(char *)(iVar6 + 0x9d6) == -1) {
    psVar5 = *(short **)(iVar6 + 0x9b0);
    local_38 = 0;
    uVar4 = FUN_800138d4(psVar5);
    if (uVar4 == 0) {
      FUN_80013900(psVar5,(uint)&local_38);
    }
  }
  FUN_8028688c();
  return;
}

