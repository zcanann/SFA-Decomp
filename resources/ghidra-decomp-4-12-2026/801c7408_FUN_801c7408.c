// Function: FUN_801c7408
// Entry: 801c7408
// Size: 568 bytes

void FUN_801c7408(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)

{
  uint uVar1;
  int *piVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  short *psVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_9 + 0x26);
  psVar4 = *(short **)(param_9 + 0x5c);
  if ((*(int *)(param_9 + 0x7c) == 0) && (uVar1 = FUN_80020078((int)psVar4[2]), uVar1 != 0)) {
    piVar2 = (int *)FUN_80013ee8(0x82);
    (**(code **)(*piVar2 + 4))(param_9,0,0,1,0xffffffff,0);
    in_r8 = 0;
    in_r9 = *piVar2;
    (**(code **)(in_r9 + 4))(param_9,1,0,1,0xffffffff);
    param_1 = FUN_8000bb38((uint)param_9,0x16d);
    FUN_80013e4c((undefined *)piVar2);
    psVar4[1] = 1;
    *(undefined4 *)(param_9 + 0x7c) = 1;
  }
  if (psVar4[1] != 0) {
    *psVar4 = *psVar4 - psVar4[1] * (ushort)DAT_803dc070;
  }
  uVar1 = FUN_8002e144();
  if (((uVar1 & 0xff) != 0) && (*psVar4 < 1)) {
    puVar3 = (undefined2 *)FUN_80023d8c(0x38,0xe);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar5 + 8);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar5 + 0xc);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar5 + 0x10);
    *puVar3 = 0x11;
    *(undefined4 *)(puVar3 + 10) = 0xffffffff;
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
    *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
    *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar5 + 7);
    *(undefined *)((int)puVar3 + 0x27) = 3;
    *(undefined *)(puVar3 + 0x14) = 0;
    puVar3[0xc] = psVar4[2] + (short)*(char *)(iVar5 + 0x1f);
    puVar3[0x18] = 0xffff;
    *(char *)(puVar3 + 0x15) = (char)((ushort)*param_9 >> 8);
    *(undefined *)((int)puVar3 + 0x2b) = 2;
    puVar3[0x10] = 0;
    puVar3[0xf] = 0;
    puVar3[0x11] = 0xffff;
    *(undefined *)((int)puVar3 + 0x29) = 0xff;
    *(undefined *)(puVar3 + 0x17) = 0xff;
    puVar3[0x12] = 0;
    puVar3[0x16] = 0;
    puVar3[0x1a] = 0xffff;
    puVar3[0xd] = 0;
    *(char *)(puVar3 + 0x19) = (char)psVar4[4];
    iVar5 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                         *(undefined *)(param_9 + 0x56),0xffffffff,*(uint **)(param_9 + 0x18),in_r8,
                         in_r9,in_r10);
    if (iVar5 != 0) {
      *(undefined *)(*(int *)(iVar5 + 0xb8) + 0x404) = 0x20;
    }
    *psVar4 = 100;
    psVar4[1] = 0;
  }
  return;
}

