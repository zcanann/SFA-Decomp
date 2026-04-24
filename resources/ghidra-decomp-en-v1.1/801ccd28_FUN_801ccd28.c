// Function: FUN_801ccd28
// Entry: 801ccd28
// Size: 476 bytes

void FUN_801ccd28(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  int *piVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar4;
  int iVar5;
  double dVar6;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  iVar4 = *(int *)(param_9 + 0xb8);
  if ((*(int *)(param_9 + 0xf8) != 0) && (uVar1 = FUN_80020078(0x1d4), uVar1 != 0)) {
    *(undefined4 *)(param_9 + 0xf8) = 0;
  }
  if ((*(int *)(param_9 + 0xf8) == 0) && (uVar1 = FUN_80020078(0x1d3), uVar1 != 0)) {
    piVar2 = (int *)FUN_80013ee8(0x82);
    (**(code **)(*piVar2 + 4))(param_9,0,0,1,0xffffffff,0);
    in_r8 = 0;
    in_r9 = *piVar2;
    (**(code **)(in_r9 + 4))(param_9,1,0,1,0xffffffff);
    FUN_8000bb38(0,0xaf);
    FUN_80013e4c((undefined *)piVar2);
    *(undefined2 *)(iVar4 + 6) = 1;
    *(undefined4 *)(param_9 + 0xf8) = 1;
  }
  if (*(short *)(iVar4 + 6) != 0) {
    *(ushort *)(iVar4 + 4) = *(short *)(iVar4 + 4) - *(short *)(iVar4 + 6) * (ushort)DAT_803dc070;
  }
  if (((*(short *)(iVar4 + 4) < 1) && (*(char *)(iVar5 + 0x1f) == '\0')) &&
     (uVar1 = FUN_8002e144(), (uVar1 & 0xff) != 0)) {
    puVar3 = FUN_8002becc(0x18,0x248);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar5 + 8);
    dVar6 = (double)FLOAT_803e5e4c;
    *(float *)(puVar3 + 6) = (float)(dVar6 + (double)*(float *)(iVar5 + 0xc));
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar5 + 0x10);
    *puVar3 = 0x248;
    *(undefined4 *)(puVar3 + 10) = 0xffffffff;
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
    *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
    *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar5 + 7);
    FUN_8002e088(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                 *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,in_r9,
                 in_r10);
    *(undefined2 *)(iVar4 + 4) = 100;
    *(undefined2 *)(iVar4 + 6) = 0;
  }
  return;
}

