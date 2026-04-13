// Function: FUN_802ab1e0
// Entry: 802ab1e0
// Size: 356 bytes

void FUN_802ab1e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  undefined8 extraout_f1;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  FUN_800207ac(1);
  FUN_800206ec(0xff);
  uVar7 = FUN_8005d0e4(1);
  if (param_9 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = (uint)(-(int)*(char *)(param_9 + 0xad) | (int)*(char *)(param_9 + 0xad)) >> 0x1f;
  }
  if (uVar1 == 0) {
    puVar2 = FUN_8002becc(0x20,0x887);
  }
  else {
    puVar2 = FUN_8002becc(0x20,0x882);
  }
  *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
  *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_9 + 0x10);
  *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
  uVar3 = FUN_8002e088(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff,
                       0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
  *(undefined4 *)(iVar6 + 0x46c) = uVar3;
  *(byte *)(iVar6 + 0x3f3) = *(byte *)(iVar6 + 0x3f3) & 0xfb;
  *(byte *)(iVar6 + 0x3f3) = *(byte *)(iVar6 + 0x3f3) & 0xfd | 2;
  DAT_803df0ac = 0;
  iVar5 = 0;
  piVar4 = &DAT_80333b34;
  uVar7 = extraout_f1;
  do {
    if (*piVar4 != 0) {
      uVar7 = FUN_8002cc9c(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar4);
      *piVar4 = 0;
    }
    piVar4 = piVar4 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 7);
  if (DAT_803df0d4 != (undefined *)0x0) {
    FUN_80013e4c(DAT_803df0d4);
    DAT_803df0d4 = (undefined *)0x0;
  }
  *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) & 0xfffffbff;
  uVar7 = FUN_8000d03c();
  FUN_8000d220(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

