// Function: FUN_80235d90
// Entry: 80235d90
// Size: 284 bytes

void FUN_80235d90(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,char param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 uVar4;
  int iVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar5 = *(int *)(iVar1 + 0x4c);
  uVar6 = extraout_f1;
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    puVar3 = FUN_8002becc(0x28,0x210);
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
    *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
    *(char *)((int)puVar3 + 7) = *(char *)(iVar5 + 7) + -10;
    iVar5 = (int)uVar7 + param_11 * 0xc;
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar5 + 0xc);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar5 + 0x10);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar5 + 0x14);
    uVar2 = FUN_80022264(0x708,6000);
    puVar3[0xe] = (short)uVar2;
    puVar3[0xf] = 0;
    *(undefined *)(puVar3 + 0x10) = 10;
    *(undefined *)((int)puVar3 + 0x21) = 0x28;
    *(undefined *)(puVar3 + 0x11) = 0x32;
    *(undefined *)((int)puVar3 + 0x23) = 10;
    *(undefined *)(puVar3 + 0x12) = 0x32;
    *(undefined *)((int)puVar3 + 0x25) = 0xd8;
    puVar3[0x13] = 0xffff;
    *(undefined4 *)(puVar3 + 0xc) = 0;
    uVar4 = FUN_8002e088(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                         *(undefined *)(iVar1 + 0xac),0xffffffff,*(uint **)(iVar1 + 0x30),param_14,
                         param_15,param_16);
    *(undefined4 *)((int)uVar7 + param_11 * 4) = uVar4;
  }
  FUN_8028688c();
  return;
}

