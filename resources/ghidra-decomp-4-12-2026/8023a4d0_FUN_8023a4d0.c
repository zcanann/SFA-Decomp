// Function: FUN_8023a4d0
// Entry: 8023a4d0
// Size: 212 bytes

void FUN_8023a4d0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  undefined8 extraout_f1;
  undefined8 uVar4;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e8128;
  uVar1 = FUN_8002e144();
  if (((uVar1 & 0xff) != 0) && (iVar2 = FUN_800381d8(param_9,0x7e5,local_18), iVar2 != 0)) {
    uVar4 = extraout_f1;
    puVar3 = FUN_8002becc(0x24,0x608);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar2 + 0xc);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar2 + 0x10);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar2 + 0x14);
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    iVar2 = FUN_8002b678(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         puVar3);
    *(int *)(param_10 + 0x10) = iVar2;
    if (*(int *)(param_10 + 0x10) != 0) {
      *(undefined *)(*(int *)(param_10 + 0x10) + 0x36) = 0xff;
      *(undefined *)(*(int *)(param_10 + 0x10) + 0x37) = 0xff;
      *(undefined4 *)(param_10 + 0x90) = 300;
    }
  }
  return;
}

