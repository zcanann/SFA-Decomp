// Function: FUN_801e83b8
// Entry: 801e83b8
// Size: 492 bytes

void FUN_801e83b8(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  int iVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  undefined2 *puVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar9;
  float local_28 [2];
  longlong local_20;
  
  uVar9 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  uVar4 = FUN_8002e144();
  if ((uVar4 & 0xff) != 0) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar3 + 0xac),6,1);
    dVar7 = (double)*(float *)(iVar3 + 0x10);
    dVar8 = (double)*(float *)(iVar3 + 0x14);
    FUN_80065a20((double)*(float *)(iVar3 + 0xc),dVar7,dVar8,iVar3,local_28,0);
    for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
      puVar5 = FUN_8002becc(0x24,0x47f);
      *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar3 + 0x14);
      uVar4 = FUN_80022264(0xffffff80,0x7f);
      *(char *)(puVar5 + 0xc) = (char)uVar4;
      fVar2 = *(float *)(iVar3 + 0x10);
      iVar1 = (int)((double)fVar2 - (double)local_28[0]);
      local_20 = (longlong)iVar1;
      puVar5[0xd] = (short)iVar1;
      *(undefined *)((int)puVar5 + 5) = 1;
      *(undefined *)((int)puVar5 + 7) = 0xff;
      *(undefined *)(puVar5 + 2) = 0x10;
      *(undefined *)(puVar5 + 3) = 6;
      *(undefined4 *)(puVar5 + 10) = *(undefined4 *)((int)uVar9 + 0x9b4);
      FUN_8002e088((double)fVar2,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,puVar5,5,
                   *(undefined *)(iVar3 + 0xac),0xffffffff,*(uint **)(iVar3 + 0x30),param_6,param_7,
                   param_8);
    }
    for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
      puVar5 = FUN_8002becc(0x24,0x47f);
      *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar3 + 0x14);
      uVar4 = FUN_80022264(0xffffff80,0x7f);
      *(char *)(puVar5 + 0xc) = (char)uVar4;
      fVar2 = *(float *)(iVar3 + 0x10);
      iVar1 = (int)((double)fVar2 - (double)local_28[0]);
      local_20 = (longlong)iVar1;
      puVar5[0xd] = (short)iVar1;
      *(undefined *)((int)puVar5 + 5) = 1;
      *(undefined *)((int)puVar5 + 7) = 0xff;
      *(undefined *)(puVar5 + 2) = 0x10;
      *(undefined *)(puVar5 + 3) = 6;
      *(undefined *)((int)puVar5 + 0x19) = 1;
      *(undefined4 *)(puVar5 + 10) = *(undefined4 *)((int)uVar9 + 0x9b4);
      FUN_8002e088((double)fVar2,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,puVar5,5,
                   *(undefined *)(iVar3 + 0xac),0xffffffff,*(uint **)(iVar3 + 0x30),param_6,param_7,
                   param_8);
    }
  }
  FUN_8028688c();
  return;
}

