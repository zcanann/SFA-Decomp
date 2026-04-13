// Function: FUN_80172058
// Entry: 80172058
// Size: 204 bytes

void FUN_80172058(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  short *psVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  uVar1 = FUN_8002e144();
  if (((((uVar1 & 0xff) != 0) && (iVar2 = FUN_8002bac4(), iVar2 != 0)) &&
      (iVar2 = FUN_8002ba84(), iVar2 == 0)) &&
     (uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x18)), uVar1 != 0)) {
    puVar3 = FUN_8002becc(0x18,0x24);
    *(undefined *)(puVar3 + 2) = 2;
    *(undefined *)((int)puVar3 + 5) = 4;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
    psVar4 = (short *)FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                   puVar3,5,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    *psVar4 = (ushort)*(byte *)(iVar5 + 0x1a) << 8;
  }
  return;
}

