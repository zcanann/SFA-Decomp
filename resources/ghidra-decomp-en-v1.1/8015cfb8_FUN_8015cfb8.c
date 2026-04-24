// Function: FUN_8015cfb8
// Entry: 8015cfb8
// Size: 196 bytes

void FUN_8015cfb8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,int param_10)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_8002becc(0x24,100);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_10 + 0x14);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_10 + 0x18);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_10 + 0x1c);
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 1;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    puVar2[0xf] = 0xffff;
    puVar2[0x10] = 0xffff;
    iVar3 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                         0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar3 != 0) {
      *(undefined4 *)(iVar3 + 0x24) = *(undefined4 *)(param_10 + 0x38);
      *(undefined4 *)(iVar3 + 0x28) = *(undefined4 *)(param_10 + 0x3c);
      *(undefined4 *)(iVar3 + 0x2c) = *(undefined4 *)(param_10 + 0x40);
      *(undefined4 *)(iVar3 + 0xc4) = param_9;
    }
  }
  return;
}

