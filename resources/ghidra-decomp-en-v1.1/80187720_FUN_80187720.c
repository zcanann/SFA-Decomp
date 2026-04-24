// Function: FUN_80187720
// Entry: 80187720
// Size: 196 bytes

int FUN_80187720(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9)

{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  double dVar4;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) == 0) {
    iVar2 = 0;
  }
  else {
    puVar3 = FUN_8002becc(0x24,0x43c);
    *puVar3 = 0x43c;
    *(undefined *)(puVar3 + 1) = 9;
    *(undefined *)(puVar3 + 2) = 2;
    *(undefined *)(puVar3 + 3) = 0xff;
    *(undefined *)((int)puVar3 + 5) = 4;
    *(undefined *)((int)puVar3 + 7) = 8;
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar4 = (double)FLOAT_803e4780;
    *(float *)(puVar3 + 6) = (float)(dVar4 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)((int)puVar3 + 0x19) = 4;
    puVar3[0xd] = 0x514;
    puVar3[0xe] = 0x28;
    *(undefined *)(puVar3 + 0xc) = 0x1e;
    iVar2 = FUN_8002b678(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         puVar3);
  }
  return iVar2;
}

