// Function: FUN_8015a9d8
// Entry: 8015a9d8
// Size: 308 bytes

void FUN_8015a9d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar4;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_8002becc(0x24,0x51b);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar4 = (double)FLOAT_803e3930;
    *(float *)(puVar2 + 6) = (float)(dVar4 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    iVar3 = FUN_8002e088(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff
                         ,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar3 != 0) {
      dVar4 = (double)FUN_802945e0();
      *(float *)(iVar3 + 0x24) = (float)((double)FLOAT_803e3934 * -dVar4);
      *(float *)(iVar3 + 0x28) = FLOAT_803e3940;
      dVar4 = (double)FUN_80294964();
      *(float *)(iVar3 + 0x2c) = (float)((double)FLOAT_803e3934 * -dVar4);
    }
  }
  return;
}

