// Function: FUN_8023293c
// Entry: 8023293c
// Size: 308 bytes

void FUN_8023293c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,int param_11,char param_12)

{
  uint uVar1;
  undefined2 *puVar2;
  ushort *puVar3;
  undefined8 uVar4;
  float local_28;
  undefined4 local_24;
  float local_20 [4];
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    uVar4 = FUN_80038524(param_9,param_10,&local_28,&local_24,local_20,0);
    puVar2 = FUN_8002becc(0x20,0x6ae);
    *(float *)(puVar2 + 4) = local_28;
    *(undefined4 *)(puVar2 + 6) = local_24;
    *(float *)(puVar2 + 8) = local_20[0];
    *(char *)(puVar2 + 0xd) = (char)((uint)(*param_9 + param_11 + 0x8000) >> 8);
    *(char *)((int)puVar2 + 0x19) = (char)((uint)-(int)param_9[1] >> 8);
    *(undefined *)(puVar2 + 0xc) = 0;
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 1;
    puVar3 = (ushort *)
             FUN_8002b678(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9
                          ,puVar2);
    if (puVar3 != (ushort *)0x0) {
      if (param_12 != '\0') {
        FUN_8022eadc((int)puVar3,'\x01');
      }
      FUN_8022ecc4((int)puVar3,0x4b);
      FUN_8022ec10((double)FLOAT_803e7e40,puVar3);
      FUN_8000b4f0((uint)puVar3,0x2b5,4);
    }
  }
  return;
}

