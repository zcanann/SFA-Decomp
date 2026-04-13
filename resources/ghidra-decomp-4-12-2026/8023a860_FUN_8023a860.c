// Function: FUN_8023a860
// Entry: 8023a860
// Size: 256 bytes

void FUN_8023a860(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)

{
  uint uVar1;
  uint uVar2;
  undefined2 *puVar3;
  ushort *puVar4;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    uVar1 = FUN_80022264(0xffffe0c0,8000);
    uVar2 = FUN_80022264(0xffffe0c0,8000);
    puVar3 = FUN_8002becc(0x20,0x80d);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_10 + 0xc0);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_10 + 0xc4);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_10 + 200);
    *(char *)(puVar3 + 0xd) =
         (char)((uint)((int)*param_9 + (int)(short)((short)uVar1 + -0x8000)) >> 8);
    *(char *)((int)puVar3 + 0x19) = (char)(uVar2 >> 8);
    *(undefined *)(puVar3 + 0xc) = 0;
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    puVar4 = (ushort *)
             FUN_8002b678(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                          (int)param_9,puVar3);
    if (puVar4 != (ushort *)0x0) {
      *(float *)(puVar4 + 4) = FLOAT_803e8148;
      FUN_8022ecc4((int)puVar4,0x6e);
      FUN_8022ec10((double)FLOAT_803e8144,puVar4);
    }
  }
  return;
}

