// Function: FUN_8022be28
// Entry: 8022be28
// Size: 316 bytes

void FUN_8022be28(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,int param_11)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined8 uVar4;
  float local_28;
  undefined4 local_24;
  float local_20 [5];
  
  uVar1 = FUN_8002e144();
  if (((uVar1 & 0xff) != 0) && (*(char *)(param_10 + 0x44c) != '\0')) {
    *(char *)(param_10 + 0x44c) = *(char *)(param_10 + 0x44c) + -1;
    if (param_11 == 0) {
      uVar4 = FUN_80038524(param_9,5,&local_28,&local_24,local_20,0);
    }
    else {
      uVar4 = FUN_80038524(param_9,6,&local_28,&local_24,local_20,0);
    }
    puVar2 = FUN_8002becc(0x20,0x605);
    *(float *)(puVar2 + 4) = local_28;
    *(undefined4 *)(puVar2 + 6) = local_24;
    *(float *)(puVar2 + 8) = local_20[0];
    *(char *)(puVar2 + 0xd) = (char)((ushort)*param_9 >> 8);
    *(char *)((int)puVar2 + 0x19) = (char)((ushort)param_9[1] >> 8);
    *(char *)(puVar2 + 0xc) = (char)((ushort)param_9[2] >> 8);
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 1;
    iVar3 = FUN_8002b678(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                         puVar2);
    *(int *)(param_10 + 0x438) = iVar3;
    FUN_8022f438(*(int *)(param_10 + 0x438),(uint)*(ushort *)(param_10 + 0x446));
    FUN_8022f3a4((double)*(float *)(param_10 + 0x448),*(ushort **)(param_10 + 0x438));
    FUN_8000bb38((uint)param_9,0x2a3);
  }
  return;
}

