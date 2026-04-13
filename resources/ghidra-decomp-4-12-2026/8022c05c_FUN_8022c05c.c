// Function: FUN_8022c05c
// Entry: 8022c05c
// Size: 424 bytes

void FUN_8022c05c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,uint param_13)

{
  undefined2 *puVar1;
  uint uVar2;
  undefined2 *puVar3;
  ushort *puVar4;
  int iVar5;
  undefined8 uVar6;
  float local_28;
  undefined4 local_24;
  float local_20 [8];
  
  uVar6 = FUN_80286840();
  puVar1 = (undefined2 *)((ulonglong)uVar6 >> 0x20);
  iVar5 = (int)uVar6;
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    if (param_11 == 0) {
      FUN_80038524(puVar1,3,&local_28,&local_24,local_20,0);
      uVar2 = countLeadingZeros(2 - param_12);
      uVar6 = FUN_8022f89c(*(int *)(iVar5 + 8),'\x01',(char)(uVar2 >> 5));
    }
    else {
      FUN_80038524(puVar1,4,&local_28,&local_24,local_20,0);
      uVar2 = countLeadingZeros(2 - param_12);
      uVar6 = FUN_8022f89c(*(int *)(iVar5 + 0xc),'\x01',(char)(uVar2 >> 5));
    }
    puVar3 = FUN_8002becc(0x20,0x604);
    *(float *)(puVar3 + 4) = local_28;
    *(undefined4 *)(puVar3 + 6) = local_24;
    *(float *)(puVar3 + 8) = local_20[0];
    *(char *)(puVar3 + 0xd) = (char)((ushort)*puVar1 >> 8);
    *(char *)((int)puVar3 + 0x19) = (char)((ushort)puVar1[1] >> 8);
    *(undefined *)(puVar3 + 0xc) = 0;
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    puVar4 = (ushort *)
             FUN_8002b678(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar1,
                          puVar3);
    if (puVar4 != (ushort *)0x0) {
      if (param_12 == 0) {
        FUN_8000bb38((uint)puVar4,0x2a1);
      }
      else if (param_12 == 1) {
        FUN_8000bb38((uint)puVar4,0x2a2);
      }
      else {
        FUN_8000bb38((uint)puVar4,0x2b4);
        FUN_8002b95c((int)puVar4,1);
      }
      if ((param_13 & 0xff) != 0) {
        FUN_8022eadc((int)puVar4,'\x01');
      }
      FUN_8022ecc4((int)puVar4,(uint)*(ushort *)(iVar5 + 0x40e));
      FUN_8022ec10((double)*(float *)(iVar5 + 0x410),puVar4);
    }
  }
  FUN_8028688c();
  return;
}

