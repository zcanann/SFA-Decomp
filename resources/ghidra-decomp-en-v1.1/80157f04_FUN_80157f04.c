// Function: FUN_80157f04
// Entry: 80157f04
// Size: 256 bytes

void FUN_80157f04(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar5;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_8002becc(0x24,0x710);
    uVar4 = 0;
    uVar5 = FUN_80038524(param_9,0,(float *)(puVar2 + 4),(undefined4 *)(puVar2 + 6),
                         (float *)(puVar2 + 8),0);
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    *(undefined *)(puVar2 + 0xc) = 0;
    *(undefined *)((int)puVar2 + 0x19) = 0;
    puVar2[0xd] = 0;
    puVar2[0xe] = 10;
    puVar2[0xf] = 0;
    puVar2[0x10] = 0;
    *(undefined *)(puVar2 + 0x11) = 3;
    *(undefined *)((int)puVar2 + 0x23) = 0;
    iVar3 = FUN_8002e088(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff
                         ,0xffffffff,(uint *)0x0,uVar4,in_r9,in_r10);
    if (iVar3 != 0) {
      FUN_80037e24(param_9,iVar3,0);
      FUN_80220120(iVar3);
      *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
    }
  }
  return;
}

