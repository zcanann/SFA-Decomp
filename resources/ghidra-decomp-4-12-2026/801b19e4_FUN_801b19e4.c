// Function: FUN_801b19e4
// Entry: 801b19e4
// Size: 360 bytes

void FUN_801b19e4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  short sVar1;
  ushort uVar2;
  double dVar3;
  uint uVar4;
  int iVar5;
  undefined2 *puVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar7;
  double dVar8;
  
  uVar4 = FUN_8002e144();
  if ((uVar4 & 0xff) != 0) {
    psVar7 = *(short **)(param_9 + 0xb8);
    sVar1 = *psVar7;
    uVar2 = (ushort)DAT_803dc070;
    *psVar7 = sVar1 - uVar2;
    if ((short)(sVar1 - uVar2) < 1) {
      iVar5 = FUN_8002bac4();
      iVar5 = FUN_80297a08(iVar5);
      if (iVar5 == 0) {
        iVar5 = *(int *)(param_9 + 0x4c);
        puVar6 = FUN_8002becc(0x24,0x196);
        *(undefined *)(puVar6 + 2) = *(undefined *)(iVar5 + 4);
        *(undefined *)(puVar6 + 3) = *(undefined *)(iVar5 + 6);
        *(undefined *)((int)puVar6 + 5) = *(undefined *)(iVar5 + 5);
        *(undefined *)((int)puVar6 + 7) = *(undefined *)(iVar5 + 7);
        *(undefined4 *)(puVar6 + 4) = *(undefined4 *)(param_9 + 0xc);
        *(undefined4 *)(puVar6 + 6) = *(undefined4 *)(param_9 + 0x10);
        *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(param_9 + 0x14);
        *(undefined4 *)(puVar6 + 10) = *(undefined4 *)(iVar5 + 0x14);
        *(undefined *)(puVar6 + 0xc) = *(undefined *)(iVar5 + 0x1c);
        puVar6[0xd] = (ushort)*(byte *)(iVar5 + 0x1a);
        uVar4 = FUN_80022264(0,100);
        dVar3 = DOUBLE_803e5508;
        dVar8 = (double)((float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e5500)
                        / FLOAT_803e54fc);
        puVar6[0xe] = (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                                    (uint)*(byte *)(iVar5 + 0x1b)) -
                                                  DOUBLE_803e5508) + dVar8);
        FUN_8002e088(dVar3,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,puVar6,5,
                     *(undefined *)(param_9 + 0xac),0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
        *psVar7 = psVar7[1];
      }
    }
  }
  return;
}

