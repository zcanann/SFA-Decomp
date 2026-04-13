// Function: FUN_802a9e38
// Entry: 802a9e38
// Size: 248 bytes

void FUN_802a9e38(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 in_r9;
  undefined4 in_r10;
  char cVar5;
  short sVar6;
  int *piVar7;
  undefined8 uVar8;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    piVar7 = &DAT_80333b34;
    sVar6 = 0;
    for (cVar5 = '\0'; cVar5 < '\a'; cVar5 = cVar5 + '\x01') {
      if (*piVar7 == 0) {
        puVar2 = FUN_8002becc(0x24,0x4ec);
        uVar4 = 0;
        uVar8 = FUN_80038524(DAT_803df0cc,0,(float *)(puVar2 + 4),(undefined4 *)(puVar2 + 6),
                             (float *)(puVar2 + 8),0);
        *(undefined *)(puVar2 + 2) = 2;
        *(undefined *)((int)puVar2 + 5) = 1;
        *(undefined *)(puVar2 + 3) = 0xff;
        *(undefined *)((int)puVar2 + 7) = 0xff;
        puVar2[0xd] = sVar6;
        puVar2[0xe] = 0;
        iVar3 = FUN_8002e088(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                             0xff,0xffffffff,(uint *)0x0,uVar4,in_r9,in_r10);
        *piVar7 = iVar3;
      }
      piVar7 = piVar7 + 1;
      sVar6 = sVar6 + 3;
    }
  }
  return;
}

