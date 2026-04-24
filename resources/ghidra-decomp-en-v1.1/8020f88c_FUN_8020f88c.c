// Function: FUN_8020f88c
// Entry: 8020f88c
// Size: 368 bytes

/* WARNING: Removing unreachable block (ram,0x8020f984) */

void FUN_8020f88c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined2 *puVar4;
  double dVar5;
  double dVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_8028683c();
  uVar1 = (uint)((ulonglong)uVar7 >> 0x20);
  iVar2 = FUN_8002bac4();
  uVar3 = FUN_8002e144();
  if ((uVar3 & 0xff) != 0) {
    puVar4 = FUN_8002becc(0x24,0x5ff);
    *puVar4 = 0x5ff;
    *(undefined *)(puVar4 + 2) = 2;
    *(undefined *)(puVar4 + 3) = 0xff;
    *(undefined *)((int)puVar4 + 5) = 1;
    *(undefined *)((int)puVar4 + 7) = 0xff;
    *(char *)((int)puVar4 + 0x19) = (char)param_11;
    *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(uVar1 + 0xc);
    *(float *)(puVar4 + 6) = FLOAT_803e7378 + *(float *)(uVar1 + 0x10);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(uVar1 + 0x14);
    dVar6 = (double)(*(float *)(iVar2 + 0x14) - *(float *)(uVar1 + 0x14));
    uVar3 = FUN_80021884();
    *(char *)(puVar4 + 0xc) = (char)((uint)(((int)(uVar3 & 0xffff) >> 8) + 0x8000) >> 8);
    dVar5 = (double)FUN_8000bb38(uVar1,0x2e4);
    if ((param_11 & 0xff) == 1) {
      dVar5 = (double)(*(float *)(iVar2 + 0xc) - *(float *)(uVar1 + 0xc));
      dVar6 = (double)(*(float *)(iVar2 + 0x14) - *(float *)(uVar1 + 0x14));
      iVar2 = FUN_80021884();
      puVar4[0xd] = (short)iVar2 + -0x8000;
    }
    else if ((param_11 & 0xff) == 0) {
      puVar4[0xd] = (short)DAT_803de9b8;
    }
    iVar2 = FUN_8002b678(dVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,puVar4);
    if (iVar2 != 0) {
      *(uint *)(iVar2 + 0xf4) = param_12 & 0xff;
      *(int *)(iVar2 + 0xc4) = (int)uVar7;
    }
  }
  FUN_80286888();
  return;
}

