// Function: FUN_8020f214
// Entry: 8020f214
// Size: 368 bytes

/* WARNING: Removing unreachable block (ram,0x8020f30c) */

void FUN_8020f214(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4)

{
  int iVar1;
  char cVar6;
  undefined2 *puVar2;
  uint uVar3;
  short sVar5;
  int iVar4;
  undefined8 uVar7;
  
  uVar7 = FUN_802860d8();
  iVar4 = (int)((ulonglong)uVar7 >> 0x20);
  iVar1 = FUN_8002b9ec();
  cVar6 = FUN_8002e04c();
  if (cVar6 != '\0') {
    puVar2 = (undefined2 *)FUN_8002bdf4(0x24,0x5ff);
    *puVar2 = 0x5ff;
    *(undefined *)(puVar2 + 2) = 2;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 5) = 1;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    *(char *)((int)puVar2 + 0x19) = (char)param_3;
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0xc);
    *(float *)(puVar2 + 6) = FLOAT_803e66e0 + *(float *)(iVar4 + 0x10);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x14);
    uVar3 = FUN_800217c0((double)(*(float *)(iVar1 + 0xc) - *(float *)(iVar4 + 0xc)),
                         (double)(*(float *)(iVar1 + 0x14) - *(float *)(iVar4 + 0x14)));
    *(char *)(puVar2 + 0xc) = (char)((uint)(((int)(uVar3 & 0xffff) >> 8) + 0x8000) >> 8);
    FUN_8000bb18(iVar4,0x2e4);
    if ((param_3 & 0xff) == 1) {
      sVar5 = FUN_800217c0((double)(*(float *)(iVar1 + 0xc) - *(float *)(iVar4 + 0xc)),
                           (double)(*(float *)(iVar1 + 0x14) - *(float *)(iVar4 + 0x14)));
      puVar2[0xd] = sVar5 + -0x8000;
    }
    else if ((param_3 & 0xff) == 0) {
      puVar2[0xd] = (short)DAT_803ddd38;
    }
    iVar4 = FUN_8002b5a0(iVar4,puVar2);
    if (iVar4 != 0) {
      *(uint *)(iVar4 + 0xf4) = param_4 & 0xff;
      *(int *)(iVar4 + 0xc4) = (int)uVar7;
    }
  }
  FUN_80286124();
  return;
}

