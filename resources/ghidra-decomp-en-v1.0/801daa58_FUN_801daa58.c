// Function: FUN_801daa58
// Entry: 801daa58
// Size: 1080 bytes

/* WARNING: Removing unreachable block (ram,0x801daa94) */

void FUN_801daa58(int param_1)

{
  byte bVar1;
  char cVar4;
  undefined4 uVar2;
  int iVar3;
  int iVar5;
  undefined4 *puVar6;
  
  puVar6 = *(undefined4 **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  bVar1 = *(byte *)(puVar6 + 5);
  if (bVar1 == 1) {
    if (-1 < *(char *)((int)puVar6 + 0x15)) {
      FUN_8000dcbc(param_1,0x9e);
      *(byte *)((int)puVar6 + 0x15) = *(byte *)((int)puVar6 + 0x15) & 0x7f | 0x80;
    }
    if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
      puVar6[4] = (float)puVar6[4] + FLOAT_803db414;
      if ((float)puVar6[4] <= FLOAT_803e5530) {
        uVar2 = 0;
      }
      else {
        uVar2 = 2;
        puVar6[4] = (float)puVar6[4] - FLOAT_803e5530;
      }
      puVar6[3] = (float)puVar6[3] + FLOAT_803db414;
      if (FLOAT_803e5534 < (float)puVar6[3]) {
        puVar6[3] = (float)puVar6[3] - FLOAT_803e5534;
        FUN_80098b18((double)*(float *)(param_1 + 8),param_1,2,uVar2,0,0);
      }
    }
  }
  else {
    if (bVar1 == 0) {
      if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
         (iVar3 = (**(code **)(*DAT_803dca68 + 0x20))(0x194), iVar3 != 0)) {
        FUN_8001fee8(0x194);
        FUN_800200e8((int)*(short *)(iVar5 + 0x20),1);
        cVar4 = FUN_8002e04c();
        if (cVar4 != '\0') {
          iVar3 = FUN_8002bdf4(0x20,0x55);
          *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(param_1 + 0xc);
          *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(param_1 + 0x10);
          *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(param_1 + 0x14);
          *(undefined *)(iVar3 + 4) = 2;
          *(undefined *)(iVar3 + 5) = *(undefined *)(*(int *)(param_1 + 0x4c) + 5);
          *(undefined *)(iVar3 + 7) = *(undefined *)(*(int *)(param_1 + 0x4c) + 7);
          uVar2 = FUN_8002b5a0(param_1);
          *puVar6 = uVar2;
        }
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
        *(undefined *)(puVar6 + 5) = 2;
      }
    }
    else if (2 < bVar1) goto LAB_801dac80;
    iVar3 = *(int *)(param_1 + 0xb8);
    *(float *)(iVar3 + 4) = *(float *)(iVar3 + 4) + FLOAT_803db414;
    if ((FLOAT_803e5528 <= *(float *)(iVar3 + 4)) &&
       (*(float *)(iVar3 + 4) = *(float *)(iVar3 + 4) - FLOAT_803e5528,
       (*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
      FUN_80098b18((double)*(float *)(param_1 + 8),param_1,0,2,0,0);
    }
  }
LAB_801dac80:
  if (*(char *)(puVar6 + 5) == '\x01') {
    iVar3 = FUN_8001ffb4(0x193);
    if ((iVar3 == 0) && (*(short *)(iVar5 + 0x1e) == 0x95)) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    if (*(char *)(puVar6 + 5) == '\x02') {
      FUN_8002b6d8(param_1,0,0,0,0,8);
    }
    else if ((*(char *)(puVar6 + 5) == '\0') && (iVar3 = FUN_8001ffb4(0x194), iVar3 == 0)) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
    iVar3 = FUN_8002b9ac();
    if ((iVar3 != 0) && ((*(byte *)(param_1 + 0xaf) & 4) != 0)) {
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,param_1,1,4);
    }
  }
  if (FLOAT_803e5538 < (float)puVar6[2]) {
    puVar6[2] = (float)puVar6[2] - FLOAT_803db414;
    if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
      FUN_80098b18((double)(FLOAT_803e553c * *(float *)(param_1 + 8)),param_1,3,0,0,0);
    }
    if (((float)puVar6[2] <= FLOAT_803e5538) && (*(char *)(puVar6 + 5) == '\x02')) {
      *(undefined *)(puVar6 + 5) = 1;
      FUN_800200e8((int)*(short *)(iVar5 + 0x1e),1);
      iVar5 = FUN_8001ffb4(400);
      if ((iVar5 == 0) ||
         ((iVar5 = FUN_8001ffb4(0x191), iVar5 == 0 || (iVar5 = FUN_8001ffb4(0x192), iVar5 == 0)))) {
        FUN_8000bb18(0,0x409);
      }
      else {
        FUN_8000bb18(0,0x7e);
      }
    }
  }
  FUN_80037b40(param_1,8,0xff,0xff,0x78,0x129,&DAT_803ddbf8);
  return;
}

