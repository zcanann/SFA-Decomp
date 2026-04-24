// Function: FUN_801db048
// Entry: 801db048
// Size: 1080 bytes

/* WARNING: Removing unreachable block (ram,0x801db084) */

void FUN_801db048(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  byte bVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  undefined8 uVar7;
  
  piVar6 = *(int **)(param_9 + 0xb8);
  iVar5 = *(int *)(param_9 + 0x4c);
  bVar1 = *(byte *)(piVar6 + 5);
  if (bVar1 == 1) {
    if (-1 < *(char *)((int)piVar6 + 0x15)) {
      FUN_8000dcdc(param_9,0x9e);
      *(byte *)((int)piVar6 + 0x15) = *(byte *)((int)piVar6 + 0x15) & 0x7f | 0x80;
    }
    if ((*(ushort *)(param_9 + 0xb0) & 0x800) != 0) {
      piVar6[4] = (int)((float)piVar6[4] + FLOAT_803dc074);
      if ((float)piVar6[4] <= FLOAT_803e61c8) {
        uVar4 = 0;
      }
      else {
        uVar4 = 2;
        piVar6[4] = (int)((float)piVar6[4] - FLOAT_803e61c8);
      }
      piVar6[3] = (int)((float)piVar6[3] + FLOAT_803dc074);
      if (FLOAT_803e61cc < (float)piVar6[3]) {
        piVar6[3] = (int)((float)piVar6[3] - FLOAT_803e61cc);
        FUN_80098da4(param_9,2,uVar4,0,(undefined4 *)0x0);
      }
    }
  }
  else {
    if (bVar1 == 0) {
      if (((*(byte *)(param_9 + 0xaf) & 1) != 0) &&
         (iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x194), iVar3 != 0)) {
        FUN_8001ffac(0x194);
        uVar7 = FUN_800201ac((int)*(short *)(iVar5 + 0x20),1);
        uVar4 = FUN_8002e144();
        if ((uVar4 & 0xff) != 0) {
          puVar2 = FUN_8002becc(0x20,0x55);
          *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
          *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_9 + 0x10);
          *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
          *(undefined *)(puVar2 + 2) = 2;
          *(undefined *)((int)puVar2 + 5) = *(undefined *)(*(int *)(param_9 + 0x4c) + 5);
          *(undefined *)((int)puVar2 + 7) = *(undefined *)(*(int *)(param_9 + 0x4c) + 7);
          iVar3 = FUN_8002b678(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,puVar2);
          *piVar6 = iVar3;
        }
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        *(undefined *)(piVar6 + 5) = 2;
      }
    }
    else if (2 < bVar1) goto LAB_801db270;
    iVar3 = *(int *)(param_9 + 0xb8);
    *(float *)(iVar3 + 4) = *(float *)(iVar3 + 4) + FLOAT_803dc074;
    if ((FLOAT_803e61c0 <= *(float *)(iVar3 + 4)) &&
       (*(float *)(iVar3 + 4) = *(float *)(iVar3 + 4) - FLOAT_803e61c0,
       (*(ushort *)(param_9 + 0xb0) & 0x800) != 0)) {
      FUN_80098da4(param_9,0,2,0,(undefined4 *)0x0);
    }
  }
LAB_801db270:
  if (*(char *)(piVar6 + 5) == '\x01') {
    uVar4 = FUN_80020078(0x193);
    if ((uVar4 == 0) && (*(short *)(iVar5 + 0x1e) == 0x95)) {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    }
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    if (*(char *)(piVar6 + 5) == '\x02') {
      FUN_8002b7b0(param_9,0,0,0,'\0','\b');
    }
    else if ((*(char *)(piVar6 + 5) == '\0') && (uVar4 = FUN_80020078(0x194), uVar4 == 0)) {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
    }
    iVar3 = FUN_8002ba84();
    if ((iVar3 != 0) && ((*(byte *)(param_9 + 0xaf) & 4) != 0)) {
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,param_9,1,4);
    }
  }
  if (FLOAT_803e61d0 < (float)piVar6[2]) {
    piVar6[2] = (int)((float)piVar6[2] - FLOAT_803dc074);
    if ((*(ushort *)(param_9 + 0xb0) & 0x800) != 0) {
      FUN_80098da4(param_9,3,0,0,(undefined4 *)0x0);
    }
    if (((float)piVar6[2] <= FLOAT_803e61d0) && (*(char *)(piVar6 + 5) == '\x02')) {
      *(undefined *)(piVar6 + 5) = 1;
      FUN_800201ac((int)*(short *)(iVar5 + 0x1e),1);
      uVar4 = FUN_80020078(400);
      if ((uVar4 == 0) ||
         ((uVar4 = FUN_80020078(0x191), uVar4 == 0 || (uVar4 = FUN_80020078(0x192), uVar4 == 0)))) {
        FUN_8000bb38(0,0x409);
      }
      else {
        FUN_8000bb38(0,0x7e);
      }
    }
  }
  FUN_80037c38(param_9,8,0xff,0xff,0x78,0x129,(float *)&DAT_803de878);
  return;
}

